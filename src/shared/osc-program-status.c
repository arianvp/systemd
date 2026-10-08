/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <unistd.h>

#include "alloc-util.h"
#include "env-util.h"
#include "hexdecoct.h"
#include "io-util.h"
#include "log.h"
#include "osc-program-status.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "string-table.h"
#include "string-util.h"
#include "terminal-util.h"
#include "utf8.h"

/* The bytes the specification allows in an app name, and in each segment of a record id */
#define NAME_CHARS ALPHANUMERICAL "_.+-"

static const char* const osc_program_status_state_table[_OSC_PROGRAM_STATUS_STATE_MAX] = {
        [OSC_PROGRAM_STATUS_IDLE]    = "idle",
        [OSC_PROGRAM_STATUS_WORKING] = "working",
        [OSC_PROGRAM_STATUS_DONE]    = "done",
        [OSC_PROGRAM_STATUS_BLOCKED] = "blocked",
        [OSC_PROGRAM_STATUS_ERROR]   = "error",
        [OSC_PROGRAM_STATUS_CLEAR]   = "clear",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(osc_program_status_state, OscProgramStatusState);

static const char* const osc_program_status_kind_table[_OSC_PROGRAM_STATUS_KIND_MAX] = {
        [OSC_PROGRAM_STATUS_PERMISSION] = "permission",
        [OSC_PROGRAM_STATUS_QUESTION]   = "question",
        [OSC_PROGRAM_STATUS_AUTH]       = "auth",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(osc_program_status_kind, OscProgramStatusKind);

bool osc_program_status_id_is_valid(const char *id) {
        size_t depth = 0;

        /* A record id consists of up to 8 names separated by single slashes. Note that terminals skip any
         * value with bytes outside of the permitted alphabet, i.e. an invalid id might turn a report about a
         * specific record into a report about the root record, and a clear of a specific record into a clear
         * of all records. Hence we must never generate a report with an invalid id. */

        if (isempty(id))
                return false;

        if (strlen(id) > OSC_PROGRAM_STATUS_ID_MAX)
                return false;

        for (const char *p = id;;) {
                size_t n = strcspn(p, "/");

                if (n == 0 || n > OSC_PROGRAM_STATUS_ID_SEGMENT_MAX)
                        return false;
                if (strspn(p, NAME_CHARS) < n)
                        return false;
                if (++depth > OSC_PROGRAM_STATUS_ID_DEPTH_MAX)
                        return false;

                p += n;
                if (*p == 0)
                        return true;

                p++; /* skip the slash */
        }
}

static int make_app(const char *app, char **ret) {
        _cleanup_free_ char *s = NULL;
        size_t n = 0;

        assert(ret);

        /* Turns the specified string (or our program name) into something that is valid as app name, and
         * as id segment, i.e. drops all characters not permitted, and truncates it. For example, "(sd-pam)"
         * becomes "sd-pam". */

        app = app ?: program_invocation_short_name;

        s = new(char, OSC_PROGRAM_STATUS_APP_MAX + 1);
        if (!s)
                return -ENOMEM;

        for (const char *p = strempty(app); *p && n < OSC_PROGRAM_STATUS_APP_MAX; p++)
                if (strchr(NAME_CHARS, *p))
                        s[n++] = *p;
        s[n] = 0;

        if (n == 0)
                return strdup_to(ret, "systemd");

        *ret = TAKE_PTR(s);
        return 0;
}

static int sanitize_text(const char *s, size_t max_bytes, char **ret) {
        _cleanup_free_ char *copy = NULL, *buf = NULL;
        size_t n = 0;

        assert(max_bytes >= STRLEN("…"));
        assert(ret);

        /* Terminals discard reports whose text is not valid UTF-8 or contains control characters (C0, DEL,
         * C1), including TAB and newlines. Hence, drop any ANSI sequences, replace control characters by
         * spaces (collapsing runs of whitespace), replace invalid UTF-8 by U+FFFD, and truncate at a
         * character boundary so that we stay within the size limit. Returns NULL if nothing is left. */

        if (isempty(s)) {
                *ret = NULL;
                return 0;
        }

        copy = strdup(s);
        if (!copy)
                return -ENOMEM;

        if (!strip_tab_ansi(&copy, /* _isz= */ NULL, /* highlight= */ NULL))
                return -ENOMEM;

        const char *end = copy + strlen(copy);
        for (const char *p = copy; p < end; ) {
                char32_t c;
                int l;

                if (!GREEDY_REALLOC(buf, n + STRLEN(UTF8_REPLACEMENT_CHARACTER) + 4 + 1))
                        return -ENOMEM;

                l = utf8_encoded_valid_unichar_full(p, end - p, &c);
                if (l < 0) {
                        n = stpcpy(buf + n, UTF8_REPLACEMENT_CHARACTER) - buf;
                        p++;
                        continue;
                }

                if (c < 0x20 || (c >= 0x7f && c <= 0x9f) || c == ' ') {
                        /* Replace control characters by a space, and never emit two spaces in a row */
                        if (n > 0 && buf[n-1] != ' ')
                                buf[n++] = ' ';
                } else
                        n = (char*) mempcpy(buf + n, p, l) - buf;

                p += l;
        }

        /* Drop the trailing space, if there is one */
        while (n > 0 && buf[n-1] == ' ')
                n--;

        if (n == 0) {
                *ret = NULL;
                return 0;
        }

        if (n > max_bytes) {
                /* Truncate at a character boundary, leaving room for the ellipsis */
                n = max_bytes - STRLEN("…");
                while (n > 0 && (buf[n] & 0xc0) == 0x80)
                        n--;
                while (n > 0 && buf[n-1] == ' ')
                        n--;

                n = stpcpy(buf + n, "…") - buf;
        }

        buf[n] = 0;
        *ret = TAKE_PTR(buf);
        return 0;
}

static int append_text(char **seq, const char *key, const char *text, size_t max_bytes) {
        _cleanup_free_ char *sanitized = NULL, *encoded = NULL;
        ssize_t l;
        int r;

        assert(seq);
        assert(key);

        r = sanitize_text(text, max_bytes, &sanitized);
        if (r < 0)
                return r;
        if (!sanitized)
                return 0;

        /* No line breaks, and the standard alphabet and padding, which the specification all permits */
        l = base64mem(sanitized, strlen(sanitized), &encoded);
        if (l < 0)
                return l;

        if (!strextend(seq, ":", key, "=", encoded))
                return -ENOMEM;

        return 0;
}

int osc_program_status_format(const OscProgramStatus *s, char **ret_seq) {
        _cleanup_free_ char *app = NULL, *id = NULL, *seq = NULL;
        const char *state, *kind = NULL;
        int r;

        assert(s);
        assert(ret_seq);

        state = osc_program_status_state_to_string(s->state);
        if (!state)
                return -EINVAL;

        if (s->kind >= 0) {
                if (s->state != OSC_PROGRAM_STATUS_BLOCKED)
                        return -EINVAL;

                kind = osc_program_status_kind_to_string(s->kind);
                if (!kind)
                        return -EINVAL;
        }

        if (s->progress != OSC_PROGRAM_STATUS_PROGRESS_NONE &&
            (s->progress > 100 || !IN_SET(s->state, OSC_PROGRAM_STATUS_WORKING, OSC_PROGRAM_STATUS_BLOCKED)))
                return -EINVAL;

        r = make_app(s->app, &app);
        if (r < 0)
                return r;

        /* Never report on the root record, it belongs to whoever is in the foreground of the terminal, which
         * might be a program that invoked us. */
        if (isempty(s->id))
                return -EINVAL;

        id = strjoin(app, "/", s->id);
        if (!id)
                return -ENOMEM;

        if (!osc_program_status_id_is_valid(id))
                return -EINVAL;

        /* Put the id first and the state last: should the sequence ever get cut off (e.g. because the
         * console got hung up while we wrote it), the terminal won't find a valid state and drops the
         * report, rather than applying it to the wrong record. Note that a report whose id is cut off would
         * apply to the root record, and a "clear" without id would remove all records. */
        seq = strjoin(ANSI_OSC "7501;id=", id);
        if (!seq)
                return -ENOMEM;

        if (s->state != OSC_PROGRAM_STATUS_CLEAR) {
                if (kind && !strextend(&seq, ":kind=", kind))
                        return -ENOMEM;

                if (s->progress != OSC_PROGRAM_STATUS_PROGRESS_NONE) {
                        r = strextendf(&seq, ":progress=%u", s->progress);
                        if (r < 0)
                                return r;
                }

                if (!strextend(&seq, ":app=", app))
                        return -ENOMEM;

                r = append_text(&seq, "title", s->title, OSC_PROGRAM_STATUS_TITLE_MAX);
                if (r < 0)
                        return r;

                r = append_text(&seq, "msg", s->msg, OSC_PROGRAM_STATUS_MSG_MAX);
                if (r < 0)
                        return r;
        }

        if (!strextend(&seq, ":state=", state, ANSI_ST))
                return -ENOMEM;

        /* The limits on the individual fields make sure we can never exceed this */
        assert(strlen(seq) <= OSC_PROGRAM_STATUS_SEQUENCE_MAX);

        *ret_seq = TAKE_PTR(seq);
        return 0;
}

bool osc_program_status_wanted(OscProgramStatusFlags flags) {
        const char *e;
        int r;

        r = secure_getenv_bool("SYSTEMD_PROGRAM_STATUS");
        if (r == 0)
                return false;
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_PROGRAM_STATUS, ignoring: %m");

        e = getenv("TERM");
        if (e)
                return !streq(e, "dumb");

        if (!FLAGS_SET(flags, OSC_PROGRAM_STATUS_CONSOLE))
                return false;

        /* Console agents typically have no $TERM set, hence look at the one of PID 1, or the one specified
         * on the kernel command line, the same way dev_console_colors_enabled() does. */
        _cleanup_free_ char *s = NULL;
        if (getenv_for_pid(1, "TERM", &s) <= 0)
                (void) proc_cmdline_get_key("TERM", /* flags= */ 0, &s);

        return !streq_ptr(s, "dumb");
}

bool osc_program_status_enabled(int fd, OscProgramStatusFlags flags) {
        if (fd < 0)
                return false;

        /* Never write escape sequences into pipes or files, only to terminals */
        if (!isatty_safe(fd))
                return false;

        if (FLAGS_SET(flags, OSC_PROGRAM_STATUS_STDIN) && !isatty_safe(STDIN_FILENO))
                return false;

        return osc_program_status_wanted(flags);
}

static int write_seq(int fd, const char *seq) {
        assert(fd >= 0);
        assert(seq);

        /* Make sure anything still buffered for the same fd goes out first, so that the report is not
         * reordered relative to the prompt we are about to show, or have just shown. */
        if (fd == STDOUT_FILENO)
                fflush(stdout);
        else if (fd == STDERR_FILENO)
                fflush(stderr);

        /* Write the whole sequence in one go, so that it doesn't get interleaved with other output */
        return loop_write(fd, seq, SIZE_MAX);
}

int osc_program_status_write(int fd, OscProgramStatusFlags flags, const OscProgramStatus *s) {
        _cleanup_free_ char *seq = NULL;
        int r;

        assert(s);

        if (!osc_program_status_enabled(fd, flags))
                return 0;

        r = osc_program_status_format(s, &seq);
        if (r < 0)
                return log_debug_errno(r, "Failed to format OSC 7501 report: %m");

        r = write_seq(fd, seq);
        if (r < 0)
                return log_debug_errno(r, "Failed to write OSC 7501 report: %m");

        return 1;
}

int osc_program_status_clear(int fd, OscProgramStatusFlags flags, const char *id) {
        assert(id);

        return osc_program_status_write(
                        fd,
                        flags,
                        &(const OscProgramStatus) {
                                .state = OSC_PROGRAM_STATUS_CLEAR,
                                .id = id,
                                .kind = _OSC_PROGRAM_STATUS_KIND_INVALID,
                                .progress = OSC_PROGRAM_STATUS_PROGRESS_NONE,
                        });
}

static int record_update(
                OscProgramStatusRecord *r,
                int fd,
                OscProgramStatusFlags flags,
                const OscProgramStatus *s) {

        _cleanup_free_ char *seq = NULL;
        int k;

        assert(r);
        assert(s);
        assert(s->id);

        /* A record object tracks a single record on a single terminal */
        assert(!r->id || (r->fd == fd && streq(r->id, s->id)));

        if (!osc_program_status_enabled(fd, flags))
                return 0;

        k = osc_program_status_format(s, &seq);
        if (k < 0)
                return log_debug_errno(k, "Failed to format OSC 7501 report: %m");

        if (r->id && streq_ptr(r->last_seq, seq))
                return 0; /* Nothing changed, don't bother the terminal */

        /* Remember the record before writing, so that we clear it later even if the write fails half-way */
        if (!r->id) {
                r->id = strdup(s->id);
                if (!r->id)
                        return log_oom_debug();

                r->fd = fd;
                r->flags = flags;
        }

        k = write_seq(fd, seq);
        if (k < 0)
                return log_debug_errno(k, "Failed to write OSC 7501 report: %m");

        free_and_replace(r->last_seq, seq);
        return 1;
}

int osc_program_status_record_blocked(
                OscProgramStatusRecord *r,
                int fd,
                OscProgramStatusFlags flags,
                const char *id,
                OscProgramStatusKind kind,
                const char *msg) {

        assert(r);
        assert(id);

        return record_update(
                        r,
                        fd,
                        flags,
                        &(const OscProgramStatus) {
                                .state = OSC_PROGRAM_STATUS_BLOCKED,
                                .id = id,
                                .kind = kind,
                                .progress = OSC_PROGRAM_STATUS_PROGRESS_NONE,
                                .msg = msg,
                        });
}

int osc_program_status_record_working(
                OscProgramStatusRecord *r,
                int fd,
                OscProgramStatusFlags flags,
                const char *id,
                unsigned progress,
                const char *msg) {

        assert(r);
        assert(id);

        return record_update(
                        r,
                        fd,
                        flags,
                        &(const OscProgramStatus) {
                                .state = OSC_PROGRAM_STATUS_WORKING,
                                .id = id,
                                .kind = _OSC_PROGRAM_STATUS_KIND_INVALID,
                                .progress = progress,
                                .msg = msg,
                        });
}

int osc_program_status_record_finish(OscProgramStatusRecord *r, bool success, const char *msg) {
        int k;

        assert(r);

        if (!r->id)
                return 0;

        k = osc_program_status_write(
                        r->fd,
                        r->flags,
                        &(const OscProgramStatus) {
                                .state = success ? OSC_PROGRAM_STATUS_DONE : OSC_PROGRAM_STATUS_ERROR,
                                .id = r->id,
                                .kind = _OSC_PROGRAM_STATUS_KIND_INVALID,
                                .progress = OSC_PROGRAM_STATUS_PROGRESS_NONE,
                                .msg = msg,
                        });

        /* The terminal keeps done/error records around after we exit, so don't clear it later */
        r->id = mfree(r->id);
        r->last_seq = mfree(r->last_seq);
        r->fd = -EBADF;

        return k;
}

void osc_program_status_record_clear(OscProgramStatusRecord *r) {
        assert(r);

        if (r->id)
                (void) osc_program_status_clear(r->fd, r->flags, r->id);

        r->id = mfree(r->id);
        r->last_seq = mfree(r->last_seq);
        r->fd = -EBADF;
}
