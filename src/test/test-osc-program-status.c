/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "io-util.h"
#include "osc-program-status.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "tests.h"
#include "time-util.h"
#include "utf8.h"

#define NO_KIND _OSC_PROGRAM_STATUS_KIND_INVALID
#define NO_PROGRESS OSC_PROGRAM_STATUS_PROGRESS_NONE

/* All fields are always specified, so that the defaults for "kind" and "progress" are explicit */
#define REPORT(_state, _id, _kind, _progress, _app, _title, _msg)       \
        (const OscProgramStatus) {                                      \
                .state = (_state),                                      \
                .id = (_id),                                            \
                .kind = (_kind),                                        \
                .progress = (_progress),                                \
                .app = (_app),                                          \
                .title = (_title),                                      \
                .msg = (_msg),                                          \
        }

static void test_format_one(const OscProgramStatus *s, const char *expected) {
        _cleanup_free_ char *seq = NULL;

        ASSERT_OK(osc_program_status_format(s, &seq));
        ASSERT_STREQ(seq, expected);

        /* The state must always come last, so that a report that is cut off is discarded by the terminal,
         * rather than applied to the root record, or turned into a clear of all records. */
        const char *st = ASSERT_PTR(strstr(seq, ":state="));
        ASSERT_PTR_EQ(strstr(seq, "state="), st + 1);
        ASSERT_NULL(strchr(st + 1, ':'));
        ASSERT_TRUE(startswith(seq, "\e]7501;id="));
        ASSERT_TRUE(endswith(seq, "\e\\"));
}

TEST(format) {
        test_format_one(
                        &REPORT(OSC_PROGRAM_STATUS_BLOCKED, "password", OSC_PROGRAM_STATUS_AUTH, NO_PROGRESS, "systemd-cryptsetup", NULL, "Plan"),
                        "\e]7501;id=systemd-cryptsetup/password:kind=auth:app=systemd-cryptsetup:msg=UGxhbg==:state=blocked\e\\");

        test_format_one(
                        &REPORT(OSC_PROGRAM_STATUS_WORKING, "transfer", NO_KIND, 42, "importctl", "Plan", NULL),
                        "\e]7501;id=importctl/transfer:progress=42:app=importctl:title=UGxhbg==:state=working\e\\");

        test_format_one(
                        &REPORT(OSC_PROGRAM_STATUS_WORKING, "transfer", NO_KIND, 0, "importctl", NULL, NULL),
                        "\e]7501;id=importctl/transfer:progress=0:app=importctl:state=working\e\\");

        test_format_one(
                        &REPORT(OSC_PROGRAM_STATUS_BLOCKED, "prompt", NO_KIND, 100, "foo", NULL, NULL),
                        "\e]7501;id=foo/prompt:progress=100:app=foo:state=blocked\e\\");

        test_format_one(
                        &REPORT(OSC_PROGRAM_STATUS_DONE, "a/b", NO_KIND, NO_PROGRESS, "foo", NULL, NULL),
                        "\e]7501;id=foo/a/b:app=foo:state=done\e\\");

        test_format_one(
                        &REPORT(OSC_PROGRAM_STATUS_ERROR, "a", NO_KIND, NO_PROGRESS, "foo", NULL, NULL),
                        "\e]7501;id=foo/a:app=foo:state=error\e\\");

        test_format_one(
                        &REPORT(OSC_PROGRAM_STATUS_IDLE, "a", NO_KIND, NO_PROGRESS, "foo", NULL, NULL),
                        "\e]7501;id=foo/a:app=foo:state=idle\e\\");

        /* A clear only carries the id, nothing else */
        test_format_one(
                        &REPORT(OSC_PROGRAM_STATUS_CLEAR, "password", NO_KIND, NO_PROGRESS, "foo", "baz", "bar"),
                        "\e]7501;id=foo/password:state=clear\e\\");

        /* Empty texts are omitted */
        test_format_one(
                        &REPORT(OSC_PROGRAM_STATUS_DONE, "a", NO_KIND, NO_PROGRESS, "foo", " \t\n ", ""),
                        "\e]7501;id=foo/a:app=foo:state=done\e\\");
}

TEST(format_invalid) {
        _cleanup_free_ char *seq = NULL;

        /* Never the root record */
        ASSERT_ERROR(osc_program_status_format(&REPORT(OSC_PROGRAM_STATUS_CLEAR, NULL, NO_KIND, NO_PROGRESS, "foo", NULL, NULL), &seq), EINVAL);
        ASSERT_ERROR(osc_program_status_format(&REPORT(OSC_PROGRAM_STATUS_CLEAR, "", NO_KIND, NO_PROGRESS, "foo", NULL, NULL), &seq), EINVAL);

        FOREACH_STRING(id,
                       "/", "a//b", "/a", "a/", "a b", "a:b", "a=b", "ä", "a\nb",
                       "123456789012345678901234567890123",
                       "a/b/c/d/e/f/g/h" /* 8 segments plus the app makes 9 */)
                ASSERT_ERROR(osc_program_status_format(&REPORT(OSC_PROGRAM_STATUS_IDLE, id, NO_KIND, NO_PROGRESS, "foo", NULL, NULL), &seq), EINVAL);

        /* 128 bytes in total is OK, 129 is not */
        _cleanup_free_ char *id = strjoin("a/", strrepa("b", 32), "/", strrepa("c", 32), "/", strrepa("d", 32), "/", strrepa("e", 23));
        ASSERT_NOT_NULL(id);
        ASSERT_OK(osc_program_status_format(&REPORT(OSC_PROGRAM_STATUS_IDLE, id, NO_KIND, NO_PROGRESS, "foo", NULL, NULL), &seq));
        ASSERT_EQ(strlen("foo/") + strlen(id), 128U);
        seq = mfree(seq);
        ASSERT_NOT_NULL(strextend(&id, "e"));
        ASSERT_ERROR(osc_program_status_format(&REPORT(OSC_PROGRAM_STATUS_IDLE, id, NO_KIND, NO_PROGRESS, "foo", NULL, NULL), &seq), EINVAL);

        /* kind only with blocked */
        ASSERT_ERROR(osc_program_status_format(&REPORT(OSC_PROGRAM_STATUS_WORKING, "a", OSC_PROGRAM_STATUS_AUTH, NO_PROGRESS, NULL, NULL, NULL), &seq), EINVAL);
        ASSERT_ERROR(osc_program_status_format(&REPORT(OSC_PROGRAM_STATUS_BLOCKED, "a", _OSC_PROGRAM_STATUS_KIND_MAX, NO_PROGRESS, NULL, NULL, NULL), &seq), EINVAL);

        /* progress only with working and blocked, and at most 100 */
        ASSERT_ERROR(osc_program_status_format(&REPORT(OSC_PROGRAM_STATUS_WORKING, "a", NO_KIND, 101, NULL, NULL, NULL), &seq), EINVAL);
        ASSERT_ERROR(osc_program_status_format(&REPORT(OSC_PROGRAM_STATUS_DONE, "a", NO_KIND, 100, NULL, NULL, NULL), &seq), EINVAL);

        ASSERT_ERROR(osc_program_status_format(&REPORT(_OSC_PROGRAM_STATUS_STATE_INVALID, "a", NO_KIND, NO_PROGRESS, NULL, NULL, NULL), &seq), EINVAL);
        ASSERT_ERROR(osc_program_status_format(&REPORT(_OSC_PROGRAM_STATUS_STATE_MAX, "a", NO_KIND, NO_PROGRESS, NULL, NULL, NULL), &seq), EINVAL);

        ASSERT_NULL(seq);
}

TEST(id_is_valid) {
        ASSERT_TRUE(osc_program_status_id_is_valid("a"));
        ASSERT_TRUE(osc_program_status_id_is_valid("systemd-firstboot/prompt"));
        ASSERT_TRUE(osc_program_status_id_is_valid("A-Z_a.z+0-9"));
        ASSERT_TRUE(osc_program_status_id_is_valid("a/b/c/d/e/f/g/h"));
        ASSERT_TRUE(osc_program_status_id_is_valid("12345678901234567890123456789012"));

        ASSERT_FALSE(osc_program_status_id_is_valid(NULL));
        ASSERT_FALSE(osc_program_status_id_is_valid(""));
        ASSERT_FALSE(osc_program_status_id_is_valid("a/b/c/d/e/f/g/h/i"));
        ASSERT_FALSE(osc_program_status_id_is_valid("123456789012345678901234567890123"));
        ASSERT_FALSE(osc_program_status_id_is_valid("a,b"));
        ASSERT_FALSE(osc_program_status_id_is_valid("a/"));
}

static void test_app_one(const char *app, const char *expected) {
        _cleanup_free_ char *seq = NULL, *exp = NULL;

        ASSERT_OK(osc_program_status_format(&REPORT(OSC_PROGRAM_STATUS_IDLE, "x", NO_KIND, NO_PROGRESS, app, NULL, NULL), &seq));
        exp = strjoin("\e]7501;id=", expected, "/x:app=", expected, ":state=idle\e\\");
        ASSERT_NOT_NULL(exp);
        ASSERT_STREQ(seq, exp);
}

TEST(app) {
        test_app_one("systemd-tty-ask-password-agent", "systemd-tty-ask-password-agent");
        test_app_one("(sd-pam)", "sd-pam");
        test_app_one("a b:c/d=e", "abcde");
        test_app_one("", "systemd");
        test_app_one("()", "systemd");
        test_app_one("äöü", "systemd");
        test_app_one("123456789012345678901234567890123456789", "12345678901234567890123456789012");

        /* Without an explicit app, we use our own name */
        _cleanup_free_ char *seq = NULL;
        ASSERT_OK(osc_program_status_format(&REPORT(OSC_PROGRAM_STATUS_IDLE, "x", NO_KIND, NO_PROGRESS, NULL, NULL, NULL), &seq));
        ASSERT_STREQ(seq, "\e]7501;id=test-osc-program-status/x:app=test-osc-program-status:state=idle\e\\");
}

static char* decode_msg(const char *seq) {
        _cleanup_free_ void *decoded = NULL;
        size_t size;
        const char *p, *e;

        /* Extracts and decodes the "msg" value of a report */

        p = ASSERT_PTR(strstr(seq, ":msg="));
        p += STRLEN(":msg=");
        e = ASSERT_PTR(strchr(p, ':'));

        ASSERT_OK(unbase64mem_full(p, e - p, /* secure= */ false, &decoded, &size));
        ASSERT_EQ(strlen(decoded), size);
        ASSERT_LE(size, (size_t) OSC_PROGRAM_STATUS_MSG_MAX);
        ASSERT_TRUE(utf8_is_valid(decoded));

        /* No C0, DEL or C1 characters, since terminals would discard the whole report otherwise */
        for (const char *q = decoded; *q; ) {
                char32_t c;
                int l = utf8_encoded_valid_unichar_full(q, SIZE_MAX, &c);
                ASSERT_OK_POSITIVE(l);
                ASSERT_FALSE(c < 0x20 || (c >= 0x7f && c <= 0x9f));
                q += l;
        }

        return TAKE_PTR(decoded);
}

static void test_msg_one(const char *msg, const char *expected) {
        _cleanup_free_ char *seq = NULL, *decoded = NULL;

        ASSERT_OK(osc_program_status_format(&REPORT(OSC_PROGRAM_STATUS_DONE, "x", NO_KIND, NO_PROGRESS, "foo", NULL, msg), &seq));
        if (!expected) {
                /* Nothing left after sanitizing, hence no msg at all */
                ASSERT_NULL(strstr(seq, ":msg="));
                return;
        }

        decoded = decode_msg(seq);
        ASSERT_STREQ(decoded, expected);
        ASSERT_LE(strlen(seq), (size_t) OSC_PROGRAM_STATUS_SEQUENCE_MAX);
}

TEST(sanitize) {
        test_msg_one("Please enter passphrase for disk foo:", "Please enter passphrase for disk foo:");
        test_msg_one("  a\tb\nc\x7f\xc2\x85" "d\xff  ", "a b c d" UTF8_REPLACEMENT_CHARACTER);
        test_msg_one("\e[1mbold\e[0m and \e]8;;https://example.com\e\\link\e]8;;\e\\", "bold and link");
        test_msg_one("\e]7501;state=clear\e\\", NULL);
        test_msg_one("Schlüssel 🔐", "Schlüssel 🔐");

        /* Truncation, on a character boundary, with an ellipsis */
        _cleanup_free_ char *long_ascii = strdup(strrepa("x", 3000));
        _cleanup_free_ char *expected = strjoin(strrepa("x", OSC_PROGRAM_STATUS_MSG_MAX - STRLEN("…")), "…");
        ASSERT_NOT_NULL(long_ascii);
        ASSERT_NOT_NULL(expected);
        test_msg_one(long_ascii, expected);

        /* 2044 + 3×2 bytes is 2050 bytes, which must be cut in front of the first "ä", since cutting at
         * 2045 bytes would split it. */
        _cleanup_free_ char *long_utf8 = strjoin(strrepa("x", 2044), "äää");
        _cleanup_free_ char *expected_utf8 = strjoin(strrepa("x", 2044), "…");
        ASSERT_NOT_NULL(long_utf8);
        ASSERT_NOT_NULL(expected_utf8);
        test_msg_one(long_utf8, expected_utf8);

        /* Exactly at the limit, nothing is cut */
        _cleanup_free_ char *exact = strdup(strrepa("x", OSC_PROGRAM_STATUS_MSG_MAX));
        ASSERT_NOT_NULL(exact);
        test_msg_one(exact, exact);

        /* The title has a lower limit */
        _cleanup_free_ char *seq = NULL;
        _cleanup_free_ void *title = NULL;
        size_t size;
        ASSERT_OK(osc_program_status_format(&REPORT(OSC_PROGRAM_STATUS_DONE, "x", NO_KIND, NO_PROGRESS, "foo", long_ascii, NULL), &seq));
        const char *p = ASSERT_PTR(strstr(seq, ":title="));
        p += STRLEN(":title=");
        ASSERT_OK(unbase64mem_full(p, strcspn(p, ":"), /* secure= */ false, &title, &size));
        ASSERT_EQ(size, (size_t) OSC_PROGRAM_STATUS_TITLE_MAX);
        ASSERT_TRUE(endswith(title, "…"));

        /* Everything at the maximum still fits into the size limit of the specification */
        _cleanup_free_ char *max_id = strjoin(strrepa("b", 32), "/", strrepa("c", 32), "/", strrepa("d", 26));
        seq = mfree(seq);
        ASSERT_OK(osc_program_status_format(
                                  &REPORT(OSC_PROGRAM_STATUS_BLOCKED, max_id, OSC_PROGRAM_STATUS_PERMISSION, 100, long_ascii, long_ascii, long_ascii),
                                  &seq));
        ASSERT_LE(strlen(seq), (size_t) OSC_PROGRAM_STATUS_SEQUENCE_MAX);
}

static char* read_available(int fd) {
        _cleanup_free_ char *buf = NULL;
        size_t n = 0;

        /* Reads whatever is available on the (non-blocking) pty master */

        for (;;) {
                ASSERT_NOT_NULL(GREEDY_REALLOC(buf, n + 4096 + 1));

                if (fd_wait_for_event(fd, POLLIN, 100 * USEC_PER_MSEC) <= 0)
                        break;

                ssize_t l = read(fd, buf + n, 4096);
                if (l < 0 && errno == EAGAIN)
                        break;
                ASSERT_OK_ERRNO(l);
                if (l == 0)
                        break;
                n += l;
        }

        buf[n] = 0;
        return TAKE_PTR(buf);
}

static void set_env(const char *term, const char *status) {
        if (term)
                ASSERT_OK_ERRNO(setenv("TERM", term, /* overwrite= */ true));
        else
                ASSERT_OK_ERRNO(unsetenv("TERM"));

        if (status)
                ASSERT_OK_ERRNO(setenv("SYSTEMD_PROGRAM_STATUS", status, /* overwrite= */ true));
        else
                ASSERT_OK_ERRNO(unsetenv("SYSTEMD_PROGRAM_STATUS"));
}

TEST(enabled) {
        _cleanup_free_ char *saved_term = NULL, *saved_status = NULL;
        _cleanup_close_pair_ int pipe_fds[2] = EBADF_PAIR;

        ASSERT_OK(strdup_to(&saved_term, getenv("TERM")));
        ASSERT_OK(strdup_to(&saved_status, getenv("SYSTEMD_PROGRAM_STATUS")));

        _cleanup_close_ int pty_fd = ASSERT_OK(openpt_allocate(O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK, NULL));
        _cleanup_close_ int peer_fd = ASSERT_OK(pty_open_peer(pty_fd, O_RDWR|O_NOCTTY|O_CLOEXEC));
        ASSERT_OK_ERRNO(pipe2(pipe_fds, O_CLOEXEC));

        set_env("xterm-256color", NULL);
        ASSERT_TRUE(osc_program_status_wanted(/* flags= */ 0));
        ASSERT_TRUE(osc_program_status_enabled(peer_fd, /* flags= */ 0));
        ASSERT_FALSE(osc_program_status_enabled(pipe_fds[1], /* flags= */ 0));
        ASSERT_FALSE(osc_program_status_enabled(-EBADF, /* flags= */ 0));

        set_env("xterm-256color", "0");
        ASSERT_FALSE(osc_program_status_wanted(/* flags= */ 0));
        ASSERT_FALSE(osc_program_status_wanted(OSC_PROGRAM_STATUS_CONSOLE));
        ASSERT_FALSE(osc_program_status_enabled(peer_fd, /* flags= */ 0));

        set_env("xterm-256color", "1");
        ASSERT_TRUE(osc_program_status_enabled(peer_fd, /* flags= */ 0));

        set_env("xterm-256color", "garbage");
        ASSERT_TRUE(osc_program_status_enabled(peer_fd, /* flags= */ 0));

        set_env("dumb", NULL);
        ASSERT_FALSE(osc_program_status_wanted(/* flags= */ 0));
        ASSERT_FALSE(osc_program_status_wanted(OSC_PROGRAM_STATUS_CONSOLE));
        ASSERT_FALSE(osc_program_status_enabled(peer_fd, /* flags= */ 0));

        /* Without $TERM we don't know what we are talking to, unless it's the console, where we can look
         * at PID 1's $TERM or the kernel command line instead. The result of that depends on the system
         * we run on, hence just make sure it doesn't fail. */
        set_env(NULL, NULL);
        ASSERT_FALSE(osc_program_status_wanted(/* flags= */ 0));
        ASSERT_FALSE(osc_program_status_enabled(peer_fd, /* flags= */ 0));
        (void) osc_program_status_wanted(OSC_PROGRAM_STATUS_CONSOLE);

        set_env(saved_term, saved_status);
}

TEST(enabled_stdin) {
        _cleanup_free_ char *saved_term = NULL, *saved_status = NULL;
        _cleanup_close_pair_ int pipe_fds[2] = EBADF_PAIR;
        _cleanup_close_ int saved_stdin = -EBADF;

        saved_stdin = fcntl(STDIN_FILENO, F_DUPFD_CLOEXEC, 3);
        if (saved_stdin < 0)
                return (void) log_tests_skipped_errno(errno, "Failed to duplicate stdin");

        ASSERT_OK(strdup_to(&saved_term, getenv("TERM")));
        ASSERT_OK(strdup_to(&saved_status, getenv("SYSTEMD_PROGRAM_STATUS")));
        set_env("xterm-256color", NULL);

        _cleanup_close_ int pty_fd = ASSERT_OK(openpt_allocate(O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK, NULL));
        _cleanup_close_ int peer_fd = ASSERT_OK(pty_open_peer(pty_fd, O_RDWR|O_NOCTTY|O_CLOEXEC));
        ASSERT_OK_ERRNO(pipe2(pipe_fds, O_CLOEXEC));

        /* Answers piped in: don't claim we are blocked on the user */
        ASSERT_OK_ERRNO(dup2(pipe_fds[0], STDIN_FILENO));
        ASSERT_TRUE(osc_program_status_enabled(peer_fd, /* flags= */ 0));
        ASSERT_FALSE(osc_program_status_enabled(peer_fd, OSC_PROGRAM_STATUS_STDIN));

        ASSERT_OK_ERRNO(dup2(peer_fd, STDIN_FILENO));
        ASSERT_TRUE(osc_program_status_enabled(peer_fd, OSC_PROGRAM_STATUS_STDIN));

        ASSERT_OK_ERRNO(dup2(saved_stdin, STDIN_FILENO));
        set_env(saved_term, saved_status);
}

TEST(write_and_record) {
        _cleanup_free_ char *saved_term = NULL, *saved_status = NULL, *out = NULL;
        _cleanup_close_pair_ int pipe_fds[2] = EBADF_PAIR;

        ASSERT_OK(strdup_to(&saved_term, getenv("TERM")));
        ASSERT_OK(strdup_to(&saved_status, getenv("SYSTEMD_PROGRAM_STATUS")));
        set_env("xterm-256color", NULL);

        _cleanup_close_ int pty_fd = ASSERT_OK(openpt_allocate(O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK, NULL));
        _cleanup_close_ int peer_fd = ASSERT_OK(pty_open_peer(pty_fd, O_RDWR|O_NOCTTY|O_CLOEXEC));
        ASSERT_OK_ERRNO(pipe2(pipe_fds, O_CLOEXEC|O_NONBLOCK));

        /* Nothing is written into pipes */
        ASSERT_OK_ZERO(osc_program_status_clear(pipe_fds[1], /* flags= */ 0, "x"));
        char c;
        ASSERT_ERROR_ERRNO(read(pipe_fds[0], &c, 1), EAGAIN);

        ASSERT_OK_POSITIVE(osc_program_status_clear(peer_fd, /* flags= */ 0, "x"));
        out = read_available(pty_fd);
        ASSERT_STREQ(out, "\e]7501;id=test-osc-program-status/x:state=clear\e\\");
        out = mfree(out);

        /* A blocked record is cleared when the record object goes out of scope, and duplicates are suppressed */
        {
                _cleanup_(osc_program_status_record_clear) OscProgramStatusRecord r = OSC_PROGRAM_STATUS_RECORD_NULL;

                ASSERT_OK_POSITIVE(osc_program_status_record_blocked(&r, peer_fd, /* flags= */ 0, "prompt", OSC_PROGRAM_STATUS_QUESTION, "Plan"));
                ASSERT_OK_ZERO(osc_program_status_record_blocked(&r, peer_fd, /* flags= */ 0, "prompt", OSC_PROGRAM_STATUS_QUESTION, "Plan"));
                ASSERT_OK_POSITIVE(osc_program_status_record_blocked(&r, peer_fd, /* flags= */ 0, "prompt", OSC_PROGRAM_STATUS_AUTH, "Plan"));
        }

        out = read_available(pty_fd);
        ASSERT_STREQ(out,
                     "\e]7501;id=test-osc-program-status/prompt:kind=question:app=test-osc-program-status:msg=UGxhbg==:state=blocked\e\\"
                     "\e]7501;id=test-osc-program-status/prompt:kind=auth:app=test-osc-program-status:msg=UGxhbg==:state=blocked\e\\"
                     "\e]7501;id=test-osc-program-status/prompt:state=clear\e\\");
        out = mfree(out);

        /* A finished record is not cleared afterwards */
        {
                _cleanup_(osc_program_status_record_clear) OscProgramStatusRecord r = OSC_PROGRAM_STATUS_RECORD_NULL;

                /* Nothing to finish yet */
                ASSERT_OK_ZERO(osc_program_status_record_finish(&r, /* success= */ true, NULL));

                ASSERT_OK_POSITIVE(osc_program_status_record_working(&r, peer_fd, /* flags= */ 0, "transfer", 10, NULL));
                ASSERT_OK_ZERO(osc_program_status_record_working(&r, peer_fd, /* flags= */ 0, "transfer", 10, NULL));
                ASSERT_OK_POSITIVE(osc_program_status_record_working(&r, peer_fd, /* flags= */ 0, "transfer", 20, NULL));
                ASSERT_OK_POSITIVE(osc_program_status_record_finish(&r, /* success= */ false, "Plan"));
        }

        out = read_available(pty_fd);
        ASSERT_STREQ(out,
                     "\e]7501;id=test-osc-program-status/transfer:progress=10:app=test-osc-program-status:state=working\e\\"
                     "\e]7501;id=test-osc-program-status/transfer:progress=20:app=test-osc-program-status:state=working\e\\"
                     "\e]7501;id=test-osc-program-status/transfer:app=test-osc-program-status:msg=UGxhbg==:state=error\e\\");
        out = mfree(out);

        /* Nothing is written, and nothing needs clearing, when disabled */
        set_env("xterm-256color", "no");
        {
                _cleanup_(osc_program_status_record_clear) OscProgramStatusRecord r = OSC_PROGRAM_STATUS_RECORD_NULL;

                ASSERT_OK_ZERO(osc_program_status_record_blocked(&r, peer_fd, /* flags= */ 0, "prompt", OSC_PROGRAM_STATUS_AUTH, NULL));
                ASSERT_NULL(r.id);
        }

        out = read_available(pty_fd);
        ASSERT_STREQ(out, "");

        set_env(saved_term, saved_status);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
