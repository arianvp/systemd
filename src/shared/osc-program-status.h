/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* Generates OSC 7501 "Program Status Protocol" reports, which tell the terminal emulator what a program
 * is doing: whether it is working (possibly with a progress percentage), blocked waiting for the user (to
 * type a password, answer a question, or approve something), or finished. See:
 *
 * https://www.superlogical.com/rex/docs/build/program-status
 *
 * This is orthogonal to OSC 3008 (see osc-context.h): OSC 3008 describes *who* controls the terminal
 * (boot, container, VM, elevated session, service, …), while OSC 7501 describes *what* the program in the
 * foreground is currently doing.
 *
 * A couple of rules we follow here:
 *
 * • We never report on the root record (i.e. a report without an id), and we never send a "clear" without
 *   an id, since that would remove every record in the terminal, including those of whatever program (a
 *   shell script, a build tool, an agent, …) invoked us. Instead, every record id is prefixed by the
 *   program name, i.e. "<program>/<id>".
 *
 * • Terminals only drop "working" and "blocked" records automatically when the attached process exits or
 *   a new shell prompt is shown. When we write to a VM's serial console, or to a terminal forwarded via
 *   ptyfwd, the "attached process" from the terminal's PoV is qemu, nspawn, run0, … hence we need to clear
 *   every record we created explicitly. Use OscProgramStatusRecord with _cleanup_ for that.
 *
 * • We never send the "?" support query, since the reply would show up as input on the terminal, which is
 *   typically where we read the user's answer from. Terminals that do not know OSC 7501 ignore it. */

typedef enum OscProgramStatusState {
        OSC_PROGRAM_STATUS_IDLE,
        OSC_PROGRAM_STATUS_WORKING,
        OSC_PROGRAM_STATUS_DONE,
        OSC_PROGRAM_STATUS_BLOCKED,
        OSC_PROGRAM_STATUS_ERROR,
        OSC_PROGRAM_STATUS_CLEAR,
        _OSC_PROGRAM_STATUS_STATE_MAX,
        _OSC_PROGRAM_STATUS_STATE_INVALID = -EINVAL,
} OscProgramStatusState;

/* What a blocked program needs from the user */
typedef enum OscProgramStatusKind {
        OSC_PROGRAM_STATUS_PERMISSION, /* approval to do something */
        OSC_PROGRAM_STATUS_QUESTION,   /* an answer the user has to type */
        OSC_PROGRAM_STATUS_AUTH,       /* a password, PIN, token touch, or other credential */
        _OSC_PROGRAM_STATUS_KIND_MAX,
        _OSC_PROGRAM_STATUS_KIND_INVALID = -EINVAL, /* no kind */
} OscProgramStatusKind;

typedef enum OscProgramStatusFlags {
        /* The fd refers to /dev/console. If we have no $TERM ourselves, look at the one of PID 1 or the one
         * on the kernel command line instead. */
        OSC_PROGRAM_STATUS_CONSOLE = 1 << 0,
        /* We read the user's answer from stdin, hence only report that we are blocked on the user if stdin
         * is a TTY too, i.e. not if the answers are piped in. */
        OSC_PROGRAM_STATUS_STDIN   = 1 << 1,
} OscProgramStatusFlags;

#define OSC_PROGRAM_STATUS_PROGRESS_NONE UINT_MAX

/* Limits from the specification, in bytes */
#define OSC_PROGRAM_STATUS_SEQUENCE_MAX 4096U
#define OSC_PROGRAM_STATUS_TITLE_MAX 192U
#define OSC_PROGRAM_STATUS_MSG_MAX 2048U
#define OSC_PROGRAM_STATUS_APP_MAX 32U
#define OSC_PROGRAM_STATUS_ID_MAX 128U
#define OSC_PROGRAM_STATUS_ID_SEGMENT_MAX 32U
#define OSC_PROGRAM_STATUS_ID_DEPTH_MAX 8U

typedef struct OscProgramStatus {
        OscProgramStatusState state;
        /* Mandatory. Gets prefixed by the app name, i.e. "<app>/<id>". */
        const char *id;
        /* Only for blocked. _OSC_PROGRAM_STATUS_KIND_INVALID for none. */
        OscProgramStatusKind kind;
        /* 0…100, only for working and blocked. OSC_PROGRAM_STATUS_PROGRESS_NONE for none. */
        unsigned progress;
        /* If NULL, derived from program_invocation_short_name */
        const char *app;
        /* Free-form text, sanitized and truncated as needed. Optional. */
        const char *title;
        const char *msg;
} OscProgramStatus;

DECLARE_STRING_TABLE_LOOKUP_TO_STRING(osc_program_status_state, OscProgramStatusState);
DECLARE_STRING_TABLE_LOOKUP_TO_STRING(osc_program_status_kind, OscProgramStatusKind);

bool osc_program_status_id_is_valid(const char *id) _pure_;

/* Generates the escape sequence for the specified report. Does not check whether it should be emitted. */
int osc_program_status_format(const OscProgramStatus *s, char **ret_seq);

/* Checks whether reports are wanted at all, without looking at any specific fd: $SYSTEMD_PROGRAM_STATUS
 * must not be set to false, and $TERM must be set and not be "dumb". With OSC_PROGRAM_STATUS_CONSOLE, if
 * $TERM is not set, the one of PID 1 or the kernel command line is checked instead. */
bool osc_program_status_wanted(OscProgramStatusFlags flags);

/* Checks whether reports should be written to the specified fd: in addition to the above, it must be a
 * TTY, and so must stdin if OSC_PROGRAM_STATUS_STDIN is set. */
bool osc_program_status_enabled(int fd, OscProgramStatusFlags flags);

/* Writes the report to the specified fd, if enabled. Returns 0 if suppressed, 1 if written. */
int osc_program_status_write(int fd, OscProgramStatusFlags flags, const OscProgramStatus *s);

/* Removes the specified record (and the records below it), if enabled */
int osc_program_status_clear(int fd, OscProgramStatusFlags flags, const char *id);

/* Tracks a record we reported on, so that it can be cleared again on all exit paths. Declare it *after* the
 * fd it refers to, so that it is destroyed (and the clear is written) before the fd is closed. */
typedef struct OscProgramStatusRecord {
        int fd;                      /* borrowed */
        OscProgramStatusFlags flags;
        char *id;                    /* set while the terminal shows a record that we need to clear */
        char *last_seq;              /* the last report written, to suppress duplicates */
} OscProgramStatusRecord;

#define OSC_PROGRAM_STATUS_RECORD_NULL (OscProgramStatusRecord) { .fd = -EBADF }

int osc_program_status_record_blocked(
                OscProgramStatusRecord *r,
                int fd,
                OscProgramStatusFlags flags,
                const char *id,
                OscProgramStatusKind kind,
                const char *msg);
int osc_program_status_record_working(
                OscProgramStatusRecord *r,
                int fd,
                OscProgramStatusFlags flags,
                const char *id,
                unsigned progress,
                const char *msg);

/* Reports "done" or "error" for the record, if we reported on it before. These two states are kept by the
 * terminal even after we exit, so that the user can see the result later. Hence we do not clear it
 * afterwards. Only use this for long-running operations the user might have stopped watching. */
int osc_program_status_record_finish(OscProgramStatusRecord *r, bool success, const char *msg);

/* Clears the record, if we reported on it before, and releases the resources. Suitable for _cleanup_. */
void osc_program_status_record_clear(OscProgramStatusRecord *r);
