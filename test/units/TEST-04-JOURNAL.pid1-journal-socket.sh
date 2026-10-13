#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Check that PID 1 keeps logging to the journal socket while journald is down, instead of falling back to
# kmsg (or the console in containers), which drops all structured fields (MESSAGE_ID=, UNIT=, JOB_ID=, …)
# of its messages.
# See: https://github.com/systemd/systemd/issues/43622

CURSOR_FILE="$(mktemp)"
trap 'rm -f "$CURSOR_FILE"' EXIT

journalctl --sync
journalctl --cursor-file="$CURSOR_FILE" -n1

# While journald is restarted, PID 1 logs "Stopping …" right after sending SIGTERM to it, "Stopped …" once
# it is gone, and "Starting …" before the new instance is up, i.e. while journald.service isn't active.
systemctl restart systemd-journald.service
journalctl --sync

for message_id in de5b426a63be47a7b6ac3eaac82e2f6f \
                  9d1aaa27d60140bd96365438aad20286 \
                  7d4958e842da4a758f6c1cdc7b36dcc5; do
    # Use --slurp, so that not finding any matching entry is an error with jq < 1.7 too
    journalctl -q --after-cursor="$(<"$CURSOR_FILE")" -o json \
               _PID=1 _TRANSPORT=journal MESSAGE_ID="$message_id" UNIT=systemd-journald.service |
        jq -s -e 'any(.[]; .JOB_ID != null and .JOB_TYPE != null)' >/dev/null
done
