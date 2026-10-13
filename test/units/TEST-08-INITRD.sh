#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if systemd-detect-virt -qc; then
    echo >&2 "This test can't run in a container"
    exit 1
fi

# This test requires systemd to run in the initrd as well, which is not the case
# for mkinitrd-based initrd (Ubuntu/Debian)
if [[ "$(systemctl show -P InitRDTimestampMonotonic)" -eq 0 ]]; then
    echo "systemd didn't run in the initrd, skipping the test"
    touch /skipped
    exit 77
fi

# We should've created a mount under /run in initrd (see the other half of the test)
# that should've survived the transition from initrd to the real system
test -d /run/initrd-mount-target
mountpoint /run/initrd-mount-target
[[ -e /run/initrd-mount-target/hello-world ]]

# The initrd-run-initramfs.service in the initrd should have populated /run/initramfs
# from the initrd's own contents before switch-root.
test -x /run/initramfs/shutdown

# PID 1 should log to journald's socket as soon as it is listening, even if journald itself isn't up yet,
# so that the structured fields of its messages are retained. Check this for the initrd, where journald is
# started for the first time, and for the host, where the initrd's journald is terminated on switch-root
# and started again.
# See: https://github.com/systemd/systemd/issues/43622
journalctl --sync
# This is measured again on switch-root, i.e. marks the transition from the initrd to the host
USERSPACE_USEC="$(systemctl show -P UserspaceTimestampMonotonic)"
check_journald_job_message() {
    local message_id="${1:?}"
    local filter="${2:?}"

    # Use --slurp, so that not finding any matching entry is an error with jq < 1.7 too
    journalctl -b -o json _PID=1 _TRANSPORT=journal UNIT=systemd-journald.service MESSAGE_ID="$message_id" |
        jq -s -e --argjson usec "$USERSPACE_USEC" \
           "any(.[]; (.__MONOTONIC_TIMESTAMP | tonumber) $filter \$usec and .JOB_ID != null)" >/dev/null
}
# "Starting Journal Service…" and "Started Journal Service." in the initrd
check_journald_job_message 7d4958e842da4a758f6c1cdc7b36dcc5 "<"
check_journald_job_message 39f53479d3a045ac8e11786248231fbf "<"
# "Started Journal Service." after switch-root
check_journald_job_message 39f53479d3a045ac8e11786248231fbf ">="

touch /testok
