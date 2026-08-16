#!/usr/bin/env bash
# Host-share acceptance: does a guest MOUNT a directory belonging to the host
# and read a file the host wrote?
#
# Nothing hosted can answer that. The protocol, the client, the option parsing
# and the attribute translation are all covered by `cargo test`; what is not is
# the descriptor chain — the DMA staging path, the device-reported length
# clamping, and the queue submit. Those are proven by this and only by this.
#
# The host writes a file into a scratch directory, QEMU exports it under a
# mount tag, and the guest mounts the tag and cats the file back. The content
# is a per-run nonce, so a stale mount or a cached page cannot pass for a live
# read.
#
# Usage:
#   tools/boot-smoke-hostshare.sh x86 [timeout_seconds]   # default 600
#   tools/boot-smoke-hostshare.sh arm [timeout_seconds]

set -uo pipefail

# This harness drives the guest through systemd's root debug shell over the
# serial FIFO: it types a command and waits for the output. The boot line's
# default puts that shell on a VT and a LOGIN on the serial line, which would
# swallow every command as a username, so ask for the serial control plane —
# the boot-line builder moves the shell and masks the login together.
export OXIDE_SERIAL_SHELL="${OXIDE_SERIAL_SHELL:-1}"

usage() {
    cat >&2 <<EOF
usage: $0 <x86|arm> [timeout_seconds]
EOF
    exit 2
}

ARCH="${1:-}"
case "$ARCH" in
    x86) MAKE_TARGET=qemu-x86 ;;
    arm) MAKE_TARGET=qemu-arm ;;
    *)   usage ;;
esac

# Vendor preflight: a fresh worktree has no `vendor/`, and an ARM guest then
# fails before QEMU starts with a message that reads like a kernel fault.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tools/vendor-preflight.sh"
vendor_preflight || exit 2
TIMEOUT="${2:-${SMOKE_TIMEOUT:-600}}"

LOG="$(mktemp /tmp/oxide-hostshare-smoke-${ARCH}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-hostshare-smoke-${ARCH}-XXXXXX.pid)"
QIN="$(mktemp -u /tmp/oxide-hostshare-smoke-${ARCH}-qin-XXXXXX)"
mkfifo "$QIN"
cleanup() {
    if [ -s "$PIDFILE" ]; then
        local pid
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "-$pid" 2>/dev/null || true
            sleep 1
            kill -KILL "-$pid" 2>/dev/null || true
        fi
    fi
    rm -f "$PIDFILE" "$QIN"
    [ -n "${SHARE:-}" ] && rm -rf "$SHARE"
    # $LOG is preserved for inspection
}
trap cleanup EXIT

echo "boot-smoke-hostshare: arch=$ARCH timeout=${TIMEOUT}s log=$LOG"

exec 9<>"$QIN"

# The host side of the share: a scratch directory and a per-run nonce, so the
# content the guest reads back cannot have come from anywhere but this run.
SHARE="$(mktemp -d /tmp/oxide-hostshare-XXXXXX)"
NONCE="hostshare-$(date +%s)-$$"
printf '%s\n' "$NONCE" > "$SHARE/from-host.txt"
mkdir -p "$SHARE/subdir"
printf 'nested\n' > "$SHARE/subdir/nested.txt"
chmod -R a+rX "$SHARE"
TAG=hostshare
echo "boot-smoke-hostshare: share=$SHARE tag=$TAG nonce=$NONCE"

OXIDE_QEMU_9P_SHARE="$SHARE" OXIDE_QEMU_9P_TAG="$TAG" \
    OXIDE_QEMU_HEADLESS=1 setsid bash -c "exec make '$MAKE_TARGET' > '$LOG' 2>&1 < '$QIN'" &
echo $! > "$PIDFILE"

deadline=$(( $(date +%s) + TIMEOUT ))

wait_for() {
    local pat="$1" label="$2"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local pid
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "boot-smoke-hostshare: FAIL — qemu exited before $label" >&2
            tail -n 80 "$LOG" >&2
            exit 1
        fi
        if grep -aq "$pat" "$LOG" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    echo "boot-smoke-hostshare: FAIL — timeout waiting for $label" >&2
    tail -n 120 "$LOG" >&2
    exit 1
}

# Each step is one shell command + own DONE marker. PASS = every
# marker observed in order. FAIL = a step's marker never arrives →
# that path wedges.
TAGS=()
wait_for_step() {
    local pat="$1" label="$2"
    local retry_deadline=$(( $(date +%s) + 20 ))
    while [ "$(date +%s)" -lt "$deadline" ] && [ "$(date +%s)" -lt "$retry_deadline" ]; do
        local pid
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "boot-smoke-hostshare: FAIL — qemu exited before $label" >&2
            tail -n 80 "$LOG" >&2
            exit 1
        fi
        grep -aq "$pat" "$LOG" 2>/dev/null && return 0
        sleep 1
    done
    return 1
}

step() {
    local tag="$1" cmd="$2"
    TAGS+=("$tag")
    local attempt
    for attempt in 1 2 3; do
        send_slowly "$cmd; echo ===DONE_${tag}==="
        wait_for_step "===DONE_${tag}===" "$tag" && return 0
    done
    echo "boot-smoke-hostshare: FAIL — timeout waiting for $tag after 3 sends" >&2
    tail -n 120 "$LOG" >&2
    exit 1
}

# The production image boots a graphical session and has no serial getty.
# Its command line deliberately starts systemd's root debug shell on the
# serial tty, the canonical in-guest control plane for smoke probes.
wait_for "Started debug-shell.service" "debug shell"
sleep 1

# The UART shares the line with early boot output and can drop long bursts.
# Type commands in small chunks so the shell receives every probe intact.
send_slowly() {
    local text="$1" i=0
    while [ "$i" -lt "${#text}" ]; do
        printf '%s' "${text:$i:8}" >&9
        i=$(( i + 8 ))
        sleep 0.3
    done
    printf '\n' >&9
}

# The device must have bound before anything can be mounted through it. A
# missing tag here means the driver never probed, which is a different failure
# from a mount that was refused.
step have_9p_type   'grep -q 9p /proc/filesystems || { echo no-9p-type; exit 1; }'
step have_virtiofs  'grep -q virtiofs /proc/filesystems || { echo no-virtiofs-type; exit 1; }'
step mkdir_mnt      'mkdir -p /mnt/host'

# The mount itself: attach, version handshake, root getattr.
step mount_9p       "mount -t 9p -o trans=virtio,version=9P2000.L,msize=131096 $TAG /mnt/host"
step mounted_shows  'grep " /mnt/host " /proc/mounts'

# Reading a file the host wrote is the whole point.
step read_nonce     'cat /mnt/host/from-host.txt'
step nonce_matches  "grep -qx '$NONCE' /mnt/host/from-host.txt || { echo nonce-mismatch; exit 1; }"

# Directory listing exercises Treaddir and its cookie contract.
step list_share     'ls -la /mnt/host'
step list_has_file  'ls /mnt/host | grep -qx from-host.txt || { echo missing-entry; exit 1; }'
step walk_subdir    'cat /mnt/host/subdir/nested.txt'

# Metadata: Tgetattr through stat(2).
step stat_file      'stat -c %s:%F /mnt/host/from-host.txt'
step statfs_share   'stat -f -c %T /mnt/host'

# Writing back is what makes the share useful in both directions.
step write_back     'echo guest-wrote-this > /mnt/host/from-guest.txt'
step read_back      'cat /mnt/host/from-guest.txt'
step create_dir     'mkdir -p /mnt/host/made-by-guest'
step remove_file    'rm -f /mnt/host/from-guest.txt'

step unmount_share  'umount /mnt/host'
step share_done     'echo hostshare-roundtrip-clean'

# The host's own view is the check the guest cannot fake: a file the guest
# claimed to create must exist on the host side.
if [ ! -d "$SHARE/made-by-guest" ]; then
    echo "boot-smoke-hostshare: FAIL — the guest's mkdir never reached the host" >&2
    exit 1
fi

echo "boot-smoke-hostshare: PASS — guest read the host's nonce and wrote back (${#TAGS[@]} steps)"
