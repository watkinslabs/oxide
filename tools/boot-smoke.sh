#!/usr/bin/env bash
# Boot-smoke gate. Boots the kernel under qemu headless and waits
# for `oxide login:` on serial within $SMOKE_TIMEOUT seconds. Exit
# 0 on success, 1 on timeout, 2 on argument / build error.
#
# Usage:
#   tools/boot-smoke.sh x86            # default 600s timeout
#   tools/boot-smoke.sh arm 1200       # explicit timeout
#   SMOKE_TIMEOUT=1200 tools/boot-smoke.sh x86
#
# CI uses this as the PR-time gate; local devs can run it the same
# way. `make qemu-arm` exiting at login on a dev box (~30s) takes
# ~10-15min under TCG on a hosted runner — pick the timeout
# accordingly.
set -uo pipefail

usage() {
    cat >&2 <<EOF
usage: $0 <x86|arm> [timeout_seconds]
       SMOKE_TIMEOUT env var also accepted (defaults to 600).
EOF
    exit 2
}

ARCH="${1:-}"
case "$ARCH" in
    x86) MAKE_TARGET=qemu-x86 ;;
    arm) MAKE_TARGET=qemu-arm ;;
    *)   usage ;;
esac
TIMEOUT="${2:-${SMOKE_TIMEOUT:-600}}"

LOG="$(mktemp /tmp/oxide-boot-smoke-${ARCH}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-boot-smoke-${ARCH}-XXXXXX.pid)"
cleanup() {
    if [ -s "$PIDFILE" ]; then
        local pid
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        # `setsid` made the child a new process-group leader, so
        # `kill -- -PID` sends to the whole group (make → xtask →
        # qemu-system-*). Without the leading `-` we'd kill bash
        # but leave qemu running.
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "-$pid" 2>/dev/null || true
            sleep 1
            kill -KILL "-$pid" 2>/dev/null || true
        fi
    fi
    rm -f "$LOG" "$PIDFILE"
}
trap cleanup EXIT

echo "boot-smoke: arch=$ARCH timeout=${TIMEOUT}s log=$LOG"

# Headless + no-stdin: feed /dev/null so qemu's stdio chardev
# doesn't try to read from CI's missing TTY.
OXIDE_QEMU_HEADLESS=1 setsid bash -c "exec make '$MAKE_TARGET' > '$LOG' 2>&1 < /dev/null" &
echo $! > "$PIDFILE"

deadline=$(( $(date +%s) + TIMEOUT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
        echo "boot-smoke: FAIL — qemu exited before login marker" >&2
        echo "------ last 60 lines of log ------" >&2
        tail -n 60 "$LOG" >&2
        exit 1
    fi
    if grep -q "oxide login:" "$LOG" 2>/dev/null; then
        elapsed=$(( $(date +%s) - (deadline - TIMEOUT) ))
        echo "boot-smoke: PASS — $ARCH reached login in ${elapsed}s"
        exit 0
    fi
    sleep 2
done

echo "boot-smoke: FAIL — timeout after ${TIMEOUT}s without login marker" >&2
echo "------ last 80 lines of log ------" >&2
tail -n 80 "$LOG" >&2
exit 1
