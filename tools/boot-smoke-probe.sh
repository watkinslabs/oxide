#!/usr/bin/env bash
# Generic userspace-probe gate: boot the kernel, log in over the serial
# console (alice/swordfish), run a /bin/<probe>, and assert it prints
# "<probe>: PASS". For probes that must run from a real login shell (the
# rcS smoke path does not run under the systemd boot).
#
# Usage:
#   tools/boot-smoke-probe.sh <x86|arm> <probe-name> [timeout_seconds]
# Example:
#   tools/boot-smoke-probe.sh x86 drm_probe 360
set -uo pipefail

usage() { echo "usage: $0 <x86|arm> <probe-name> [timeout_seconds]" >&2; exit 2; }
ARCH="${1:-}"; PROBE="${2:-}"; TIMEOUT="${3:-360}"
case "$ARCH" in
    x86) MAKE_TARGET=qemu-x86 ;;
    arm) MAKE_TARGET=qemu-arm ;;
    *)   usage ;;
esac
[ -n "$PROBE" ] || usage

LOG="$(mktemp /tmp/oxide-probe-${ARCH}-${PROBE}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-probe-${ARCH}-${PROBE}-XXXXXX.pid)"
QIN="$(mktemp -u /tmp/oxide-probe-${ARCH}-${PROBE}-qin-XXXXXX)"
mkfifo "$QIN"
cleanup() {
    if [ -s "$PIDFILE" ]; then
        local pid; pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "-$pid" 2>/dev/null || true; sleep 1
            kill -KILL "-$pid" 2>/dev/null || true
        fi
    fi
    exec 9>&- 2>/dev/null || true
    rm -f "$LOG" "$PIDFILE" "$QIN"
}
trap cleanup EXIT

echo "boot-smoke-probe: arch=$ARCH probe=$PROBE timeout=${TIMEOUT}s log=$LOG"
exec 9<>"$QIN"
OXIDE_QEMU_HEADLESS=1 setsid bash -c "exec make '$MAKE_TARGET' > '$LOG' 2>&1 < '$QIN'" &
echo $! > "$PIDFILE"

wait_for() {
    local pat="$1" label="$2" deadline="$3"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local pid; pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "boot-smoke-probe: FAIL — qemu exited before $label" >&2
            tail -n 50 "$LOG" >&2; exit 1
        fi
        grep -aq "$pat" "$LOG" 2>/dev/null && return 0
        sleep 2
    done
    echo "boot-smoke-probe: FAIL — timeout waiting for $label" >&2
    tail -n 50 "$LOG" >&2; exit 1
}

deadline=$(( $(date +%s) + TIMEOUT ))
wait_for "oxide login:" "login prompt" "$deadline"
sleep 1; printf 'alice\n' >&9
sleep 2; printf 'swordfish\n' >&9
wait_for 'oxide:~\$' "shell prompt" "$deadline"
printf '/bin/%s\n' "$PROBE" >&9
while [ "$(date +%s)" -lt "$deadline" ]; do
    if grep -aq "${PROBE}: PASS" "$LOG" 2>/dev/null; then
        echo "boot-smoke-probe: PASS — ${PROBE}"
        grep -aE "${PROBE}:" "$LOG" | tail -2
        exit 0
    fi
    if grep -aq "${PROBE}: FAIL" "$LOG" 2>/dev/null; then
        echo "boot-smoke-probe: FAIL — ${PROBE} reported failure" >&2
        grep -aE "${PROBE}:" "$LOG" >&2; exit 1
    fi
    sleep 2
done
echo "boot-smoke-probe: FAIL — timeout (no ${PROBE} verdict)" >&2
grep -aE "${PROBE}:" "$LOG" >&2 || true
tail -n 50 "$LOG" >&2; exit 1
