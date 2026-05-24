#!/usr/bin/env bash
# F155 DHCP-path smoke. Boots with OXIDE_UDHCPC_ENABLE=1 + checks for
# the udhcpc lease confirmation line ("udhcpc: configured eth0 as ...
# via …") on serial within $TIMEOUT seconds. Mirrors boot-smoke.sh's
# pattern but for the full DHCP-online chain (lease + ifconfig + route
# + resolv.conf via /usr/share/udhcpc/default.script).
#
# Usage:
#   tools/boot-smoke-dhcp.sh x86 600
#   tools/boot-smoke-dhcp.sh arm 900
set -uo pipefail

usage() { echo "usage: $0 <x86|arm> [timeout_seconds]" >&2; exit 2; }
ARCH="${1:-}"
case "$ARCH" in
    x86) MAKE_TARGET=qemu-x86 ;;
    arm) MAKE_TARGET=qemu-arm ;;
    *)   usage ;;
esac
TIMEOUT="${2:-600}"

LOG="$(mktemp /tmp/oxide-smoke-dhcp-${ARCH}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-smoke-dhcp-${ARCH}-XXXXXX.pid)"
cleanup() {
    if [ -s "$PIDFILE" ]; then
        local pid; pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "-$pid" 2>/dev/null || true
            sleep 1
            kill -KILL "-$pid" 2>/dev/null || true
        fi
    fi
    rm -f "$LOG" "$PIDFILE"
}
trap cleanup EXIT

echo "boot-smoke-dhcp: arch=$ARCH timeout=${TIMEOUT}s log=$LOG"

OXIDE_QEMU_HEADLESS=1 OXIDE_UDHCPC_ENABLE=1 setsid bash -c \
    "exec make '$MAKE_TARGET' > '$LOG' 2>&1 < /dev/null" &
echo $! > "$PIDFILE"

deadline=$(( $(date +%s) + TIMEOUT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
        echo "boot-smoke-dhcp: FAIL — qemu exited" >&2
        tail -n 60 "$LOG" >&2
        exit 1
    fi
    if grep -q "udhcpc: configured eth0" "$LOG" 2>/dev/null; then
        elapsed=$(( $(date +%s) - (deadline - TIMEOUT) ))
        echo "boot-smoke-dhcp: PASS — $ARCH got lease in ${elapsed}s"
        grep -E "udhcpc:|online_smoke|tcp_smoke" "$LOG" | tail -10
        exit 0
    fi
    sleep 2
done

echo "boot-smoke-dhcp: FAIL — timeout after ${TIMEOUT}s without lease" >&2
tail -n 80 "$LOG" >&2
exit 1
