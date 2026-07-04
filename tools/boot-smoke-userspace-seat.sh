#!/usr/bin/env bash
# B326 udev/logind seat gate. Boots with an opt-in systemd oneshot that checks
# the userspace discovery chain after the kernel-visible device nodes exist.
set -euo pipefail

usage() {
    echo "usage: $0 <x86|arm> [timeout_seconds]" >&2
    exit 2
}

ARCH="${1:-}"
TIMEOUT="${2:-${SMOKE_TIMEOUT:-600}}"
case "$ARCH" in
    x86) MT=qemu-x86 ;;
    arm) MT=qemu-arm ;;
    *) usage ;;
esac

LOG="$(mktemp /tmp/oxide-userspace-seat-${ARCH}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-userspace-seat-${ARCH}-XXXXXX.pid)"
UART="$(mktemp -u /tmp/oxide-userspace-seat-${ARCH}-uart-XXXXXX.sock)"
UART_BRIDGE_PID=""

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
    [ -n "$UART_BRIDGE_PID" ] && kill "$UART_BRIDGE_PID" 2>/dev/null || true
    [ -n "${KEEP_LOG:-}" ] && cp -f "$LOG" "$KEEP_LOG" 2>/dev/null || true
    rm -f "$LOG" "$PIDFILE" "$UART"
}
trap cleanup EXIT

echo "userspace-seat-smoke: arch=$ARCH timeout=${TIMEOUT}s uart=$UART log=$LOG"
OXIDE_USERSPACE_SEAT_SMOKE=1 OXIDE_QEMU_HEADLESS=1 OXIDE_QEMU_UART_SOCK="$UART" OXIDE_QEMU_KVM="${OXIDE_QEMU_KVM:-1}" \
    setsid bash -c "exec make '$MT' > '$LOG' 2>&1 < /dev/null" &
echo $! > "$PIDFILE"
for _ in $(seq 1 600); do
    [ -S "$UART" ] && break
    sleep 0.1
done
[ -S "$UART" ] || { echo "userspace-seat-smoke: FAIL - UART socket absent" >&2; exit 1; }
python3 - "$UART" "$LOG" <<'PY' &
import socket, sys

uart, log_path = sys.argv[1:3]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(uart)
with open(log_path, "ab", buffering=0) as log:
    while True:
        data = sock.recv(4096)
        if not data:
            break
        log.write(data)
PY
UART_BRIDGE_PID=$!

deadline=$(( $(date +%s) + TIMEOUT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
        echo "userspace-seat-smoke: FAIL - qemu exited before verdict" >&2
        tail -n 80 "$LOG" >&2
        exit 1
    fi
    if grep -aq 'userspace_seat_smoke: PASS' "$LOG" 2>/dev/null; then
        grep -aE 'userspace_seat_smoke:|fbdev_probe:|drm_probe:|sysblock_probe:|snd_probe:|rtlink_probe:' "$LOG" | tail -32
        echo "userspace-seat-smoke: PASS"
        exit 0
    fi
    if grep -aq 'userspace_seat_smoke: FAIL' "$LOG" 2>/dev/null; then
        echo "userspace-seat-smoke: FAIL - service reported gaps" >&2
        grep -aE 'userspace_seat_smoke:|fbdev_probe:|drm_probe:|sysblock_probe:|snd_probe:|rtlink_probe:' "$LOG" >&2
        exit 1
    fi
    sleep 2
done

echo "userspace-seat-smoke: FAIL - timeout waiting for service verdict" >&2
tail -n 80 "$LOG" >&2
exit 1
