#!/usr/bin/env bash
# B399 virtio-snd multi-device gate. Boots once with two virtio-snd devices
# and waits for the guest probe to prove ALSA card add/remove/readd.
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

LOG="$(mktemp /tmp/oxide-virtio-snd-multidev-${ARCH}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-virtio-snd-multidev-${ARCH}-XXXXXX.pid)"
UART="$(mktemp -u /tmp/oxide-virtio-snd-multidev-${ARCH}-uart-XXXXXX.sock)"
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

echo "virtio-snd-multidev-smoke: arch=$ARCH timeout=${TIMEOUT}s uart=$UART log=$LOG"
OXIDE_DRIVER_PATH_SMOKE=1 OXIDE_VIRTIO_SND_MULTIDEV_SMOKE=1 OXIDE_QEMU_HEADLESS=1 OXIDE_QEMU_UART_SOCK="$UART" OXIDE_QEMU_KVM="${OXIDE_QEMU_KVM:-1}" \
    setsid bash -c "exec make '$MT' > '$LOG' 2>&1 < /dev/null" &
echo $! > "$PIDFILE"
for _ in $(seq 1 600); do
    [ -S "$UART" ] && break
    sleep 0.1
done
[ -S "$UART" ] || { echo "virtio-snd-multidev-smoke: FAIL - UART socket absent" >&2; exit 1; }
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
        echo "virtio-snd-multidev-smoke: FAIL - qemu exited before verdict" >&2
        tail -n 80 "$LOG" >&2
        exit 1
    fi
    if grep -aq 'driver_path_smoke: PASS - GPU sound block net virtio-snd-multidev-rebind' "$LOG" 2>/dev/null; then
        grep -aE 'virtio_snd_multidev_probe:|b399_|fbdev_probe:|drm_probe:|sysblock_probe:|rtlink_probe:|snd_probe:|driver_path_smoke:' "$LOG" | tail -32
        echo "virtio-snd-multidev-smoke: PASS"
        exit 0
    fi
    if grep -aqE 'virtio_snd_multidev_probe: FAIL|b399_.*: FAIL|fbdev_probe: FAIL|drm_probe: FAIL|sysblock_probe: FAIL|rtlink_probe: FAIL|snd_probe: FAIL|driver-path-smoke.service: Failed' "$LOG" 2>/dev/null; then
        echo "virtio-snd-multidev-smoke: FAIL - probe reported failure" >&2
        grep -aE 'virtio_snd_multidev_probe:|b399_|fbdev_probe:|drm_probe:|sysblock_probe:|rtlink_probe:|snd_probe:|driver_path_smoke:|driver-path-smoke.service' "$LOG" >&2
        exit 1
    fi
    sleep 2
done

echo "virtio-snd-multidev-smoke: FAIL - timeout waiting for verdict" >&2
tail -n 80 "$LOG" >&2
exit 1
