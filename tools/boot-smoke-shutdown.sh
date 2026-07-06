#!/usr/bin/env bash
# B599 terminal driver-shutdown gate. Boots a direct-init reboot probe and
# requires driver-core shutdown callbacks before QEMU exits via -no-reboot.
set -euo pipefail

usage() {
    echo "usage: $0 <x86|arm> [timeout_seconds]" >&2
    exit 2
}

ARCH="${1:-}"
TIMEOUT="${2:-${SMOKE_TIMEOUT:-600}}"
case "$ARCH" in
    x86) MT=qemu-x86; SERIAL_DRIVER=8250-serial ;;
    arm) MT=qemu-arm; SERIAL_DRIVER=pl011-serial ;;
    *) usage ;;
esac

LOG="$(mktemp /tmp/oxide-shutdown-${ARCH}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-shutdown-${ARCH}-XXXXXX.pid)"
UART="$(mktemp -u /tmp/oxide-shutdown-${ARCH}-uart-XXXXXX.sock)"
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

echo "shutdown-smoke: arch=$ARCH timeout=${TIMEOUT}s uart=$UART log=$LOG"
OXIDE_DRIVER_PATH_SMOKE=1 OXIDE_SHUTDOWN_SMOKE=1 OXIDE_QEMU_HEADLESS=1 OXIDE_QEMU_UART_SOCK="$UART" OXIDE_QEMU_KVM="${OXIDE_QEMU_KVM:-1}" \
    setsid bash -c "exec make '$MT' > '$LOG' 2>&1 < /dev/null" &
echo $! > "$PIDFILE"
for _ in $(seq 1 600); do
    [ -S "$UART" ] && break
    sleep 0.1
done
[ -S "$UART" ] || { echo "shutdown-smoke: FAIL - UART socket absent" >&2; exit 1; }
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

need() {
    local pattern="$1"
    if ! grep -aqE "$pattern" "$LOG" 2>/dev/null; then
        echo "shutdown-smoke: FAIL - missing pattern: $pattern" >&2
        grep -aE 'shutdown_probe:|driver_shutdown' "$LOG" >&2 || true
        exit 1
    fi
}

deadline=$(( $(date +%s) + TIMEOUT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null || true
        need 'power_cmd restart'
        need "driver_shutdown bus=platform addr=serial0 driver=${SERIAL_DRIVER}"
        need 'driver_shutdown bus=pci .* driver=virtio-pci'
        need 'driver_shutdown bus=pci .* driver=nvme'
        need 'driver_shutdown bus=pci .* driver=ahci'
        need 'driver_shutdown bus=virtio .* driver=virtio-gpu'
        need 'driver_shutdown bus=virtio .* driver=virtio-input'
        need 'driver_shutdown bus=virtio .* driver=virtio-net'
        need 'driver_shutdown bus=virtio .* driver=virtio-blk'
        need 'driver_shutdown bus=virtio .* driver=virtio-rng'
        need 'driver_shutdown bus=virtio .* driver=virtio-vsock'
        need 'driver_shutdown bus=virtio .* driver=virtio-snd'
        grep -aE 'shutdown_probe:|power_cmd|driver_shutdown' "$LOG"
        echo "shutdown-smoke: PASS"
        exit 0
    fi
    if grep -aq 'shutdown_probe: FAIL' "$LOG" 2>/dev/null; then
        echo "shutdown-smoke: FAIL - reboot syscall returned" >&2
        grep -aE 'shutdown_probe:|power_cmd|driver_shutdown' "$LOG" >&2 || true
        exit 1
    fi
    sleep 1
done

echo "shutdown-smoke: FAIL - timeout waiting for reboot exit" >&2
tail -n 100 "$LOG" >&2
exit 1
