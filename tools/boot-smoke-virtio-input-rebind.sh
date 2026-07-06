#!/usr/bin/env bash
# B576 virtio-input live rebind gate. The guest unbinds/rebinds the pointer
# virtio-input child, then mouseprobe proves restored evdev event delivery.
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

LOG="$(mktemp /tmp/oxide-virtio-input-rebind-${ARCH}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-virtio-input-rebind-${ARCH}-XXXXXX.pid)"
QMP="$(mktemp -u /tmp/oxide-virtio-input-rebind-${ARCH}-qmp-XXXXXX.sock)"
UART="$(mktemp -u /tmp/oxide-virtio-input-rebind-${ARCH}-uart-XXXXXX.sock)"
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
    rm -f "$LOG" "$PIDFILE" "$QMP" "$UART"
}
trap cleanup EXIT

echo "virtio-input-rebind-smoke: arch=$ARCH timeout=${TIMEOUT}s qmp=$QMP uart=$UART log=$LOG"
OXIDE_DRIVER_PATH_SMOKE=1 OXIDE_VIRTIO_INPUT_REBIND_SMOKE=1 OXIDE_QEMU_HEADLESS=1 OXIDE_QEMU_QMP_SOCK="$QMP" OXIDE_QEMU_UART_SOCK="$UART" OXIDE_QEMU_KVM="${OXIDE_QEMU_KVM:-1}" \
    setsid bash -c "exec make '$MT' > '$LOG' 2>&1 < /dev/null" &
echo $! > "$PIDFILE"
for _ in $(seq 1 600); do
    [ -S "$UART" ] && [ -S "$QMP" ] && break
    sleep 0.1
done
[ -S "$UART" ] || { echo "virtio-input-rebind-smoke: FAIL - UART socket absent" >&2; exit 1; }
[ -S "$QMP" ] || { echo "virtio-input-rebind-smoke: FAIL - QMP socket absent" >&2; exit 1; }
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
    grep -aq 'driver_path_smoke: run mouseprobe' "$LOG" 2>/dev/null && break
    if grep -aqE 'virtio_input_rebind_probe: FAIL|b576_.*: FAIL|driver-path-smoke.service: Failed|\\[EXIT\\] name=init code=[1-9]' "$LOG" 2>/dev/null; then
        echo "virtio-input-rebind-smoke: FAIL - probe reported failure before mouseprobe" >&2
        grep -aE 'virtio_input_rebind_probe:|b576_|driver_path_smoke:|driver-path-smoke.service' "$LOG" >&2
        exit 1
    fi
    sleep 1
done
grep -aq 'driver_path_smoke: run mouseprobe' "$LOG" 2>/dev/null || {
    echo "virtio-input-rebind-smoke: FAIL - timeout waiting for mouseprobe marker" >&2
    tail -n 80 "$LOG" >&2
    exit 1
}

python3 - "$QMP" <<'PY'
import json, socket, sys, time

s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.settimeout(15)
f = s.makefile("rwb", buffering=0)
def rd():
    line = f.readline()
    return json.loads(line) if line else {}
def cmd(o):
    f.write((json.dumps(o) + "\r\n").encode())
rd()
cmd({"execute": "qmp_capabilities"}); rd()
def hmp(command):
    cmd({"execute": "human-monitor-command", "arguments": {"command-line": command}})
    rd()
def send_key(k):
    cmd({"execute": "send-key", "arguments": {"keys": [{"type": "qcode", "data": k}]}})
    rd()
def input_event(evs):
    cmd({"execute": "input-send-event", "arguments": {"events": evs}})
    rd()
for idx in range(6):
    hmp("mouse_set " + str(idx))
    for _ in range(8):
        send_key("a")
        input_event([
            {"type": "rel", "data": {"axis": "x", "value": 12}},
            {"type": "rel", "data": {"axis": "y", "value": -7}},
        ])
        input_event([{"type": "btn", "data": {"button": "left", "down": True}}])
        input_event([{"type": "btn", "data": {"button": "left", "down": False}}])
        time.sleep(0.15)
PY

while [ "$(date +%s)" -lt "$deadline" ]; do
    if grep -aq 'driver_path_smoke: PASS - virtio-input-rebind' "$LOG" 2>/dev/null; then
        grep -aE 'virtio_input_rebind_probe:|b576_|mouseprobe:|driver_path_smoke:' "$LOG" | tail -48
        echo "virtio-input-rebind-smoke: PASS"
        exit 0
    fi
    if grep -aqE 'virtio_input_rebind_probe: FAIL|b576_.*: FAIL|mouseprobe: FAIL|driver-path-smoke.service: Failed|\\[EXIT\\] name=init code=[1-9]' "$LOG" 2>/dev/null; then
        echo "virtio-input-rebind-smoke: FAIL - probe reported failure" >&2
        grep -aE 'virtio_input_rebind_probe:|b576_|mouseprobe:|driver_path_smoke:|driver-path-smoke.service' "$LOG" >&2
        exit 1
    fi
    sleep 2
done

echo "virtio-input-rebind-smoke: FAIL - timeout waiting for verdict" >&2
tail -n 80 "$LOG" >&2
exit 1
