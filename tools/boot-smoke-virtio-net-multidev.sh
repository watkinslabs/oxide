#!/usr/bin/env bash
# B580 virtio-net multi-device gate. Boots with two virtio-net devices
# and waits for the guest probe to prove netdev remove/readd loops.
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

LOG="$(mktemp /tmp/oxide-virtio-net-multidev-${ARCH}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-virtio-net-multidev-${ARCH}-XXXXXX.pid)"
QMP="$(mktemp -u /tmp/oxide-virtio-net-multidev-${ARCH}-qmp-XXXXXX.sock)"
UART="$(mktemp -u /tmp/oxide-virtio-net-multidev-${ARCH}-uart-XXXXXX.sock)"
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

echo "virtio-net-multidev-smoke: arch=$ARCH timeout=${TIMEOUT}s qmp=$QMP uart=$UART log=$LOG"
OXIDE_DRIVER_PATH_SMOKE=1 OXIDE_VIRTIO_NET_MULTIDEV_SMOKE=1 OXIDE_QEMU_HEADLESS=1 OXIDE_QEMU_QMP_SOCK="$QMP" OXIDE_QEMU_UART_SOCK="$UART" OXIDE_QEMU_KVM="${OXIDE_QEMU_KVM:-1}" \
    setsid bash -c "exec make '$MT' > '$LOG' 2>&1 < /dev/null" &
echo $! > "$PIDFILE"
for _ in $(seq 1 600); do
    [ -S "$UART" ] && [ -S "$QMP" ] && break
    sleep 0.1
done
[ -S "$UART" ] || { echo "virtio-net-multidev-smoke: FAIL - UART socket absent" >&2; exit 1; }
[ -S "$QMP" ] || { echo "virtio-net-multidev-smoke: FAIL - QMP socket absent" >&2; exit 1; }
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
    if grep -aqE 'virtio_net_multidev_probe: FAIL|b382_.*: FAIL|b580_.*: FAIL|fbdev_probe: FAIL|drm_probe: FAIL|sysblock_probe: FAIL|rtlink_probe: FAIL|snd_probe: FAIL|driver-path-smoke.service: Failed|\[EXIT\] name=init code=[1-9]' "$LOG" 2>/dev/null; then
        echo "virtio-net-multidev-smoke: FAIL - probe reported failure before mouseprobe" >&2
        grep -aE 'virtio_net_multidev_probe:|b382_|b580_|fbdev_probe:|drm_probe:|sysblock_probe:|rtlink_probe:|snd_probe:|driver_path_smoke:|driver-path-smoke.service' "$LOG" >&2
        exit 1
    fi
    sleep 1
done
grep -aq 'driver_path_smoke: run mouseprobe' "$LOG" 2>/dev/null || {
    echo "virtio-net-multidev-smoke: FAIL - timeout waiting for mouseprobe marker" >&2
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
rd()
cmd({"execute": "qmp_capabilities"})
def hmp(command):
    cmd({"execute": "human-monitor-command", "arguments": {"command-line": command}})
def send_key(k):
    cmd({"execute": "send-key", "arguments": {"keys": [{"type": "qcode", "data": k}]}})
def input_event(evs):
    cmd({"execute": "input-send-event", "arguments": {"events": evs}})
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
    pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
        echo "virtio-net-multidev-smoke: FAIL - qemu exited before verdict" >&2
        tail -n 80 "$LOG" >&2
        exit 1
    fi
    if grep -aq 'driver_path_smoke: PASS - GPU input sound block net virtio-net-multidev-rebind' "$LOG" 2>/dev/null; then
        grep -aE 'virtio_net_multidev_probe:|b382_|b580_|fbdev_probe:|drm_probe:|sysblock_probe:|rtlink_probe:|snd_probe:|mouseprobe:|driver_path_smoke:' "$LOG" | tail -70
        echo "virtio-net-multidev-smoke: PASS"
        exit 0
    fi
    if grep -aqE 'virtio_net_multidev_probe: FAIL|b382_.*: FAIL|b580_.*: FAIL|fbdev_probe: FAIL|drm_probe: FAIL|sysblock_probe: FAIL|rtlink_probe: FAIL|snd_probe: FAIL|mouseprobe: FAIL|driver-path-smoke.service: Failed' "$LOG" 2>/dev/null; then
        echo "virtio-net-multidev-smoke: FAIL - probe reported failure" >&2
        grep -aE 'virtio_net_multidev_probe:|b382_|b580_|fbdev_probe:|drm_probe:|sysblock_probe:|rtlink_probe:|snd_probe:|mouseprobe:|driver_path_smoke:|driver-path-smoke.service' "$LOG" >&2
        exit 1
    fi
    sleep 2
done

echo "virtio-net-multidev-smoke: FAIL - timeout waiting for verdict" >&2
tail -n 80 "$LOG" >&2
exit 1
