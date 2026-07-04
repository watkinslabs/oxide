#!/usr/bin/env bash
# B002 single-machine driver-path gate. Boots once with an opt-in systemd
# service that proves one GPU, one input device, one sound card, one root disk,
# and one network device from userspace-visible Linux surfaces.
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

LOG="$(mktemp /tmp/oxide-driver-path-${ARCH}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-driver-path-${ARCH}-XXXXXX.pid)"
QMP="$(mktemp -u /tmp/oxide-driver-path-${ARCH}-qmp-XXXXXX.sock)"
UART="$(mktemp -u /tmp/oxide-driver-path-${ARCH}-uart-XXXXXX.sock)"
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

echo "driver-path-smoke: arch=$ARCH timeout=${TIMEOUT}s qmp=$QMP uart=$UART log=$LOG"
OXIDE_DRIVER_PATH_SMOKE=1 OXIDE_QEMU_HEADLESS=1 OXIDE_QEMU_QMP_SOCK="$QMP" OXIDE_QEMU_UART_SOCK="$UART" OXIDE_QEMU_KVM="${OXIDE_QEMU_KVM:-1}" \
    setsid bash -c "exec make '$MT' > '$LOG' 2>&1 < /dev/null" &
echo $! > "$PIDFILE"
for _ in $(seq 1 600); do
    [ -S "$UART" ] && break
    sleep 0.1
done
[ -S "$UART" ] || { echo "driver-path-smoke: FAIL - UART socket absent" >&2; exit 1; }
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
wait_for() {
    local pat="$1" label="$2"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local pid
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "driver-path-smoke: FAIL - qemu exited before $label" >&2
            tail -n 60 "$LOG" >&2
            exit 1
        fi
        if grep -aqE 'fbdev_probe: FAIL|drm_probe: FAIL|sysblock_probe: FAIL|snd_probe: FAIL|rtlink_probe: FAIL|mouseprobe: FAIL|driver-path-smoke.service: Failed' "$LOG" 2>/dev/null; then
            echo "driver-path-smoke: FAIL - service failed before $label" >&2
            grep -aE 'fbdev_probe:|drm_probe:|sysblock_probe:|snd_probe:|rtlink_probe:|b002_net_eth0:|mouseprobe:|driver_path_smoke:|driver-path-smoke.service' "$LOG" >&2
            exit 1
        fi
        grep -aqE "$pat" "$LOG" 2>/dev/null && return 0
        sleep 2
    done
    echo "driver-path-smoke: FAIL - timeout waiting for $label" >&2
    tail -n 80 "$LOG" >&2
    exit 1
}

[ -S "$QMP" ] || { echo "driver-path-smoke: FAIL - QMP socket absent" >&2; exit 1; }
wait_for 'driver_path_smoke: run mouseprobe' "mouseprobe start"
echo "driver-path-smoke: inject mouse events"
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
    r = rd()
    print("driver-path-smoke: qmp " + command + ": " + str(r), file=sys.stderr)
    return r
hmp("info mice")
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
    if grep -aq 'driver_path_smoke: PASS - GPU input sound block net' "$LOG" 2>/dev/null; then
        grep -aE 'fbdev_probe:|drm_probe:|sysblock_probe:|snd_probe:|rtlink_probe:|b002_net_eth0:|mouseprobe:|driver_path_smoke:' "$LOG" | tail -16
        echo "driver-path-smoke: PASS - GPU input sound block net"
        exit 0
    fi
    if grep -aqE 'fbdev_probe: FAIL|drm_probe: FAIL|sysblock_probe: FAIL|snd_probe: FAIL|rtlink_probe: FAIL|mouseprobe: FAIL|driver-path-smoke.service: Failed' "$LOG" 2>/dev/null; then
        echo "driver-path-smoke: FAIL - service reported failure" >&2
        grep -aE 'fbdev_probe:|drm_probe:|sysblock_probe:|snd_probe:|rtlink_probe:|b002_net_eth0:|mouseprobe:|driver_path_smoke:|driver-path-smoke.service' "$LOG" >&2
        exit 1
    fi
    sleep 2
done

echo "driver-path-smoke: FAIL - timeout waiting for service verdict" >&2
tail -n 80 "$LOG" >&2
exit 1
