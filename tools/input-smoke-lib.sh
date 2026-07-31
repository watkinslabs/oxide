#!/usr/bin/env bash
# Shared harness for the input gates. The injected `oxide-input-delivery`
# oneshot owns the verdict; these helpers only mirror the guest console,
# wait for its READY announcement, drive real QMP input, and read the result.
# Sourced by boot-smoke-mouse.sh and boot-smoke-virtio-input-rebind.sh.

# Mirror the guest UART socket into the boot log so the probe's console output
# is greppable. $1 uart socket, $2 log, $3 pidfile, $4 label.
input_smoke_bridge_uart() {
    local uart="$1" log="$2" pidfile="$3" label="$4"
    local waited=0
    while [ "$waited" -lt 900 ]; do
        [ -S "$uart" ] && break
        local pid; pid="$(cat "$pidfile" 2>/dev/null || true)"
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "$label: FAIL - qemu exited before the UART socket appeared" >&2
            tail -n 60 "$log" >&2
            exit 1
        fi
        sleep 0.2
        waited=$(( waited + 1 ))
    done
    [ -S "$uart" ] || { echo "$label: FAIL - UART socket absent" >&2; exit 1; }
    python3 - "$uart" "$log" <<'PY' &
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
}

# Block until the probe announces the named phase. $1 phase, $2 log,
# $3 pidfile, $4 deadline epoch, $5 label.
input_smoke_wait_ready() {
    local phase="$1" log="$2" pidfile="$3" deadline="$4" label="$5"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local pid; pid="$(cat "$pidfile" 2>/dev/null || true)"
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "$label: FAIL - qemu exited before phase=$phase" >&2
            tail -n 80 "$log" >&2
            exit 1
        fi
        if grep -aq "input_delivery: FAIL" "$log" 2>/dev/null; then
            echo "$label: FAIL - probe reported failure before phase=$phase" >&2
            grep -aE 'input_delivery:' "$log" >&2
            exit 1
        fi
        grep -aq "input_delivery: READY phase=$phase " "$log" 2>/dev/null && {
            grep -aE "input_delivery: READY phase=$phase " "$log" | tail -n 1
            return 0
        }
        sleep 1
    done
    echo "$label: FAIL - timeout waiting for phase=$phase" >&2
    tail -n 80 "$log" >&2
    exit 1
}

# Inject real pointer and keyboard events through QMP for the probe's window.
# $1 qmp socket.
input_smoke_inject() {
    local qmp="$1"
    [ -S "$qmp" ] || { echo "input-smoke: FAIL - QMP socket absent" >&2; exit 1; }
    python3 - "$qmp" <<'PY'
import json, socket, sys, time

ROUNDS = 40
ROUND_PAUSE_SECONDS = 0.3
MOTION_X = 12
MOTION_Y = -7

s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.settimeout(20)
f = s.makefile("rwb", buffering=0)

def rd():
    line = f.readline()
    return json.loads(line) if line else {}

def cmd(o):
    f.write((json.dumps(o) + "\r\n").encode())

rd()
cmd({"execute": "qmp_capabilities"}); rd()
cmd({"execute": "query-mice"}); print("MICE:", rd())

def send_key(k):
    cmd({"execute": "send-key", "arguments": {"keys": [{"type": "qcode", "data": k}]}})
    rd()

def input_event(evs):
    cmd({"execute": "input-send-event", "arguments": {"events": evs}})
    rd()

for _ in range(ROUNDS):
    send_key("a")
    input_event([
        {"type": "rel", "data": {"axis": "x", "value": MOTION_X}},
        {"type": "rel", "data": {"axis": "y", "value": MOTION_Y}},
    ])
    input_event([{"type": "btn", "data": {"button": "left", "down": True}}])
    input_event([{"type": "btn", "data": {"button": "left", "down": False}}])
    time.sleep(ROUND_PAUSE_SECONDS)
PY
}

# Wait for the probe's own PASS/FAIL. $1 log, $2 deadline epoch, $3 label.
input_smoke_verdict() {
    local log="$1" deadline="$2" label="$3"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if grep -aq 'input_delivery: PASS' "$log" 2>/dev/null; then
            grep -aE 'input_delivery:' "$log" | tail -n 20
            echo "$label: PASS"
            exit 0
        fi
        if grep -aq 'input_delivery: FAIL' "$log" 2>/dev/null; then
            echo "$label: FAIL - probe reported failure" >&2
            grep -aE 'input_delivery:' "$log" >&2
            exit 1
        fi
        sleep 2
    done
    echo "$label: FAIL - timeout waiting for the probe verdict" >&2
    grep -aE 'input_delivery:' "$log" >&2 || true
    tail -n 80 "$log" >&2
    exit 1
}
