#!/usr/bin/env bash
# Framebuffer KEYBOARD login gate (console-plan B0). Boots headless with a QMP
# control socket, waits for `oxide login:`, then injects REAL virtio-keyboard
# events via QMP `send-key` (not serial RX) to type the username + password +
# `id`. /dev/console output mirrors to serial, so success is observed there:
# `uid=1000(alice)`. Proves keystrokes from the physical keyboard reach
# console-getty/login/shell on the framebuffer console.
#
# Usage: tools/boot-smoke-kbd-login.sh x86 [timeout]
set -uo pipefail

ARCH="${1:-x86}"; TIMEOUT="${2:-${SMOKE_TIMEOUT:-300}}"
case "$ARCH" in x86) MT=qemu-x86 ;; arm) MT=qemu-arm ;; *) echo "arch x86|arm"; exit 2 ;; esac

LOG="$(mktemp /tmp/oxide-kbd-login-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-kbd-login-XXXXXX.pid)"
QMP="$(mktemp -u /tmp/oxide-kbd-qmp-XXXXXX.sock)"
cleanup() {
    if [ -s "$PIDFILE" ]; then
        local pid; pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && { kill -TERM "-$pid" 2>/dev/null; sleep 1; kill -KILL "-$pid" 2>/dev/null; }
    fi
    [ -n "${KEEP_LOG:-}" ] && cp -f "$LOG" "$KEEP_LOG" 2>/dev/null || true
    rm -f "$LOG" "$PIDFILE" "$QMP"
}
trap cleanup EXIT

echo "kbd-login: arch=$ARCH timeout=${TIMEOUT}s qmp=$QMP log=$LOG"
OXIDE_QEMU_HEADLESS=1 OXIDE_QEMU_QMP_SOCK="$QMP" OXIDE_QEMU_KVM="${OXIDE_QEMU_KVM:-1}" \
    setsid bash -c "exec make '$MT' > '$LOG' 2>&1 < /dev/null" &
echo $! > "$PIDFILE"

deadline=$(( $(date +%s) + TIMEOUT ))
wait_for() {
    local pat="$1" label="$2"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local pid; pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "kbd-login: FAIL — qemu exited before $label" >&2; tail -n 40 "$LOG" >&2; exit 1
        fi
        grep -aq "$pat" "$LOG" 2>/dev/null && return 0
        sleep 2
    done
    echo "kbd-login: FAIL — timeout waiting for $label" >&2; tail -n 60 "$LOG" >&2; exit 1
}

wait_for "oxide login:" "login prompt"
[ -S "$QMP" ] || { echo "kbd-login: FAIL — QMP socket absent" >&2; exit 1; }
sleep 1

# Inject keystrokes through QMP send-key (real virtio-keyboard events). All
# chars here are lowercase letters → qcode == the letter; Enter == "ret".
python3 - "$QMP" <<'PY'
import socket, json, sys, time
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.settimeout(10)
f = s.makefile("rwb", buffering=0)
def rd():
    line = f.readline()
    return json.loads(line) if line else {}
rd()  # QMP greeting
def cmd(obj): f.write((json.dumps(obj)+"\r\n").encode());
def send_key(k): cmd({"execute":"send-key","arguments":{"keys":[{"type":"qcode","data":k}]}}); rd()
cmd({"execute":"qmp_capabilities"}); rd()
def typ(text, delay=0.06):
    for ch in text:
        send_key("ret" if ch == "\n" else ("spc" if ch == " " else ch))
        time.sleep(delay)
typ("alice\n");      time.sleep(1.5)
typ("swordfish\n");  time.sleep(2.0)
typ("id\n");         time.sleep(0.5)
PY

wait_for "uid=1000(alice)" "id output after keyboard login"
echo "kbd-login: PASS — framebuffer keyboard login reached a shell (uid=1000)"
