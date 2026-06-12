#!/usr/bin/env bash
# virtio-tablet pointer gate (F458). Boots headless, logs in over the SERIAL
# console (reliable, mirrored to the log), runs /bin/mouseprobe (reads
# /dev/input/event1), then injects REAL pointer events via QMP
# `input-send-event` (absolute motion + a left click). mouseprobe prints
# `mouseprobe: PASS` once it observes EV_ABS + EV_KEY(BTN) + EV_SYN on
# event1 — proving host pointer input reaches the second evdev node through
# virtio-input. Serial login decouples the reliable login path from the QMP
# pointer injection.
#
# Usage: tools/boot-smoke-mouse.sh x86|arm [timeout]
set -uo pipefail

ARCH="${1:-x86}"; TIMEOUT="${2:-${SMOKE_TIMEOUT:-360}}"
case "$ARCH" in x86) MT=qemu-x86 ;; arm) MT=qemu-arm ;; *) echo "arch x86|arm"; exit 2 ;; esac

LOG="$(mktemp /tmp/oxide-mouse-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-mouse-XXXXXX.pid)"
QMP="$(mktemp -u /tmp/oxide-mouse-qmp-XXXXXX.sock)"
QIN="$(mktemp -u /tmp/oxide-mouse-qin-XXXXXX)"; mkfifo "$QIN"
cleanup() {
    if [ -s "$PIDFILE" ]; then
        local pid; pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && { kill -TERM "-$pid" 2>/dev/null; sleep 1; kill -KILL "-$pid" 2>/dev/null; }
    fi
    exec 9>&- 2>/dev/null || true
    [ -n "${KEEP_LOG:-}" ] && cp -f "$LOG" "$KEEP_LOG" 2>/dev/null || true
    rm -f "$LOG" "$PIDFILE" "$QMP" "$QIN"
}
trap cleanup EXIT

echo "mouse-smoke: arch=$ARCH timeout=${TIMEOUT}s qmp=$QMP log=$LOG"
exec 9<>"$QIN"
OXIDE_QEMU_HEADLESS=1 OXIDE_QEMU_QMP_SOCK="$QMP" OXIDE_QEMU_KVM="${OXIDE_QEMU_KVM:-1}" \
    setsid bash -c "exec make '$MT' > '$LOG' 2>&1 < '$QIN'" &
echo $! > "$PIDFILE"

deadline=$(( $(date +%s) + TIMEOUT ))
wait_for() {
    local pat="$1" label="$2"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local pid; pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "mouse-smoke: FAIL — qemu exited before $label" >&2; tail -n 40 "$LOG" >&2; exit 1
        fi
        grep -aqE "$pat" "$LOG" 2>/dev/null && return 0
        sleep 2
    done
    echo "mouse-smoke: FAIL — timeout waiting for $label" >&2; tail -n 60 "$LOG" >&2; exit 1
}

# Serial login (reliable; output mirrors to LOG).
wait_for "oxide login:" "login prompt"
sleep 1; printf 'alice\n'     >&9
sleep 2; printf 'swordfish\n' >&9
wait_for 'oxide:~[#$]' "shell prompt"
[ -S "$QMP" ] || { echo "mouse-smoke: FAIL — QMP socket absent" >&2; exit 1; }

# Launch the probe (polls event1 ~8 s), then inject pointer events via QMP.
printf '/bin/mouseprobe\n' >&9
sleep 1
python3 - "$QMP" <<'PY'
import socket, json, sys, time
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.settimeout(15)
f = s.makefile("rwb", buffering=0)
def rd():
    line = f.readline(); return json.loads(line) if line else {}
def cmd(o): f.write((json.dumps(o)+"\r\n").encode())
rd(); cmd({"execute":"qmp_capabilities"}); rd()
cmd({"execute":"query-mice"}); print("MICE:", rd())
def ise(evs): cmd({"execute":"input-send-event","arguments":{"events":evs}}); rd()
def sk(k): cmd({"execute":"send-key","arguments":{"keys":[{"type":"qcode","data":k}]}}); rd()
# Diagnostic: a keystroke (→ event0) interleaved with relative motion + a
# left click (→ event1). Both injected to their current virtio device.
for _ in range(8):
    sk("a")
    ise([{"type":"rel","data":{"axis":"x","value":12}},
         {"type":"rel","data":{"axis":"y","value":-7}}])
    ise([{"type":"btn","data":{"button":"left","down":True}}])
    ise([{"type":"btn","data":{"button":"left","down":False}}])
    time.sleep(0.4)
PY

# Verdict.
while [ "$(date +%s)" -lt "$deadline" ]; do
    grep -aq "mouseprobe: PASS" "$LOG" 2>/dev/null && { echo "mouse-smoke: PASS — virtio-tablet pointer events reached /dev/input/event1"; exit 0; }
    grep -aq "mouseprobe: FAIL" "$LOG" 2>/dev/null && { echo "mouse-smoke: FAIL — mouseprobe reported failure" >&2; grep -aE 'mouseprobe:' "$LOG" >&2; exit 1; }
    sleep 2
done
echo "mouse-smoke: FAIL — timeout (no mouseprobe verdict)" >&2; tail -n 40 "$LOG" >&2; exit 1
