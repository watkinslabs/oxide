#!/usr/bin/env bash
# Boot the micro (Xorg + JWM) image and capture what is actually on the
# screen, so "is there a desktop?" is answered by a framebuffer dump rather
# than by reading a log and inferring.
#
# Usage: tools/micro-desktop-shot.sh [marker-regex] [timeout_s] [out-prefix]
set -uo pipefail
FEATURES="${FEATURES:-}"

MARKER="${1:-micro-desktop.service}"
TIMEOUT="${2:-240}"
OUT="${3:-/tmp/micro-desktop}"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

SERIAL="${OUT}-serial.log"
QMP="${OUT}-qmp.sock"
SHOT="${OUT}-screen.ppm"

pkill -9 -f qemu-system 2>/dev/null || true
sleep 2
rm -f "$SERIAL" "$QMP" "$SHOT"

OXIDE_QUICKBOOT_PROFILE=micro \
OXIDE_QEMU_HEADLESS=1 \
OXIDE_QEMU_QMP_SOCK="${QMP}" \
setsid bash -c "exec cargo run -q -p xtask -- grub --arch x86_64 --smp 1 --id micro ${FEATURES:+--features \"$FEATURES\"} > '$SERIAL' 2>&1 < /dev/null" &

deadline=$(( $(date +%s) + TIMEOUT ))
status=timeout
while [ "$(date +%s)" -lt "$deadline" ]; do
    sleep 3
    grep -qE "$MARKER" "$SERIAL" 2>/dev/null && { status=match; break; }
done

# Let the session settle after the marker, then dump the scanout.
[ "$status" = match ] && sleep 20

python3 - "$QMP" "$SHOT" <<'PY'
import json, socket, sys, time
sock_path, shot = sys.argv[1], sys.argv[2]
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(sock_path)
    f = s.makefile("rw")
    f.readline()                                   # greeting
    for cmd in ({"execute": "qmp_capabilities"},
                {"execute": "screendump", "arguments": {"filename": shot}}):
        f.write(json.dumps(cmd) + "\n"); f.flush()
        while True:
            line = f.readline()
            if not line: break
            msg = json.loads(line)
            if "return" in msg or "error" in msg:
                print("qmp:", json.dumps(msg)); break
    time.sleep(2)
except Exception as e:
    print("qmp: FAILED", e)
PY

pkill -9 -f qemu-system 2>/dev/null || true
echo "micro-desktop-shot: status=$status serial=$SERIAL shot=$SHOT"
ls -l "$SHOT" 2>/dev/null || echo "micro-desktop-shot: no screendump produced"
