#!/usr/bin/env bash
# Boot a desktop image and capture what is actually on the screen, so "is there
# a desktop?" is answered by a framebuffer dump rather than by reading a log and
# inferring.
#
# Usage: tools/desktop-shot.sh [marker-regex] [timeout_s] [out-prefix]
#
# Env:
#   PROFILE   images profile to boot (default micro)
#   BUILD_ID  build namespace, so concurrent lanes do not share an image copy
#             (default: the profile name)
#   FEATURES  kernel cargo features, e.g. debug-desktop for the DRM ioctl trace
#   GPU       set to 1 to attach virtio-gpu instead of the firmware VGA
#   SETTLE    seconds to wait after the marker before the screendump (default 20)
set -uo pipefail
FEATURES="${FEATURES:-}"
PROFILE="${PROFILE:-micro}"
BUILD_ID="${BUILD_ID:-$PROFILE}"
GPU="${GPU:-}"
SETTLE="${SETTLE:-20}"

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

# A conditional assignment must be built as an `env` argument, not spliced into
# the assignment prefix: a word that only appears after expansion is the command
# name, so `${GPU:+VAR=1} setsid ...` runs a command called `VAR=1` and the boot
# never starts, leaving no serial log to explain why.
env_args=(OXIDE_QUICKBOOT_PROFILE="$PROFILE" OXIDE_QEMU_HEADLESS=1 OXIDE_QEMU_QMP_SOCK="$QMP")
[ -n "$GPU" ] && env_args+=(OXIDE_QEMU_VIRTIO_GPU=1)

feature_args=""
[ -n "$FEATURES" ] && feature_args="--features $FEATURES"

setsid env "${env_args[@]}" bash -c \
    "exec cargo run -q -p xtask -- grub --arch x86_64 --smp 1 --id $BUILD_ID $feature_args > '$SERIAL' 2>&1 < /dev/null" &

deadline=$(( $(date +%s) + TIMEOUT ))
status=timeout
while [ "$(date +%s)" -lt "$deadline" ]; do
    sleep 3
    grep -qE "$MARKER" "$SERIAL" 2>/dev/null && { status=match; break; }
done

# Let the session settle after the marker, then dump the scanout. A desktop
# reaches graphical.target long before its greeter or window manager has drawn
# anything, so the settle is the caller's to size.
[ "$status" = match ] && sleep "$SETTLE"

# QMP refuses a connection when qemu is gone, which is a different answer from
# a screendump that failed — say which one happened rather than reporting an
# empty capture.
if ! pgrep -f "qemu-system-x86_64.*$BUILD_ID" >/dev/null 2>&1 \
   && ! pgrep -x qemu-system-x86_64 >/dev/null 2>&1; then
    echo "desktop-shot: WARNING qemu is no longer running — nothing to capture"
fi

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
echo "desktop-shot: status=$status serial=$SERIAL shot=$SHOT"
ls -l "$SHOT" 2>/dev/null || echo "desktop-shot: no screendump produced"
