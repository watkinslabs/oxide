#!/usr/bin/env bash
# V4L2 acceptance. Boots once, then asks the guest's debug shell whether the
# virtual camera exists and whether a frame can actually be captured through
# it. Node presence proves publication and nothing else, so the probe drives
# the whole path an application drives — QUERYCAP, G_FMT, REQBUFS, mmap, QBUF,
# STREAMON, DQBUF — and asserts the mapped page is not still zero.
#
# One command at a time, each followed by `echo ===DONE_<tag>===`, so a hang
# names the step that wedged.
#
# The raw qemu serial log is left at /tmp/oxide-v4l2-smoke-<arch>-*.log
# for post-run inspection.
#
# Usage:
#   tools/boot-smoke-v4l2.sh x86 [timeout_seconds]   # default 600
#   tools/boot-smoke-v4l2.sh arm [timeout_seconds]
set -uo pipefail

# The production image boots a graphical session with no serial getty; its
# command line puts systemd's root debug shell on the serial tty instead,
# which is the canonical in-guest control plane for a smoke probe.
export OXIDE_SERIAL_SHELL="${OXIDE_SERIAL_SHELL:-1}"

usage() { echo "usage: $0 <x86|arm> [timeout_seconds]" >&2; exit 2; }

ARCH="${1:-}"
case "$ARCH" in
    x86) MAKE_TARGET=qemu-x86 ;;
    arm) MAKE_TARGET=qemu-arm ;;
    *)   usage ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROOT/tools/vendor-preflight.sh"
vendor_preflight || exit 2
TIMEOUT="${2:-${SMOKE_TIMEOUT:-600}}"
# Two CPUs, as every other boot gate uses. A uniprocessor guest hits the
# recorded early-userspace spinlock wedge on roughly half its boots, which
# would report this subsystem as broken on a fault that has nothing to do
# with it. Override with OXIDE_SMP=1 to reproduce that wedge deliberately.
OXIDE_SMP="${OXIDE_SMP:-2}"
PROBE="$ROOT/tools/v4l2-capture-probe.py"
[ -r "$PROBE" ] || { echo "boot-smoke-v4l2: missing $PROBE" >&2; exit 2; }

LOG="$(mktemp /tmp/oxide-v4l2-smoke-${ARCH}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-v4l2-smoke-${ARCH}-XXXXXX.pid)"
QIN="$(mktemp -u /tmp/oxide-v4l2-smoke-${ARCH}-qin-XXXXXX)"
mkfifo "$QIN"
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
    rm -f "$PIDFILE" "$QIN"
}
trap cleanup EXIT

echo "boot-smoke-v4l2: arch=$ARCH timeout=${TIMEOUT}s log=$LOG"
exec 9<>"$QIN"
OXIDE_QEMU_HEADLESS=1 setsid bash -c "exec make SMP='$OXIDE_SMP' '$MAKE_TARGET' > '$LOG' 2>&1 < '$QIN'" &
echo $! > "$PIDFILE"

deadline=$(( $(date +%s) + TIMEOUT ))

guest_alive() {
    local pid
    pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    [ -z "$pid" ] && return 0
    kill -0 "$pid" 2>/dev/null
}

wait_for() {
    local pat="$1" label="$2"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        guest_alive || { echo "boot-smoke-v4l2: FAIL — qemu exited before $label" >&2
                         tail -n 80 "$LOG" >&2; exit 1; }
        grep -aq "$pat" "$LOG" 2>/dev/null && return 0
        sleep 1
    done
    echo "boot-smoke-v4l2: FAIL — timeout waiting for $label" >&2
    tail -n 120 "$LOG" >&2
    exit 1
}

wait_for "Started debug-shell.service" "debug shell"
sleep 1

# The UART shares the line with kernel output and drops long bursts, so every
# command goes in small chunks.
send_slowly() {
    local text="$1" i=0
    while [ "$i" -lt "${#text}" ]; do
        printf '%s' "${text:$i:8}" >&9
        i=$(( i + 8 ))
        sleep 0.25
    done
    printf '\n' >&9
}

wait_for_step() {
    local pat="$1"
    local retry_deadline=$(( $(date +%s) + 25 ))
    while [ "$(date +%s)" -lt "$deadline" ] && [ "$(date +%s)" -lt "$retry_deadline" ]; do
        guest_alive || { echo "boot-smoke-v4l2: FAIL — qemu exited mid-probe" >&2
                         tail -n 80 "$LOG" >&2; exit 1; }
        grep -aq "$pat" "$LOG" 2>/dev/null && return 0
        sleep 1
    done
    return 1
}

TAGS=()
step() {
    local tag="$1" cmd="$2" attempt
    TAGS+=("$tag")
    for attempt in 1 2 3; do
        send_slowly "$cmd; echo ===DONE_${tag}==="
        wait_for_step "===DONE_${tag}===" && return 0
    done
    echo "boot-smoke-v4l2: FAIL — timeout waiting for $tag after 3 sends" >&2
    tail -n 140 "$LOG" >&2
    exit 1
}

# --- publication --------------------------------------------------------
step v4l_dev    'ls -l /dev/video0 2>&1'
step v4l_ischar 'test -c /dev/video0 && echo v4l2-node-present'
step v4l_major  'stat -c %t:%T /dev/video0 2>&1'
step v4l_class  'ls /sys/class/video4linux 2>&1'
step v4l_sysfs  'test -e /sys/class/video4linux/video0 && echo v4l2-class-entry-present'
step v4l_open   'exec 7</dev/video0 && echo v4l2-node-open-ok && exec 7<&-'

# --- one real capture ---------------------------------------------------
# The probe is typed in line by line; a heredoc keeps the shell from
# interpreting anything in it.
send_slowly "cat > /tmp/v4l2_probe.py <<'PYEOF'"
while IFS= read -r line; do send_slowly "$line"; done < "$PROBE"
step probe_written 'PYEOF'
step probe_size    'wc -l /tmp/v4l2_probe.py 2>&1'
step probe_run     'python3 /tmp/v4l2_probe.py 2>&1'

elapsed=$(( $(date +%s) - (deadline - TIMEOUT) ))
for marker in v4l2-node-present v4l2-class-entry-present v4l2-node-open-ok; do
    grep -aq "$marker" "$LOG" || {
        echo "boot-smoke-v4l2: FAIL — $ARCH guest never printed $marker" >&2
        grep -a -A6 "===DONE_v4l_dev===" "$LOG" | head -30 >&2
        exit 1
    }
done
if ! grep -aq "v4l2_probe: PASS" "$LOG"; then
    echo "boot-smoke-v4l2: FAIL — $ARCH guest published the node but captured no frame" >&2
    grep -aE "v4l2_probe:" "$LOG" >&2 || echo "(the probe printed nothing at all)" >&2
    exit 1
fi
grep -aE "v4l2_probe:" "$LOG"
echo "boot-smoke-v4l2: PASS — $ARCH captured through /dev/video0 (${#TAGS[@]} steps) in ${elapsed}s"
exit 0
