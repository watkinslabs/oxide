#!/usr/bin/env bash
# HD-Audio acceptance. Boots once, then asks the guest's debug shell whether
# the second sound card exists: drv-hda publishes its nodes only after the
# controller came out of reset, a codec answered, the generic parser found a
# playable route and the ALSA card registered, so the nodes are proof of the
# whole chain. One command at a time, each followed by `echo ===DONE_<tag>===`
# so a hang names the step that wedged.
#
# The raw qemu serial log is left at /tmp/oxide-hda-smoke-<arch>-*.log
# for post-run inspection.
#
# Usage:
#   tools/boot-smoke-hda.sh x86 [timeout_seconds]   # default 600
#   tools/boot-smoke-hda.sh arm [timeout_seconds]
set -uo pipefail

# This harness drives the guest through systemd's root debug shell over the
# serial FIFO: it types a command and waits for the output. The boot line's
# default puts that shell on a VT and a LOGIN on the serial line, which would
# swallow every command as a username, so ask for the serial control plane —
# the boot-line builder moves the shell and masks the login together.
export OXIDE_SERIAL_SHELL="${OXIDE_SERIAL_SHELL:-1}"

usage() {
    cat >&2 <<EOF
usage: $0 <x86|arm> [timeout_seconds]
EOF
    exit 2
}

ARCH="${1:-}"
case "$ARCH" in
    x86) MAKE_TARGET=qemu-x86 ;;
    arm) MAKE_TARGET=qemu-arm ;;
    *)   usage ;;
esac

# Vendor preflight: a fresh worktree has no `vendor/`, and an ARM guest then
# fails before QEMU starts with a message that reads like a kernel fault.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tools/vendor-preflight.sh"
vendor_preflight || exit 2
TIMEOUT="${2:-${SMOKE_TIMEOUT:-600}}"

LOG="$(mktemp /tmp/oxide-hda-smoke-${ARCH}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-hda-smoke-${ARCH}-XXXXXX.pid)"
QIN="$(mktemp -u /tmp/oxide-hda-smoke-${ARCH}-qin-XXXXXX)"
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
    # $LOG is preserved for inspection
}
trap cleanup EXIT

echo "boot-smoke-hda: arch=$ARCH timeout=${TIMEOUT}s log=$LOG"

exec 9<>"$QIN"

OXIDE_QEMU_HEADLESS=1 setsid bash -c "exec make '$MAKE_TARGET' > '$LOG' 2>&1 < '$QIN'" &
echo $! > "$PIDFILE"

deadline=$(( $(date +%s) + TIMEOUT ))

wait_for() {
    local pat="$1" label="$2"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local pid
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "boot-smoke-hda: FAIL — qemu exited before $label" >&2
            tail -n 80 "$LOG" >&2
            exit 1
        fi
        if grep -aq "$pat" "$LOG" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    echo "boot-smoke-hda: FAIL — timeout waiting for $label" >&2
    tail -n 120 "$LOG" >&2
    exit 1
}

# Each step is one shell command + own DONE marker. PASS = every
# marker observed in order. FAIL = a step's marker never arrives →
# that path wedges.
TAGS=()
wait_for_step() {
    local pat="$1" label="$2"
    local retry_deadline=$(( $(date +%s) + 20 ))
    while [ "$(date +%s)" -lt "$deadline" ] && [ "$(date +%s)" -lt "$retry_deadline" ]; do
        local pid
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "boot-smoke-hda: FAIL — qemu exited before $label" >&2
            tail -n 80 "$LOG" >&2
            exit 1
        fi
        grep -aq "$pat" "$LOG" 2>/dev/null && return 0
        sleep 1
    done
    return 1
}

step() {
    local tag="$1" cmd="$2"
    TAGS+=("$tag")
    local attempt
    for attempt in 1 2 3; do
        send_slowly "$cmd; echo ===DONE_${tag}==="
        wait_for_step "===DONE_${tag}===" "$tag" && return 0
    done
    echo "boot-smoke-hda: FAIL — timeout waiting for $tag after 3 sends" >&2
    tail -n 120 "$LOG" >&2
    exit 1
}

# The production image boots a graphical session and has no serial getty.
# Its command line deliberately starts systemd's root debug shell on the
# serial tty, the canonical in-guest control plane for smoke probes.
wait_for "Started debug-shell.service" "debug shell"
sleep 1

# The UART shares the line with early boot output and can drop long bursts.
# Type commands in small chunks so the shell receives every probe intact.
send_slowly() {
    local text="$1" i=0
    while [ "$i" -lt "${#text}" ]; do
        printf '%s' "${text:$i:8}" >&9
        i=$(( i + 8 ))
        sleep 0.3
    done
    printf '\n' >&9
}

# The HD-Audio controller QEMU attaches is a second sound card: virtio-snd
# takes card 0, drv-hda takes card 1. Its nodes appear only after the codec
# enumerated, the generic parser found a route, and the card registered — a
# probe that fails at any of those steps publishes nothing.
step snd_ls           'ls /dev/snd'
step snd_control1     'test -c /dev/snd/controlC1 && echo hda-control-node-present'
step snd_pcm1_play    'test -c /dev/snd/pcmC1D0p && echo hda-playback-node-present'
step snd_pcm1_cap     'test -c /dev/snd/pcmC1D0c && echo hda-capture-node-present'
step snd_class        'ls /sys/class/sound 2>&1'
step snd_open         'exec 7</dev/snd/controlC1 && echo hda-control-open-ok && exec 7<&-'

step sweep_done       'echo hda-card-present'

elapsed=$(( $(date +%s) - (deadline - TIMEOUT) ))
for marker in hda-control-node-present hda-playback-node-present hda-capture-node-present hda-control-open-ok; do
    grep -aq "$marker" "$LOG" || {
        echo "boot-smoke-hda: FAIL — $ARCH guest never printed $marker" >&2
        grep -a -A4 "===DONE_snd_ls===" "$LOG" | head -20 >&2
        exit 1
    }
done
echo "boot-smoke-hda: PASS — $ARCH HD-Audio card enumerated (${#TAGS[@]} steps) in ${elapsed}s"
exit 0
