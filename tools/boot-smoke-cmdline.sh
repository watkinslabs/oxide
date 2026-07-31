#!/usr/bin/env bash
# Boot-cmdline propagation gate (B1589). Asserts the command line the
# BOOTLOADER passed reaches the kernel and /proc/cmdline — on both arches.
#
# Why a gate: the bootloader hands the command line over a different transport
# per arch (x86_64 = the multiboot2 boot-command-line tag; aarch64 = UCS-2
# LoadOptions on the EFI loaded-image protocol, because the firmware behind
# GRUB publishes no device tree and therefore has no /chosen/bootargs). A
# transport that silently drops the line makes EVERY kernel parameter a no-op
# on that arch while the boot still looks completely healthy — which is how
# the aarch64 side went unnoticed. Nothing short of checking the line's
# contents catches it.
#
# Four independent checks, each covering a different link of the chain:
#   1. the kernel's own "Kernel command line:" echo  — bootloader -> kernel
#   2. `console=` names this arch's serial UART      -> the kernel honored it
#   3. `systemd.mask=` was obeyed                    -> /proc/cmdline -> pid 1
#   4. /proc/cmdline read in the guest               -> procfs serves the line
# Check 3 is the load-bearing one: systemd's ONLY source for `systemd.mask=`
# is /proc/cmdline, so a masked unit staying down proves the whole chain
# end-to-end. Check 4 reads the file itself, through the root shell that
# `systemd.debug_shell=` on the same line puts on the serial console.
#
# Usage:
#   tools/boot-smoke-cmdline.sh x86 [timeout_seconds]
#   tools/boot-smoke-cmdline.sh arm [timeout_seconds]
set -uo pipefail

usage() { echo "usage: $0 <x86|arm> [timeout_seconds]" >&2; exit 2; }

ARCH="${1:-}"
case "$ARCH" in
    x86) MAKE_TARGET=qemu-x86;  SERIAL=ttyS0   ;;
    arm) MAKE_TARGET=qemu-arm;  SERIAL=ttyAMA0 ;;
    *)   usage ;;
esac
TIMEOUT="${2:-${SMOKE_TIMEOUT:-900}}"

# Marker parameter the image pipeline puts on the bootloader command line
# (tools/xtask/src/image_qemu/bootargs.rs). The kernel's built-in arch default
# does not contain it, so its presence cannot come from the fallback.
MARKER="oxide.bootargs=grub"
# A unit the bootloader line masks. It exists and is wanted by the image's
# boot target, so it starts iff the mask did not arrive.
MASKED_UNIT="firewalld.service"
# systemd reaching this means pid 1 has parsed /proc/cmdline and built its
# initial transaction — the point at which the mask has had its effect.
BOOT_MARKER="Reached target basic.target"
FAIL_MARKER='\[FAULT\]|\[BADSTACK\]|\[BUG\]'

LOG="$(mktemp /tmp/oxide-cmdline-smoke-${ARCH}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-cmdline-smoke-${ARCH}-XXXXXX.pid)"
QIN="$(mktemp -u /tmp/oxide-cmdline-smoke-${ARCH}-qin-XXXXXX)"
mkfifo "$QIN"
cleanup() {
    if [ -s "$PIDFILE" ]; then
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "-$pid" 2>/dev/null || true
            sleep 1
            kill -KILL "-$pid" 2>/dev/null || true
        fi
    fi
    [ -n "${KEEP_LOG:-}" ] && cp -f "$LOG" "$KEEP_LOG" 2>/dev/null || true
    rm -f "$PIDFILE" "$QIN"
    [ -z "${KEEP_LOG:-}" ] && rm -f "$LOG"
    return 0
}
trap cleanup EXIT

echo "boot-smoke-cmdline: arch=$ARCH timeout=${TIMEOUT}s log=$LOG"

# Hold the FIFO open writable for the whole run so qemu never sees EOF.
exec 9<>"$QIN"
OXIDE_QEMU_HEADLESS=1 setsid bash -c "exec make '$MAKE_TARGET' > '$LOG' 2>&1 < '$QIN'" &
echo $! > "$PIDFILE"

fail() {
    echo "boot-smoke-cmdline: FAIL — $1" >&2
    echo "--- kernel command line echo (if any) ---" >&2
    grep -a 'Kernel command line:' "$LOG" >&2 || echo "  (kernel printed none)" >&2
    echo "--- last 40 log lines ---" >&2
    tail -n 40 "$LOG" >&2
    exit 1
}

deadline=$(( $(date +%s) + TIMEOUT ))
wait_for() {
    local pat="$1" label="$2"
    while :; do
        [ "$(date +%s)" -ge "$deadline" ] && fail "timeout waiting for $label"
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            fail "qemu exited before $label"
        fi
        grep -aqE "$FAIL_MARKER" "$LOG" 2>/dev/null && fail "kernel fault during boot"
        grep -aq "$pat" "$LOG" 2>/dev/null && return 0
        sleep 2
    done
}
wait_for "$BOOT_MARKER" "'$BOOT_MARKER'"

# 1. Bootloader -> kernel: the kernel echoed a line carrying the marker.
grep -aq "Kernel command line:.*$MARKER" "$LOG" \
    || fail "kernel did not receive the bootloader line (marker '$MARKER' absent from its echo)"

# 2. Kernel honored `console=`: the arch's serial UART is on the line.
grep -aq "Kernel command line:.*console=$SERIAL,115200" "$LOG" \
    || fail "bootloader console=$SERIAL,115200 missing from the kernel's line"

# 3. /proc/cmdline -> pid 1: a unit the line masks must never have started.
#    systemd has no other source for `systemd.mask=`, so this is end-to-end.
if grep -aq "Starting $MASKED_UNIT" "$LOG"; then
    fail "$MASKED_UNIT started — systemd.mask= from the bootloader line did not reach /proc/cmdline"
fi

# 4. procfs serves the line: read the file in the guest. The root shell comes
#    from `systemd.debug_shell=` on the very line under test, so reaching it
#    is itself a use of the line.
wait_for "Started debug-shell.service" "the debug shell (systemd.debug_shell=)"
sleep 3
printf '\n' >&9
sleep 1
# The wrapper prefix cannot collide with the kernel's own echo of the line.
printf 'echo PROCCMDLINE=$(cat /proc/cmdline)\n' >&9
wait_for "PROCCMDLINE=.*$MARKER" "marker '$MARKER' in the guest's /proc/cmdline"

echo "boot-smoke-cmdline: kernel line: $(grep -a 'Kernel command line:' "$LOG" | tail -n 1)"
echo "boot-smoke-cmdline: guest /proc/cmdline: $(grep -a 'PROCCMDLINE=' "$LOG" | grep -av 'echo PROCCMDLINE' | tail -n 1)"
elapsed=$(( $(date +%s) - (deadline - TIMEOUT) ))
echo "boot-smoke-cmdline: PASS — $ARCH bootloader cmdline reached the kernel and /proc/cmdline in ${elapsed}s"
exit 0
