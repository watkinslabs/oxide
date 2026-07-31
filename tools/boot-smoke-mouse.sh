#!/usr/bin/env bash
# Input delivery gate. Boots headless with the injected `oxide-input-delivery`
# oneshot, which resolves the pointer and keyboard evdev nodes through udev,
# opens both, and announces `input_delivery: READY`. This script then injects
# REAL host events over QMP (relative motion, a left click, key presses), and
# the probe fails unless it read EV_REL + EV_KEY + EV_SYN records off the
# pointer node and EV_KEY off the keyboard node. No login is involved: the
# verdict is the service's own console output, so the gate fails whenever
# event delivery regresses.
#
# Usage: tools/boot-smoke-mouse.sh x86|arm [timeout]
set -uo pipefail

ARCH="${1:-x86}"; TIMEOUT="${2:-${SMOKE_TIMEOUT:-900}}"
case "$ARCH" in x86) MT=qemu-x86 ;; arm) MT=qemu-arm ;; *) echo "arch x86|arm"; exit 2 ;; esac

LOG="$(mktemp /tmp/oxide-mouse-${ARCH}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-mouse-${ARCH}-XXXXXX.pid)"
QMP="$(mktemp -u /tmp/oxide-mouse-${ARCH}-qmp-XXXXXX.sock)"
UART="$(mktemp -u /tmp/oxide-mouse-${ARCH}-uart-XXXXXX.sock)"
UART_BRIDGE_PID=""

cleanup() {
    if [ -s "$PIDFILE" ]; then
        local pid; pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && { kill -TERM "-$pid" 2>/dev/null; sleep 1; kill -KILL "-$pid" 2>/dev/null; }
    fi
    [ -n "$UART_BRIDGE_PID" ] && kill "$UART_BRIDGE_PID" 2>/dev/null || true
    [ -n "${KEEP_LOG:-}" ] && cp -f "$LOG" "$KEEP_LOG" 2>/dev/null || true
    rm -f "$LOG" "$PIDFILE" "$QMP" "$UART"
}
trap cleanup EXIT

# shellcheck source=tools/input-smoke-lib.sh
. "$(dirname "$0")/input-smoke-lib.sh"

echo "mouse-smoke: arch=$ARCH timeout=${TIMEOUT}s qmp=$QMP uart=$UART log=$LOG"
OXIDE_INPUT_DELIVERY_SMOKE=1 OXIDE_QEMU_HEADLESS=1 OXIDE_QEMU_QMP_SOCK="$QMP" \
    OXIDE_QEMU_UART_SOCK="$UART" OXIDE_QEMU_KVM="${OXIDE_QEMU_KVM:-1}" \
    setsid bash -c "exec make '$MT' > '$LOG' 2>&1 < /dev/null" &
echo $! > "$PIDFILE"

input_smoke_bridge_uart "$UART" "$LOG" "$PIDFILE" "mouse-smoke"
deadline=$(( $(date +%s) + TIMEOUT ))
input_smoke_wait_ready "first" "$LOG" "$PIDFILE" "$deadline" "mouse-smoke"
input_smoke_inject "$QMP"
input_smoke_verdict "$LOG" "$deadline" "mouse-smoke"
