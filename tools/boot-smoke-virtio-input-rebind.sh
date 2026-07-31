#!/usr/bin/env bash
# virtio-input live rebind gate. Same injected probe as the mouse gate, in
# rebind mode: it proves event delivery once, unbinds and rebinds every
# virtio-input child through sysfs, re-resolves the evdev nodes, and proves
# delivery again. Both phases are driven by real QMP input injection, so the
# gate fails if a rebound device stops delivering events.
#
# Usage: tools/boot-smoke-virtio-input-rebind.sh x86|arm [timeout]
set -uo pipefail

usage() {
    echo "usage: $0 <x86|arm> [timeout_seconds]" >&2
    exit 2
}

ARCH="${1:-}"
TIMEOUT="${2:-${SMOKE_TIMEOUT:-900}}"
case "$ARCH" in
    x86) MT=qemu-x86 ;;
    arm) MT=qemu-arm ;;
    *) usage ;;
esac

LOG="$(mktemp /tmp/oxide-virtio-input-rebind-${ARCH}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-virtio-input-rebind-${ARCH}-XXXXXX.pid)"
QMP="$(mktemp -u /tmp/oxide-virtio-input-rebind-${ARCH}-qmp-XXXXXX.sock)"
UART="$(mktemp -u /tmp/oxide-virtio-input-rebind-${ARCH}-uart-XXXXXX.sock)"
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

# shellcheck source=tools/input-smoke-lib.sh
. "$(dirname "$0")/input-smoke-lib.sh"

LABEL="virtio-input-rebind-smoke"
echo "$LABEL: arch=$ARCH timeout=${TIMEOUT}s qmp=$QMP uart=$UART log=$LOG"
OXIDE_VIRTIO_INPUT_REBIND_SMOKE=1 OXIDE_QEMU_HEADLESS=1 OXIDE_QEMU_QMP_SOCK="$QMP" \
    OXIDE_QEMU_UART_SOCK="$UART" OXIDE_QEMU_KVM="${OXIDE_QEMU_KVM:-1}" \
    setsid bash -c "exec make '$MT' > '$LOG' 2>&1 < /dev/null" &
echo $! > "$PIDFILE"

input_smoke_bridge_uart "$UART" "$LOG" "$PIDFILE" "$LABEL"
deadline=$(( $(date +%s) + TIMEOUT ))
input_smoke_wait_ready "first" "$LOG" "$PIDFILE" "$deadline" "$LABEL"
input_smoke_inject "$QMP"
input_smoke_wait_ready "rebound" "$LOG" "$PIDFILE" "$deadline" "$LABEL"
input_smoke_inject "$QMP"
input_smoke_verdict "$LOG" "$deadline" "$LABEL"
