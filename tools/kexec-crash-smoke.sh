#!/usr/bin/env bash
# Boot a guest with a reserved crash region, stage a crash kernel into it,
# panic the machine, and watch for a SECOND kernel coming up out of that
# reservation.
#
# This is the one kexec question a hosted test cannot reach. Every step up to
# the jump is decided in an ungated module and covered by unit tests, but the
# jump does not return: whether the staged image actually runs can only be
# answered by the new kernel's own console output, and reaching the crash slot
# specifically requires a real panic rather than `kexec -e`.
#
# Usage: kexec-crash-smoke.sh <x86|arm> [timeout_seconds]
set -euo pipefail

usage() { echo "usage: $0 <x86|arm> [timeout_seconds]" >&2; exit 2; }

ARCH="${1:-}"
TIMEOUT="${2:-${SMOKE_TIMEOUT:-900}}"
case "$ARCH" in
    x86) MT=qemu-x86 ;;
    arm) MT=qemu-arm ;;
    *) usage ;;
esac
case "$TIMEOUT" in ''|*[!0-9]*) usage ;; esac

ROOT="$(git rev-parse --show-toplevel)"
. "$ROOT/tools/vendor-preflight.sh"
vendor_preflight || exit 2

# Bytes to reserve. Large enough for a distribution kernel plus its initramfs
# plus the purgatory; the placement rounds it to the region alignment.
CRASH_SIZE="${OXIDE_CRASHKERNEL:-512M}"

RUN_ROOT="${KEXEC_CRASH_LOG_DIR:-$ROOT/target/smoke/kexec-crash}"
mkdir -p "$RUN_ROOT"
RUN_DIR="$(mktemp -d "$RUN_ROOT/${ARCH}-XXXXXX")"
BOOT_LOG="$RUN_DIR/boot.log"
UART_LOG="$RUN_DIR/uart.log"
PIDFILE="$(mktemp "/tmp/oxide-kexec-crash-${ARCH}-XXXXXX.pid")"
UART="$(mktemp -u "/tmp/oxide-kexec-crash-${ARCH}-XXXXXX.sock")"

cleanup() {
    if [ -s "$PIDFILE" ]; then
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "-$pid" 2>/dev/null || true
            sleep 1
            kill -KILL "-$pid" 2>/dev/null || true
        fi
    fi
    rm -f "$UART" "$PIDFILE"
}
trap cleanup EXIT

echo "kexec-crash-smoke: arch=$ARCH crashkernel=$CRASH_SIZE logs=$RUN_DIR"

# The image has to carry the loader and a SECOND kernel to relocate into, and
# only one composed profile does. Booting the default profile gets `kexec:
# command not found` and an empty `/lib/modules`, which reads like the syscall
# refusing when nothing was ever asked of it.
OXIDE_QUICKBOOT_PROFILE="${OXIDE_QUICKBOOT_PROFILE:-lite}" \
OXIDE_CMDLINE_EXTRA="crashkernel=$CRASH_SIZE ${OXIDE_CMDLINE_EXTRA:-}" \
OXIDE_QEMU_HEADLESS=1 OXIDE_QEMU_UART_SOCK="$UART" \
OXIDE_QEMU_KVM="${OXIDE_QEMU_KVM:-1}" \
    setsid bash -c "exec make SMP='${OXIDE_SMP:-2}' '$MT' > '$BOOT_LOG' 2>&1 < /dev/null" &
echo $! > "$PIDFILE"

for _ in $(seq 1 $((TIMEOUT * 10))); do
    [ -S "$UART" ] && break
    pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
        tail -n 60 "$BOOT_LOG" >&2
        echo "kexec-crash-smoke: FAIL - boot exited before the UART appeared" >&2
        exit 1
    fi
    sleep 0.1
done
[ -S "$UART" ] || { echo "kexec-crash-smoke: FAIL - no UART socket" >&2; exit 1; }

rc=0
python3 "$ROOT/tools/kexec-smoke.py" "$UART" --crash --timeout "$TIMEOUT" --log "$UART_LOG" || rc=$?
if [ "$rc" -eq 0 ]; then
    echo "kexec-crash-smoke: PASS - $ARCH reached a crash kernel"
else
    echo "kexec-crash-smoke: FAIL - $ARCH rc=$rc" >&2
fi
echo "kexec-crash-smoke: log=$UART_LOG"
exit "$rc"
