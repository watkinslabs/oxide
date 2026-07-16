#!/usr/bin/env bash
# Run the AF_PACKET probe on Linux and compare it byte-for-byte with one Oxide boot.
set -euo pipefail

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
case "$TIMEOUT" in
    ''|*[!0-9]*) usage ;;
esac
[ "$TIMEOUT" -gt 0 ] || usage

ROOT="$(git rev-parse --show-toplevel)"
PROBE_DIR="$ROOT/userspace/af_packet_diff"
PROBE="$PROBE_DIR/af_packet_diff"
RUN_ROOT="${AF_PACKET_DIFF_LOG_DIR:-$ROOT/target/smoke/af-packet-diff}"
mkdir -p "$RUN_ROOT"
RUN_DIR="$(mktemp -d "$RUN_ROOT/${ARCH}-$(date +%Y%m%d-%H%M%S)-XXXXXX")"
HOST_BUILD_LOG="$RUN_DIR/linux-build.log"
HOST_LOG="$RUN_DIR/linux.log"
BOOT_LOG="$RUN_DIR/boot.log"
UART_LOG="$RUN_DIR/oxide-uart.log"
LINUX_RECORDS="$RUN_DIR/linux.records"
OXIDE_RECORDS="$RUN_DIR/oxide.records"
DIFF_LOG="$RUN_DIR/linux-vs-oxide.diff"
PIDFILE="$(mktemp "/tmp/oxide-af-packet-${ARCH}-XXXXXX.pid")"
UART="$(mktemp -u "/tmp/oxide-af-packet-${ARCH}-XXXXXX.sock")"
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
    if [ -n "$UART_BRIDGE_PID" ] && kill -0 "$UART_BRIDGE_PID" 2>/dev/null; then
        kill "$UART_BRIDGE_PID" 2>/dev/null || true
    fi
    rm -f "$UART" "$PIDFILE"
}
trap cleanup EXIT

fail() {
    echo "af-packet-diff-smoke: FAIL - $*" >&2
    echo "af-packet-diff-smoke: logs=$RUN_DIR" >&2
    return 1
}

normalize_records() {
    local input="$1" output="$2"
    LC_ALL=C sed $'s/\r$//; s/\033\\[[0-9;?]*[ -\/]*[@-~]//g' "$input" |
        LC_ALL=C awk -F '|' '
            /^[[:alnum:]_]+\|[[:alnum:]_]+\|/ && NF >= 3 { print }
        ' > "$output"
}

echo "af-packet-diff-smoke: arch=$ARCH timeout=${TIMEOUT}s logs=$RUN_DIR"
command -v sudo >/dev/null 2>&1 || fail "sudo is unavailable"
sudo -n true >/dev/null 2>&1 || fail "sudo -n authorization is required for the Linux probe"

if ! make -B -C "$PROBE_DIR" all >"$HOST_BUILD_LOG" 2>&1; then
    tail -n 80 "$HOST_BUILD_LOG" >&2
    fail "Linux probe build failed"
fi
if ! sudo -n -- "$PROBE" >"$HOST_LOG" 2>&1; then
    tail -n 80 "$HOST_LOG" >&2
    fail "Linux probe exited nonzero"
fi
normalize_records "$HOST_LOG" "$LINUX_RECORDS"
if ! grep -qx 'meta|complete|status=DONE' "$LINUX_RECORDS"; then
    tail -n 80 "$HOST_LOG" >&2
    fail "Linux probe did not complete"
fi

OXIDE_AF_PACKET_DIFF_SMOKE=1 OXIDE_QEMU_HEADLESS=1 \
    OXIDE_QEMU_UART_SOCK="$UART" OXIDE_QEMU_KVM="${OXIDE_QEMU_KVM:-1}" \
    setsid bash -c "exec make '$MT' > '$BOOT_LOG' 2>&1 < /dev/null" &
echo $! > "$PIDFILE"

for _ in $(seq 1 600); do
    [ -S "$UART" ] && break
    pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
        tail -n 80 "$BOOT_LOG" >&2
        fail "boot exited before UART became available"
    fi
    sleep 0.1
done
[ -S "$UART" ] || fail "UART socket did not become available"

python3 - "$UART" "$UART_LOG" <<'PY' 2>>"$BOOT_LOG" &
import socket
import sys

uart, log_path = sys.argv[1:3]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(uart)
with open(log_path, "ab", buffering=0) as log:
    while True:
        data = sock.recv(4096)
        if not data:
            break
        log.write(data)
PY
UART_BRIDGE_PID=$!

deadline=$(( $(date +%s) + TIMEOUT ))
probe_done=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
        tail -n 80 "$BOOT_LOG" >&2
        tail -n 80 "$UART_LOG" >&2
        fail "boot exited before verdict"
    fi
    if ! kill -0 "$UART_BRIDGE_PID" 2>/dev/null; then
        tail -n 80 "$BOOT_LOG" >&2
        fail "UART capture stopped before verdict"
    fi
    if grep -aiqE 'af-packet-diff-smoke\.service.*(fail|error)|Failed to (start|run).*af.packet.diff|meta\|complete\|status=UNSUPPORTED' "$UART_LOG" 2>/dev/null; then
        grep -aE 'af-packet-diff|AF_PACKET|meta\|complete' "$UART_LOG" >&2 || true
        fail "Oxide service or probe reported failure"
    fi
    if grep -aqE 'Kernel panic|kernel panic|PANIC|BUG:|not syncing|Entering emergency mode|Failed to mount|MESSAGE=Freezing execution' "$UART_LOG" 2>/dev/null; then
        tail -n 100 "$UART_LOG" >&2
        fail "Oxide boot reported a fatal error"
    fi
    grep -aq 'meta|complete|status=DONE' "$UART_LOG" 2>/dev/null && probe_done=1
    if [ "$probe_done" -eq 1 ]; then
        break
    fi
    sleep 2
done
[ "$probe_done" -eq 1 ] || fail "timeout waiting for Oxide probe completion"

normalize_records "$UART_LOG" "$OXIDE_RECORDS"
if ! grep -qx 'meta|complete|status=DONE' "$OXIDE_RECORDS"; then
    fail "normalized Oxide probe output is incomplete"
fi
if ! diff -u "$LINUX_RECORDS" "$OXIDE_RECORDS" >"$DIFF_LOG"; then
    cat "$DIFF_LOG" >&2
    fail "Linux and Oxide probe records differ"
fi

echo "af-packet-diff-smoke: PASS - $ARCH exact Linux differential"
echo "af-packet-diff-smoke: logs=$RUN_DIR"
