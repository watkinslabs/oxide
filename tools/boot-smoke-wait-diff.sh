#!/usr/bin/env bash
# Interruptible-wait / restart-semantics differential: run the probe on
# this machine's Linux kernel (the ORACLE) and inside one oxide boot, then
# require the record streams to be identical.
#
# No sudo by default. Set WAIT_DIFF_SYSLOG=1 to add the syslog(2) case,
# which needs CAP_SYSLOG and CONSUMES this machine's kernel ring buffer on
# the host side — opt in deliberately.
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
PROBE_DIR="$ROOT/userspace/wait_diff"
PROBE="$PROBE_DIR/wait_diff"
SYSLOG="${WAIT_DIFF_SYSLOG:-0}"
RUN_ROOT="${WAIT_DIFF_LOG_DIR:-$ROOT/target/smoke/wait-diff}"
mkdir -p "$RUN_ROOT"
RUN_DIR="$(mktemp -d "$RUN_ROOT/${ARCH}-$(date +%Y%m%d-%H%M%S)-XXXXXX")"
HOST_BUILD_LOG="$RUN_DIR/linux-build.log"
HOST_LOG="$RUN_DIR/linux.log"
BOOT_LOG="$RUN_DIR/boot.log"
UART_LOG="$RUN_DIR/oxide-uart.log"
LINUX_RECORDS="$RUN_DIR/linux.records"
OXIDE_RECORDS="$RUN_DIR/oxide.records"
DIFF_LOG="$RUN_DIR/linux-vs-oxide.diff"
PIDFILE="$(mktemp "/tmp/oxide-wait-diff-${ARCH}-XXXXXX.pid")"
UART="$(mktemp -u "/tmp/oxide-wait-diff-${ARCH}-XXXXXX.sock")"
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
    echo "wait-diff-smoke: FAIL - $*" >&2
    echo "wait-diff-smoke: logs=$RUN_DIR" >&2
    return 1
}

# Keep only the probe's own records: the guest stream is interleaved with
# klog and journald lines, and the `wdiff|` prefix is what separates them.
normalize_records() {
    LC_ALL=C sed $'s/\r$//; s/\033\\[[0-9;?]*[ -\/]*[@-~]//g' "$1" |
        LC_ALL=C grep '^wdiff|' > "$2" || true
}

echo "wait-diff-smoke: arch=$ARCH timeout=${TIMEOUT}s syslog=$SYSLOG logs=$RUN_DIR"

if ! make -B -C "$PROBE_DIR" all >"$HOST_BUILD_LOG" 2>&1; then
    tail -n 80 "$HOST_BUILD_LOG" >&2
    fail "Linux probe build failed"
fi
HOST_RUNNER=()
if [ "$SYSLOG" = "1" ]; then
    command -v sudo >/dev/null 2>&1 || fail "WAIT_DIFF_SYSLOG=1 needs sudo"
    sudo -n true >/dev/null 2>&1 || fail "WAIT_DIFF_SYSLOG=1 needs sudo -n authorization"
    HOST_RUNNER=(sudo -n WAIT_DIFF_SYSLOG=1 --)
fi
if ! "${HOST_RUNNER[@]}" "$PROBE" >"$HOST_LOG" 2>&1; then
    tail -n 80 "$HOST_LOG" >&2
    fail "Linux probe exited nonzero"
fi
normalize_records "$HOST_LOG" "$LINUX_RECORDS"
if ! grep -qx 'wdiff|meta|complete|status=DONE' "$LINUX_RECORDS"; then
    tail -n 80 "$HOST_LOG" >&2
    fail "Linux probe did not complete"
fi

WAIT_DIFF_SYSLOG_ENV=""
[ "$SYSLOG" = "1" ] && WAIT_DIFF_SYSLOG_ENV="OXIDE_WAIT_DIFF_SYSLOG=1"
env OXIDE_WAIT_DIFF_SMOKE=1 $WAIT_DIFF_SYSLOG_ENV OXIDE_QEMU_HEADLESS=1 \
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
    if grep -aqE 'Kernel panic|kernel panic|\[FAULT\]|\[BADSTACK\]|\[BUG\]|not syncing|Entering emergency mode' "$UART_LOG" 2>/dev/null; then
        tail -n 100 "$UART_LOG" >&2
        fail "Oxide boot reported a fatal error"
    fi
    grep -aq 'wdiff|meta|complete|status=DONE' "$UART_LOG" 2>/dev/null && probe_done=1
    [ "$probe_done" -eq 1 ] && break
    sleep 2
done
[ "$probe_done" -eq 1 ] || fail "timeout waiting for Oxide probe completion"

normalize_records "$UART_LOG" "$OXIDE_RECORDS"
if ! grep -qx 'wdiff|meta|complete|status=DONE' "$OXIDE_RECORDS"; then
    fail "normalized Oxide probe output is incomplete"
fi
if ! diff -u "$LINUX_RECORDS" "$OXIDE_RECORDS" >"$DIFF_LOG"; then
    cat "$DIFF_LOG" >&2
    fail "Linux and Oxide interruptible-wait records differ"
fi

echo "wait-diff-smoke: PASS - $ARCH exact Linux differential"
echo "wait-diff-smoke: logs=$RUN_DIR"
