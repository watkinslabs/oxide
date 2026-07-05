#!/usr/bin/env bash
# Isolated boot + serial-capture driver. Unlike boot-smoke.sh /
# boot-capture.sh (which grep a shared-port qemu and reap ALL
# `qemu-system` by name — killing any OTHER concurrent qemu, e.g. a
# second dev/agent booting in a different worktree), this driver:
#
#   * Runs `make qemu-<arch>` FROM THE CURRENT TREE, so a git worktree
#     boots its OWN target/ artifacts (no main-tree collision).
#   * Gives qemu PRIVATE unix sockets for serial (OXIDE_QEMU_UART_SOCK)
#     and control (OXIDE_QEMU_QMP_SOCK) — no shared TCP port, so any
#     number of these run concurrently without "Could not set up host
#     forwarding".
#   * Shuts down by sending QMP `quit` to ITS OWN socket — never
#     `pkill -f qemu-system`, never touching another qemu. Works even
#     where the sandbox blocks kill(2).
#
# Usage:
#   tools/boot-iso.sh <x86|arm> [marker-regex] [timeout_s] [out.log] [features]
#
# Examples:
#   tools/boot-iso.sh x86 'oxide login:' 300 /tmp/b.log
#   tools/boot-iso.sh x86 'user@979' 240 /tmp/pam.log debug-syscall   # 1.1 capture
#
# Exit: 0 marker matched, 1 timeout, 2 arg/build error. Full serial is
# always left at out.log for inspection.
set -uo pipefail

ARCH="${1:-}"
MARKER="${2:-oxide login:}"
TIMEOUT="${3:-300}"
OUT="${4:-/tmp/oxide-boot-iso-${ARCH}.log}"
FEATURES="${5:-}"

case "$ARCH" in
    x86) TARGET=qemu-x86 ;;
    arm) TARGET=qemu-arm ;;
    *)   echo "usage: $0 <x86|arm> [marker] [timeout_s] [out.log] [features]" >&2; exit 2 ;;
esac

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

RUNDIR="$(mktemp -d /tmp/oxide-boot-iso-XXXXXX)"
UART_SOCK="$RUNDIR/uart.sock"
QMP_SOCK="$RUNDIR/qmp.sock"
: > "$OUT"

cleanup() {
    # Clean, targeted shutdown: tell OUR qemu to quit over ITS QMP
    # socket. No pkill, no kill — cannot affect any other qemu.
    python3 - "$QMP_SOCK" <<'PY' 2>/dev/null || true
import socket, sys, json, time
p = sys.argv[1]
try:
    s = socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect(p)
    s.recv(4096)                                   # QMP greeting
    s.sendall(b'{"execute":"qmp_capabilities"}\n'); s.recv(4096)
    s.sendall(b'{"execute":"quit"}\n'); time.sleep(0.3)
    s.close()
except Exception:
    pass
PY
    # Best-effort reap of our OWN process group only (never global).
    if [ -n "${MK_PGID:-}" ]; then kill -KILL "-$MK_PGID" 2>/dev/null || true; fi
    rm -rf "$RUNDIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Launch build+boot in its own session/process-group so a group signal
# (fallback only) never escapes to another qemu. Serial + QMP go to our
# private unix sockets; headless so the guest UART streams to the socket.
FEATENV=()
[ -n "$FEATURES" ] && FEATENV=("FEATURES=$FEATURES")
setsid env OXIDE_QEMU_HEADLESS=1 \
           OXIDE_QEMU_UART_SOCK="$UART_SOCK" \
           OXIDE_QEMU_QMP_SOCK="$QMP_SOCK" \
    bash -c "exec make '$TARGET' ${FEATENV[*]} >>'$OUT' 2>&1 < /dev/null" &
MK_PGID=$!

# Stream the guest serial (qemu is the socket server) into $OUT once the
# socket appears. Runs until the socket closes (qemu exit) or we're reaped.
( for _ in $(seq 1 "$TIMEOUT"); do [ -S "$UART_SOCK" ] && break; sleep 1; done
  python3 - "$UART_SOCK" "$OUT" <<'PY' 2>/dev/null || true
import socket, sys, time
sock, out = sys.argv[1], sys.argv[2]
for _ in range(30):
    try:
        s = socket.socket(socket.AF_UNIX); s.connect(sock); break
    except Exception: time.sleep(1)
else: sys.exit(0)
with open(out, "ab", buffering=0) as f:
    s.settimeout(2)
    while True:
        try:
            b = s.recv(65536)
            if not b: break
            f.write(b)
        except socket.timeout: continue
        except Exception: break
PY
) &

deadline=$(( $(date +%s) + TIMEOUT ))
status=timeout
while [ "$(date +%s)" -lt "$deadline" ]; do
    sleep 2
    if grep -qE "$MARKER" "$OUT" 2>/dev/null; then status=match; break; fi
    if grep -q "Could not set up host forwarding" "$OUT" 2>/dev/null; then status=portbusy; break; fi
    if grep -qiE "qemu-system.*not on PATH|command not found" "$OUT" 2>/dev/null; then status=noqemu; break; fi
done

echo "boot-iso: arch=$ARCH status=$status marker='$MARKER' log=$OUT lines=$(wc -l <"$OUT" 2>/dev/null || echo 0)"
[ "$status" = match ] && exit 0
echo "------ last 40 lines of $OUT ------" >&2
tail -n 40 "$OUT" >&2
exit 1
