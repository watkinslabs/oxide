#!/usr/bin/env bash
# D3.3 virtio-vsock host↔guest round-trip smoke. Starts a HOST AF_VSOCK
# echo server on port 1234 (socat, else a python3 fallback), boots the
# kernel with an opt-in direct /init that runs /bin/vsock_probe, and
# asserts BOTH:
#   1. the kernel enumerated the device (`virtio-vsock installed cid=3`)
#   2. the guest probe prints `vsock_probe: PASS`
#
# The guest connects to {cid=2 (VMADDR_CID_HOST), port=1234}; the host
# echo server replies the bytes verbatim → the probe asserts echo==sent.
# Driven via the same UART-socket capture path as the driver proof smokes,
# so it exercises the real OP_REQUEST/RESPONSE/RW datapath without waiting
# for the full systemd desktop path.
#
# Requires /dev/vhost-vsock on the host. Skips cleanly (exit 0 with a
# clear message) if neither socat-with-VSOCK nor python3 is available.
#
# Usage:
#   tools/boot-smoke-vsock.sh x86 600
#   tools/boot-smoke-vsock.sh arm 900
set -uo pipefail

usage() { echo "usage: $0 <x86|arm> [timeout_seconds]" >&2; exit 2; }
ARCH="${1:-}"
case "$ARCH" in
    x86) MAKE_TARGET=qemu-x86 ;;
    arm) MAKE_TARGET=qemu-arm ;;
    *)   usage ;;
esac
TIMEOUT="${2:-600}"
HOST_PORT=1234
MULTIDEV="${OXIDE_VIRTIO_VSOCK_MULTIDEV_SMOKE:-}"

# vhost-vsock kernel module / dev node is mandatory for the host peer.
if [ ! -e /dev/vhost-vsock ]; then
    echo "boot-smoke-vsock: SKIP — /dev/vhost-vsock absent (load vhost_vsock)"
    exit 0
fi

# Pick a host echo server. socat with VSOCK support is preferred; else
# a tiny python3 AF_VSOCK echo server.
HOST_PEER_PID=""
PY_SERVER="$(mktemp /tmp/oxide-vsock-echo-XXXXXX.py)"
start_host_peer() {
    if command -v socat >/dev/null 2>&1 && socat -h 2>/dev/null | grep -qi vsock; then
        echo "boot-smoke-vsock: host peer = socat VSOCK-LISTEN:${HOST_PORT}"
        socat "VSOCK-LISTEN:${HOST_PORT},reuseaddr,fork" EXEC:cat &
        HOST_PEER_PID=$!
        return 0
    fi
    if command -v python3 >/dev/null 2>&1; then
        cat > "$PY_SERVER" <<PYEOF
import socket
s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((socket.VMADDR_CID_ANY, ${HOST_PORT}))
s.listen(8)
while True:
    c, _ = s.accept()
    while True:
        d = c.recv(4096)
        if not d:
            break
        c.sendall(d)
    c.close()
PYEOF
        echo "boot-smoke-vsock: host peer = python3 AF_VSOCK echo :${HOST_PORT}"
        python3 "$PY_SERVER" &
        HOST_PEER_PID=$!
        return 0
    fi
    return 1
}

if ! start_host_peer; then
    echo "boot-smoke-vsock: SKIP — no socat(VSOCK) or python3 host echo server"
    rm -f "$PY_SERVER"
    exit 0
fi

LOG="$(mktemp /tmp/oxide-smoke-vsock-${ARCH}-XXXXXX.log)"
KEEP_LOG="${KEEP_LOG:-}"
PIDFILE="$(mktemp /tmp/oxide-smoke-vsock-${ARCH}-XXXXXX.pid)"
UART="$(mktemp -u /tmp/oxide-smoke-vsock-${ARCH}-uart-XXXXXX.sock)"
UART_BRIDGE_PID=""
cleanup() {
    if [ -n "$HOST_PEER_PID" ] && kill -0 "$HOST_PEER_PID" 2>/dev/null; then
        kill -TERM "$HOST_PEER_PID" 2>/dev/null || true
    fi
    if [ -s "$PIDFILE" ]; then
        local pid; pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "-$pid" 2>/dev/null || true
            sleep 1
            kill -KILL "-$pid" 2>/dev/null || true
        fi
    fi
    [ -n "$UART_BRIDGE_PID" ] && kill "$UART_BRIDGE_PID" 2>/dev/null || true
    if [ -n "$KEEP_LOG" ]; then
        cp "$LOG" "$KEEP_LOG" 2>/dev/null || true
        echo "boot-smoke-vsock: kept log at $KEEP_LOG"
        rm -f "$PIDFILE" "$UART" "$PY_SERVER"
    else
        rm -f "$LOG" "$PIDFILE" "$UART" "$PY_SERVER"
    fi
}
trap cleanup EXIT

echo "boot-smoke-vsock: arch=$ARCH timeout=${TIMEOUT}s uart=$UART log=$LOG"

OXIDE_DRIVER_PATH_SMOKE=1 OXIDE_VSOCK_SMOKE=1 OXIDE_QEMU_HEADLESS=1 OXIDE_QEMU_UART_SOCK="$UART" OXIDE_QEMU_KVM="${OXIDE_QEMU_KVM:-1}" \
    setsid bash -c "exec make '$MAKE_TARGET' > '$LOG' 2>&1 < /dev/null" &
echo $! > "$PIDFILE"
for _ in $(seq 1 600); do
    [ -S "$UART" ] && break
    sleep 0.1
done
[ -S "$UART" ] || { echo "boot-smoke-vsock: FAIL — UART socket absent" >&2; exit 1; }
python3 - "$UART" "$LOG" <<'PY' &
import socket, sys

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

wait_for() {
    local pat="$1" label="$2" deadline="$3"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local pid; pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "boot-smoke-vsock: FAIL — qemu exited before $label" >&2
            tail -n 60 "$LOG" >&2
            exit 1
        fi
        if grep -aqE 'vsock_probe: FAIL|driver-path-smoke.service: Failed' "$LOG" 2>/dev/null; then
            echo "boot-smoke-vsock: FAIL — service reported failure before $label" >&2
            grep -aE "virtio-vsock installed|vsock_probe:|driver-path-smoke.service" "$LOG" >&2
            exit 1
        fi
        if grep -aq "$pat" "$LOG" 2>/dev/null; then return 0; fi
        sleep 2
    done
    echo "boot-smoke-vsock: FAIL — timeout waiting for $label" >&2
    grep -aE "virtio-vsock installed|vsock_probe:" "$LOG" >&2 || true
    tail -n 60 "$LOG" >&2
    exit 1
}

deadline=$(( $(date +%s) + TIMEOUT ))
wait_for "virtio-vsock installed cid=" "device bring-up" "$deadline"
if [ -n "$MULTIDEV" ]; then
    wait_for "virtio-vsock installed cid=3" "primary vsock endpoint" "$deadline"
    wait_for "virtio-vsock installed cid=4" "secondary vsock endpoint" "$deadline"
fi
while [ "$(date +%s)" -lt "$deadline" ]; do
    if grep -aq 'vsock_probe: PASS' "$LOG" 2>/dev/null; then
        if [ -n "$MULTIDEV" ]; then
            echo "boot-smoke-vsock: PASS — devices cid=3,cid=4 + primary host round-trip OK"
        else
            echo "boot-smoke-vsock: PASS — device cid=3 + host round-trip OK"
        fi
        grep -aE "virtio-vsock installed|vsock_probe:" "$LOG" | tail -5
        exit 0
    fi
    if grep -aq 'vsock_probe: FAIL' "$LOG" 2>/dev/null; then
        echo "boot-smoke-vsock: FAIL — probe reported failure" >&2
        grep -aE "virtio-vsock installed|vsock_probe:" "$LOG" >&2
        exit 1
    fi
    sleep 2
done
echo "boot-smoke-vsock: FAIL — timeout after ${TIMEOUT}s (no probe verdict)" >&2
grep -aE "virtio-vsock installed|vsock_probe:" "$LOG" >&2 || true
tail -n 60 "$LOG" >&2
exit 1
