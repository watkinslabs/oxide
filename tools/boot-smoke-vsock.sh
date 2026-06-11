#!/usr/bin/env bash
# D3.3 virtio-vsock host↔guest round-trip smoke. Starts a HOST AF_VSOCK
# echo server on port 1234 (socat, else a python3 fallback), boots the
# kernel, logs in over serial (alice/swordfish), runs /bin/vsock_probe,
# and asserts BOTH:
#   1. the kernel enumerated the device (`virtio-vsock installed cid=3`)
#   2. the guest probe prints `vsock_probe: PASS`
#
# The guest connects to {cid=2 (VMADDR_CID_HOST), port=1234}; the host
# echo server replies the bytes verbatim → the probe asserts echo==sent.
# Driven via the serial-login FIFO (the rcS smoke path does not run under
# the systemd boot), so this exercises the real OP_REQUEST/RESPONSE/RW
# datapath end to end.
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
PIDFILE="$(mktemp /tmp/oxide-smoke-vsock-${ARCH}-XXXXXX.pid)"
QIN="$(mktemp -u /tmp/oxide-smoke-vsock-${ARCH}-qin-XXXXXX)"
mkfifo "$QIN"
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
    exec 9>&- 2>/dev/null || true
    rm -f "$LOG" "$PIDFILE" "$QIN" "$PY_SERVER"
}
trap cleanup EXIT

echo "boot-smoke-vsock: arch=$ARCH timeout=${TIMEOUT}s log=$LOG"

# Hold the FIFO open writable so qemu doesn't see EOF after our printfs.
exec 9<>"$QIN"

OXIDE_QEMU_HEADLESS=1 setsid bash -c "exec make '$MAKE_TARGET' > '$LOG' 2>&1 < '$QIN'" &
echo $! > "$PIDFILE"

wait_for() {
    local pat="$1" label="$2" deadline="$3"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local pid; pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "boot-smoke-vsock: FAIL — qemu exited before $label" >&2
            tail -n 60 "$LOG" >&2
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
wait_for "oxide login:" "login prompt" "$deadline"
sleep 1
printf 'alice\n'     >&9
sleep 2
printf 'swordfish\n' >&9
wait_for 'oxide:~\$' "shell prompt" "$deadline"
# Run the round-trip probe: connect to the host echo server over vsock.
printf '/bin/vsock_probe\n' >&9
while [ "$(date +%s)" -lt "$deadline" ]; do
    if grep -aq 'vsock_probe: PASS' "$LOG" 2>/dev/null; then
        echo "boot-smoke-vsock: PASS — device cid=3 + host round-trip OK"
        grep -aE "virtio-vsock installed|vsock_probe:" "$LOG" | tail -3
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
