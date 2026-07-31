#!/usr/bin/env bash
# Echo-probe smoke gate. Boots the kernel headless, waits for sshd, then runs
# the distribution's own ping(8) as an ORDINARY user with no capabilities.
# That tool opens AF_INET/SOCK_DGRAM/IPPROTO_ICMP first and only falls back to
# a raw socket when that fails, so a pass proves the ICMP datagram endpoint
# class end to end: group-window admission, kernel-assigned echo identifier,
# identifier-keyed reply demultiplexing, and the receive record shape.
#
# Usage:
#   tools/boot-smoke-ping.sh x86            # default 600s timeout
#   tools/boot-smoke-ping.sh arm 1200
set -uo pipefail

ARCH="${1:-}"
case "$ARCH" in
    x86) MAKE_TARGET=qemu-x86 ;;
    arm) MAKE_TARGET=qemu-arm ;;
    *)   echo "usage: $0 <x86|arm> [timeout_seconds]" >&2; exit 2 ;;
esac
TIMEOUT="${2:-${SMOKE_TIMEOUT:-600}}"
SSH_PORT="${OXIDE_QEMU_SSH_PORT:-$((20000 + ($$ % 20000)))}"
export OXIDE_QEMU_SSH_FWD=1 OXIDE_QEMU_SSH_PORT="$SSH_PORT"

command -v sshpass >/dev/null 2>&1 || { echo "boot-smoke-ping: ERROR — sshpass not installed" >&2; exit 2; }

LOG="$(mktemp /tmp/oxide-ping-smoke-${ARCH}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-ping-smoke-${ARCH}-XXXXXX.pid)"
KNOWN_HOSTS="$(mktemp /tmp/oxide-ping-known-XXXXXX)"
cleanup() {
    if [ -s "$PIDFILE" ]; then
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "-$pid" 2>/dev/null || true
            sleep 1
            kill -KILL "-$pid" 2>/dev/null || true
        fi
    fi
    rm -f "$PIDFILE" "$KNOWN_HOSTS"
}
trap cleanup EXIT

echo "boot-smoke-ping: arch=$ARCH timeout=${TIMEOUT}s log=$LOG"
OXIDE_QEMU_HEADLESS=1 setsid bash -c "exec make '$MAKE_TARGET' > '$LOG' 2>&1 < /dev/null" &
echo $! > "$PIDFILE"

deadline=$(( $(date +%s) + TIMEOUT ))
saw_sshd=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
        echo "boot-smoke-ping: FAIL — qemu exited before ssh ready" >&2
        tail -n 60 "$LOG" >&2
        exit 1
    fi
    if grep -q "Server listening on 0.0.0.0 port 22" "$LOG" 2>/dev/null; then saw_sshd=1; break; fi
    sleep 2
done
if [ "$saw_sshd" -eq 0 ]; then
    echo "boot-smoke-ping: FAIL — timeout waiting for sshd" >&2
    tail -n 80 "$LOG" >&2
    exit 1
fi

SSH_OPTS=(
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile="$KNOWN_HOSTS"
    -o GlobalKnownHostsFile=/dev/null
    -o ConnectTimeout=30
    -p "$SSH_PORT"
)

# sshd announces its listener before the guest has finished settling, and the
# first session on a loaded TCG guest can time out during banner exchange.
# Retry a trivial session until one completes before judging anything.
ready=0
for attempt in $(seq 1 20); do
    if timeout 90 sshpass -p swordfish ssh "${SSH_OPTS[@]}" alice@127.0.0.1 \
        'echo OXIDE_SSH_READY' 2>&1 | grep -q OXIDE_SSH_READY
    then ready=1; break; fi
    echo "boot-smoke-ping: ssh warm-up attempt $attempt did not complete"
    sleep 5
done
if [ "$ready" -eq 0 ]; then
    echo "boot-smoke-ping: FAIL — ssh never completed a session" >&2
    tail -n 80 "$LOG" >&2
    exit 1
fi

failed=0
check() {
    label="$1"; cmd="$2"; want="$3"
    out="$(timeout 120 sshpass -p swordfish ssh "${SSH_OPTS[@]}" alice@127.0.0.1 "$cmd" 2>&1)"
    if ! grep -qE -- "$want" <<<"$out"; then
        echo "boot-smoke-ping: FAIL — $label (expected '$want')" >&2
        echo "--- output ---" >&2; echo "$out" >&2
        failed=1
        return 1
    fi
    echo "boot-smoke-ping: $label OK"
    return 0
}

# The caller is an ordinary user, and the binary carries no capabilities — the
# only thing that can admit an echo probe is the group window.
check "unprivileged caller"  "id -u"                                        "^1000$"
check "group window opened"  "cat /proc/sys/net/ipv4/ping_group_range"      "2147483647"
check "endpoint opens"       "ping -c1 -W3 127.0.0.1 2>&1 | head -1"        "^PING 127.0.0.1"
check "loopback probe"       "ping -c2 -W3 127.0.0.1 2>&1 | tail -3"        "2 received"
check "gateway probe"        "ping -c1 -W5 10.0.2.2 2>&1 | tail -3"         "1 received"
check "ipv6 loopback probe"  "ping -6 -c1 -W3 ::1 2>&1 | tail -3"           "1 received"

if [ "$failed" -ne 0 ]; then
    echo "boot-smoke-ping: FAIL ($ARCH)" >&2
    exit 1
fi
echo "boot-smoke-ping: PASS ($ARCH)"
