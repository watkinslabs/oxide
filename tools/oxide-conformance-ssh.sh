#!/usr/bin/env bash
# Run selected glibc conformance artifacts inside an Oxide QEMU guest.
# Requires sshpass, debugfs, and a packed glibc image from ../images.
set -euo pipefail

ARCH="${1:-x86_64}"
TESTS="${2:-t_mmsg}"
TIMEOUT="${3:-600}"
case "$ARCH" in
    x86_64) QEMU_ARCH=x86_64; GUEST_TRIPLE=x86_64-unknown-linux-gnu ;;
    aarch64) QEMU_ARCH=aarch64; GUEST_TRIPLE=aarch64-unknown-linux-gnu ;;
    *) echo "usage: $0 <x86_64|aarch64> <test[,test...]> [timeout]" >&2; exit 2 ;;
esac
command -v sshpass >/dev/null || { echo "oxide-conformance: sshpass is required" >&2; exit 2; }

ID="conformance-${ARCH}-$(date +%s)-$$"
PORT="${OXIDE_QEMU_SSH_PORT:-$((20000 + ($$ % 20000)))}"
LOG="$(mktemp /tmp/oxide-conformance-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-conformance-XXXXXX.pid)"
KNOWN="$(mktemp /tmp/oxide-conformance-known-XXXXXX)"
cleanup() {
    if [ -s "$PIDFILE" ]; then
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        [ -z "$pid" ] || kill -TERM "-$pid" 2>/dev/null || true
    fi
    rm -f "$LOG" "$PIDFILE" "$KNOWN"
    rm -rf "${KEYDIR:-}"
    rm -f "${SSHD_DROPIN:-}"
}
trap cleanup EXIT

echo "oxide-conformance: prepare arch=$ARCH tests=$TESTS id=$ID"
cargo run -q -p xtask -- rootfs --arch "$QEMU_ARCH" --id "$ID"
if ! cargo run -q -p xtask -- glibc-test --arch "$ARCH" --inject "$TESTS" --id "$ID"; then
    for name in ${TESTS//,/ }; do
        test -f "target/glibc-conf/${name}.${GUEST_TRIPLE}.guest" || {
            echo "oxide-conformance: missing requested guest artifact $name" >&2
            exit 1
        }
    done
    echo "oxide-conformance: continuing after unrelated host-oracle mismatch" >&2
fi

# The copied image is disposable; provide host keys up front so sshd does not
# depend on the guest key-generation units, which are outside this test's ABI.
KEYDIR="$(mktemp -d /tmp/oxide-conformance-keys-XXXXXX)"
SSHD_DROPIN="$(mktemp /tmp/oxide-conformance-sshd-XXXXXX.conf)"
printf '%s\n' '[Service]' 'ExecStartPre=/usr/bin/mkdir -p /run/sshd' > "$SSHD_DROPIN"
debugfs -w -R 'mkdir /etc/systemd/system/sshd.service.d' \
    "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
debugfs -w -R 'rm /etc/systemd/system/sshd.service.d/conformance.conf' \
    "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null 2>&1 || true
debugfs -w -R "write $SSHD_DROPIN /etc/systemd/system/sshd.service.d/conformance.conf" \
    "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
for spec in "rsa 2048" "ecdsa 256" "ed25519"; do
    set -- $spec
    if [ "$1" = ed25519 ]; then
        ssh-keygen -q -t ed25519 -N '' -f "$KEYDIR/ssh_host_ed25519_key"
    else
        ssh-keygen -q -t "$1" -b "$2" -N '' -f "$KEYDIR/ssh_host_${1}_key"
    fi
    debugfs -w -R "rm /etc/ssh/ssh_host_${1}_key" \
        "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null 2>&1 || true
    debugfs -w -R "rm /etc/ssh/ssh_host_${1}_key.pub" \
        "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null 2>&1 || true
    debugfs -w -R "write $KEYDIR/ssh_host_${1}_key /etc/ssh/ssh_host_${1}_key" \
        "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
    debugfs -w -R "write $KEYDIR/ssh_host_${1}_key.pub /etc/ssh/ssh_host_${1}_key.pub" \
        "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
    debugfs -w -R "sif /etc/ssh/ssh_host_${1}_key mode 0100600" \
        "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
done

OXIDE_SKIP_ROOTFS=1 OXIDE_QEMU_HEADLESS=1 OXIDE_QEMU_SSH_FWD=1 OXIDE_QEMU_SSH_PORT="$PORT" \
    setsid bash -c "exec cargo run -q -p xtask -- grub --arch $QEMU_ARCH --id $ID > '$LOG' 2>&1 < /dev/null" &
echo $! > "$PIDFILE"
deadline=$(( $(date +%s) + TIMEOUT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    grep -q "Server listening on 0.0.0.0 port 22" "$LOG" 2>/dev/null && break
    sleep 2
done
if ! grep -q "Server listening on 0.0.0.0 port 22" "$LOG" 2>/dev/null; then
    echo "oxide-conformance: SSH timeout" >&2; tail -n 80 "$LOG" >&2; exit 1
fi

ssh_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile="$KNOWN" -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=10 -p "$PORT")
for name in ${TESTS//,/ }; do
    host="target/glibc-conf/${name}.host"
    guest="/usr/local/bin/oxide-conformance-$name"
    expected="$("./$host" 2>/dev/null || true)"
    guest_out="$(timeout 90 sshpass -p swordfish ssh "${ssh_opts[@]}" alice@127.0.0.1 \
        "timeout 60 '$guest'" 2>/dev/null)" || {
        echo "oxide-conformance: FAIL $name (guest execution)" >&2
        tail -n 80 "$LOG" >&2
        exit 1
    }
    if [ "$expected" != "$guest_out" ]; then
        echo "oxide-conformance: FAIL $name (stdout mismatch)" >&2
        printf 'host:  %s\nguest: %s\n' "$expected" "$guest_out" >&2
        exit 1
    fi
    echo "oxide-conformance: PASS $name"
done
echo "oxide-conformance: PASS arch=$ARCH tests=$TESTS"
