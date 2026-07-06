#!/usr/bin/env bash
# B509 live MSI-X function-mask proof. The rootfs installs a systemd oneshot
# that runs /bin/msix_net_rx_probe; the probe configures eth0 and requires an
# inbound DNS response from QEMU slirp, exercising virtio-net RX MSI-X delivery.
set -euo pipefail

usage() {
    echo "usage: $0 <x86|arm> [timeout_seconds]" >&2
    exit 2
}

ARCH="${1:-}"
TIMEOUT="${2:-${SMOKE_TIMEOUT:-600}}"
case "$ARCH" in
    x86) MT=qemu-x86 ;;
    arm) MT=qemu-arm ;;
    *) usage ;;
esac

LOG="$(mktemp /tmp/oxide-msix-net-rx-${ARCH}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-msix-net-rx-${ARCH}-XXXXXX.pid)"

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
    [ -n "${KEEP_LOG:-}" ] && cp -f "$LOG" "$KEEP_LOG" 2>/dev/null || true
    rm -f "$LOG" "$PIDFILE"
}
trap cleanup EXIT

echo "msix-net-rx-smoke: arch=$ARCH timeout=${TIMEOUT}s log=$LOG"
OXIDE_DRIVER_PATH_SMOKE=1 OXIDE_MSIX_NET_RX_SMOKE=1 OXIDE_QEMU_HEADLESS=1 \
    OXIDE_QEMU_KVM="${OXIDE_QEMU_KVM:-1}" setsid bash -c "exec make '$MT' > '$LOG' 2>&1 < /dev/null" &
echo $! > "$PIDFILE"

deadline=$(( $(date +%s) + TIMEOUT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
        echo "msix-net-rx-smoke: FAIL - qemu exited" >&2
        tail -n 80 "$LOG" >&2
        exit 1
    fi
    if grep -aq "msix_net_rx_probe: PASS" "$LOG" 2>/dev/null; then
        grep -aE "msix_net_rx_probe:" "$LOG" | tail -10
        echo "msix-net-rx-smoke: PASS - $ARCH inbound virtio-net RX"
        exit 0
    fi
    if grep -aqE "msix_net_rx_probe: FAIL|driver-path-smoke.service: Failed" "$LOG" 2>/dev/null; then
        echo "msix-net-rx-smoke: FAIL - service reported failure" >&2
        grep -aE "msix_net_rx_probe:|driver-path-smoke.service" "$LOG" >&2
        exit 1
    fi
    sleep 2
done

echo "msix-net-rx-smoke: FAIL - timeout waiting for RX proof" >&2
tail -n 100 "$LOG" >&2
exit 1
