#!/usr/bin/env bash
# Deterministic serial-capture harness for in-guest validation.
#
# Unlike boot-smoke.sh (which only checks for `oxide login:` then kills
# qemu, deleting the log), this captures the FULL serial output to a
# stable path and waits for a caller-supplied marker — so in-guest
# probes (cgroup smoke, etc.) that print before/after login are kept.
#
# Usage:
#   tools/boot-capture.sh <x86|arm> <marker-regex> [timeout_s] [out.log]
#
# Example:
#   tools/boot-capture.sh x86 'post-cgroup-smoke' 180 /tmp/cg.log
#
# Why this exists: the make→xtask→qemu chain re-forks qemu into its own
# process group, so a setsid-group kill leaks it. A leaked qemu holds
# /dev/kvm (forcing the next boot to slow TCG) and tcp:2222 (so the
# next boot fails with "Could not set up host forwarding"). This script
# always reaps qemu by NAME at start and end, and exits 0 on capture so
# the harness doesn't report a false failure.
set -uo pipefail

ARCH="${1:-}"
MARKER="${2:-oxide login:}"
TIMEOUT="${3:-180}"
OUT="${4:-/tmp/oxide-boot-capture-${ARCH}.log}"

case "$ARCH" in
    x86) TARGET=qemu-x86 ;;
    arm) TARGET=qemu-arm ;;
    *)   echo "usage: $0 <x86|arm> <marker-regex> [timeout_s] [out.log]" >&2; exit 2 ;;
esac

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

# Reap any leaked qemu so KVM + port 2222 are free (root cause of
# TCG fallback + host-forwarding failures on repeat runs).
pkill -9 -f qemu-system 2>/dev/null || true
sleep 2

rm -f "$OUT"
# Detach the build+boot into its own session; serial → $OUT.
OXIDE_QEMU_HEADLESS=1 setsid bash -c "exec make '$TARGET' > '$OUT' 2>&1 < /dev/null" &

deadline=$(( $(date +%s) + TIMEOUT ))
status=timeout
while [ "$(date +%s)" -lt "$deadline" ]; do
    sleep 2
    if grep -qE "$MARKER" "$OUT" 2>/dev/null; then status=match; break; fi
    if grep -q "Could not set up host forwarding" "$OUT" 2>/dev/null; then status=portbusy; break; fi
done

# Always reap qemu by name (the setsid-group kill leaks the grandchild).
pkill -9 -f qemu-system 2>/dev/null || true

echo "boot-capture: arch=$ARCH status=$status log=$OUT"
[ "$status" = match ] && exit 0
echo "------ last 40 lines ------" >&2
tail -n 40 "$OUT" >&2
# Structured metrics for this capture. Hand-grepping a boot log is how two
# wrong conclusions got made ("few log lines" read as an idle machine; a
# feature that traces MUNMAP mistaken for mount tracing), so every capture now
# ends with the same parsed numbers instead of an ad-hoc grep.
if [ -s "$OUT" ] && [ -x "$REPO/tools/boot-report.py" ]; then
    echo
    "$REPO/tools/boot-report.py" "$OUT" || true
    "$REPO/tools/boot-report.py" "$OUT" --json > "${OUT%.log}.metrics.json" 2>/dev/null || true
fi

# Exit 0 regardless: the log is the deliverable; caller greps it.
exit 0

