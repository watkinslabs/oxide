#!/usr/bin/env bash
# Boot the same kernel N times and report how many reach a working resolver.
#
# An intermittent boot failure is a rate, and a rate needs repetition: one boot
# says nothing about a fault that fires half the time. This exists because
# measuring one took ~40 minutes, and almost all of that was the probe rather
# than the boot -- a FAILING boot cost 310s against a passing one's 125s,
# because it waits out five D-Bus pings at the full 35s command timeout plus a
# 60s resolver wait before giving up. Measuring a rate does not need the
# repetition that diagnosing a single boot does, so the windows here are sized
# for a verdict: one ping, short settles.
#
# The disk image is NOT special-cased. `make qemu-<arch>` already restages the
# build namespace's disks on every run -- `xtask rootfs` reflinks the pristine
# image and rebuilds the side disks in ~1.2s -- so each iteration starts clean
# for free. Do NOT set OXIDE_SKIP_ROOTFS: the VM is killed rather than
# unmounted, so a boot leaves its filesystem damaged and the next one inherits
# it. Skipping the restage measures that damage, not the change under test.
#
# Usage: tools/boot-rate.sh [-n runs] [-a x86|arm] [-f features]
# Env:   OXIDE_PROBE_PINGS / _CMD_TIMEOUT / _RESOLVER_TIMEOUT override the
#        verdict-sized windows; BOOT_DEADLINE the per-boot ceiling.
set -u

RUNS=8; ARCH=x86; FEATURES=""
while getopts "n:a:f:" opt; do
  case "$opt" in
    n) RUNS=$OPTARG ;; a) ARCH=$OPTARG ;; f) FEATURES=$OPTARG ;;
    *) echo "usage: $0 [-n runs] [-a x86|arm] [-f features]" >&2; exit 2 ;;
  esac
done
case "$ARCH" in
  x86) XARCH=x86_64 ;;
  arm) XARCH=aarch64 ;;
  *) echo "boot-rate: arch must be x86 or arm" >&2; exit 2 ;;
esac

REPO=$(git rev-parse --show-toplevel) || exit 2
cd "$REPO" || exit 2
LOGDIR="$REPO/target/boot-rate"; mkdir -p "$LOGDIR"
BOOT_DEADLINE=${BOOT_DEADLINE:-240}

pass=0
for i in $(seq 1 "$RUNS"); do
  log="$LOGDIR/rate-$i.log"
  FEATURES="$FEATURES" \
  OXIDE_PROBE_PINGS="${OXIDE_PROBE_PINGS:-1}" \
  OXIDE_PROBE_CMD_TIMEOUT="${OXIDE_PROBE_CMD_TIMEOUT:-10}" \
  OXIDE_PROBE_RESOLVER_TIMEOUT="${OXIDE_PROBE_RESOLVER_TIMEOUT:-20}" \
    timeout $((BOOT_DEADLINE + 120)) \
    python3 tools/guest-resolved-check.py "$ARCH" "$BOOT_DEADLINE" > "$log" 2>&1
  rc=$?
  [ "$rc" = 0 ] && pass=$((pass + 1))
  kern=$(ls -t "$REPO/target/boot-logs/$XARCH"-2*.log 2>/dev/null | head -1)
  printf 'boot%-3s rc=%-3s eio=%-4s nospace=%-3s badcsum=%-4s\n' "$i" "$rc" \
    "$(grep -c 'Input/output error' "$kern" 2>/dev/null)" \
    "$(grep -c 'kind=no-space' "$kern" 2>/dev/null)" \
    "$(grep -c 'kind=bad-checksum' "$kern" 2>/dev/null)"
done
echo "boot-rate: $pass/$RUNS reached a working resolver"
[ "$pass" = "$RUNS" ]
