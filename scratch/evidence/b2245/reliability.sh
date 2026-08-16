#!/usr/bin/env bash
# Tier-0 gate 2: N sequential boots of one arch, one attempt each, recording
# clean/total. A wedged run times out and the smoke handler types the sysrq
# task / blocked / per-cpu / all-cpu-backtrace sequence before the guest dies,
# so a failure leaves the dump a later lane would otherwise have to re-boot for.
set -u
cd /home/nd/oxide/kernel-B2245
ARCH="${1:-x86}"
N="${2:-9}"
TAG="${3:-m1}"
TMO="${4:-110}"
OUT="scratch/evidence/b2245/$ARCH-$TAG.txt"
: > "$OUT"
pass=0
for i in $(seq 1 "$N"); do
    OXIDE_SMOKE_ATTEMPTS=1 SMOKE_TIMEOUT="$TMO" \
      SMOKE_KEEP_LOG="scratch/evidence/b2245/$ARCH-$TAG-$i.log" \
      ./tools/boot-smoke.sh "$ARCH" "$TMO" > "scratch/evidence/b2245/$ARCH-$TAG-$i.runlog" 2>&1
    rc=$?
    [ "$rc" -eq 0 ] && pass=$((pass+1))
    lines="$(grep -ac '^\[[0-9]' "scratch/evidence/b2245/$ARCH-$TAG-$i.log" 2>/dev/null || echo 0)"
    lastk="$(grep -a '^\[[0-9]' "scratch/evidence/b2245/$ARCH-$TAG-$i.log" 2>/dev/null | tail -1 | cut -c1-110)"
    echo "run=$i rc=$rc klines=$lines | last: $lastk" >> "$OUT"
done
echo "TOTAL $pass/$N clean" >> "$OUT"
cat "$OUT"
