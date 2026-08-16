#!/usr/bin/env bash
# Gate-2 reliability series: N sequential x86 boots, one attempt each,
# recording clean/total. Not a gate; a measurement.
set -u
cd /home/nd/oxide/kernel-B2244
N="${1:-9}"
TAG="${2:-before}"
OUT="scratch/evidence/b2244/x86-reliability-$TAG.txt"
: > "$OUT"
pass=0
for i in $(seq 1 "$N"); do
    OXIDE_SMOKE_ATTEMPTS=1 SMOKE_TIMEOUT=200 \
      SMOKE_KEEP_LOG="scratch/evidence/b2244/x86-$TAG-$i.log" \
      ./tools/boot-smoke.sh x86 200 > "scratch/evidence/b2244/x86-$TAG-$i.runlog" 2>&1
    rc=$?
    if [ "$rc" -eq 0 ]; then pass=$((pass+1)); fi
    last="$(grep -a 'boot-smoke: \(PASS\|FAIL\)' "scratch/evidence/b2244/x86-$TAG-$i.runlog" | tail -1)"
    lines="$(grep -ac '^\[[0-9]' "scratch/evidence/b2244/x86-$TAG-$i.log" 2>/dev/null || echo 0)"
    lastk="$(grep -a '^\[[0-9]' "scratch/evidence/b2244/x86-$TAG-$i.log" 2>/dev/null | tail -1 | cut -c1-120)"
    echo "run=$i rc=$rc klines=$lines | $last | last: $lastk" >> "$OUT"
done
echo "TOTAL $pass/$N clean" >> "$OUT"
cat "$OUT"
