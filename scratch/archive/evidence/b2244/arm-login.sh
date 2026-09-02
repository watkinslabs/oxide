#!/usr/bin/env bash
# Tier-0 gate 1 (aarch64): does a boot reach a login prompt and stay there?
# Serial getty, no debug shell, so `oxide login:` is the real marker.
set -u
cd /home/nd/oxide/kernel-B2244
N="${1:-3}"
TAG="${2:-after}"
OUT="scratch/evidence/b2244/arm-login-$TAG.txt"
: > "$OUT"
pass=0
for i in $(seq 1 "$N"); do
    OXIDE_SERIAL_SHELL=0 OXIDE_SMOKE_ATTEMPTS=1 SMOKE_ALIVE_PROBE= SMOKE_RX_MARKER= \
      SMOKE_MARKER='oxide login:' SMOKE_TIMEOUT=240 \
      SMOKE_KEEP_LOG="scratch/evidence/b2244/arm-login-$TAG-$i.log" \
      ./tools/boot-smoke.sh arm 240 > "scratch/evidence/b2244/arm-login-$TAG-$i.runlog" 2>&1
    rc=$?
    [ "$rc" -eq 0 ] && pass=$((pass+1))
    jd="$(grep -a 'systemd-journald.service' "scratch/evidence/b2244/arm-login-$TAG-$i.log" 2>/dev/null | head -3 | tr '\n' ' ' | cut -c1-200)"
    echo "run=$i rc=$rc | journald: $jd" >> "$OUT"
done
echo "TOTAL $pass/$N reached a login prompt" >> "$OUT"
cat "$OUT"
