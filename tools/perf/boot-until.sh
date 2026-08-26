#!/usr/bin/env bash
# Run a boot in the background, stop it as soon as the serial log shows a
# marker (or a deadline passes), and reap the guest. A boot left running past
# the answer is the same waste as one that should never have started.
set -u
log="$1"; marker="$2"; deadline="$3"; shift 3
: > "$log"
( "$@" </dev/null >/dev/null 2>&1 & ) &
start=$(date +%s)
while :; do
    if grep -qa -- "$marker" "$log" 2>/dev/null; then break; fi
    if [ $(( $(date +%s) - start )) -ge "$deadline" ]; then
        echo "boot-until: marker '$marker' not seen in ${deadline}s" >&2
        break
    fi
    sleep 2
done
elapsed=$(( $(date +%s) - start ))
echo "boot-until: stopping after ${elapsed}s"
pkill -9 -f 'qemu-system-x86_64.*builds/' 2>/dev/null
pkill -9 -f 'qemu-system-aarch64.*builds/' 2>/dev/null
exit 0
