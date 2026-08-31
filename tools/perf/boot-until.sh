#!/usr/bin/env bash
# Run a boot in the background, stop it as soon as the serial log shows a
# marker (or a deadline passes), and reap the guest. A boot left running past
# the answer is the same waste as one that should never have started.
set -u
log="$1"; marker="$2"; deadline="$3"; shift 3
: > "$log"
setsid "$@" </dev/null >/dev/null 2>&1 &
child=$!
cleanup() {
    if kill -0 "$child" 2>/dev/null; then
        kill -TERM -- "-$child" 2>/dev/null || true
        sleep 1
        kill -KILL -- "-$child" 2>/dev/null || true
    fi
    wait "$child" 2>/dev/null || true
}
trap cleanup EXIT
start=$(date +%s)
status=1
while :; do
    if grep -qa -- "$marker" "$log" 2>/dev/null; then
        status=0
        break
    fi
    if ! kill -0 "$child" 2>/dev/null; then
        echo "boot-until: boot command exited before marker '$marker'" >&2
        break
    fi
    if [ $(( $(date +%s) - start )) -ge "$deadline" ]; then
        echo "boot-until: marker '$marker' not seen in ${deadline}s" >&2
        break
    fi
    sleep 2
done
elapsed=$(( $(date +%s) - start ))
echo "boot-until: stopping after ${elapsed}s"
exit "$status"
