#!/usr/bin/env bash
# Console-login regression gate (B18). Boots the kernel headless,
# waits for `oxide login:` on serial, types `alice` + `swordfish`,
# then runs `id` and checks the shell prints
# `uid=1000(alice) gid=1000`. Catches regressions in:
#   - SysV stack envp/argv ordering (process_title_init memset trap)
#   - PAM auth → session → setcred chain
#   - TIOCSCTTY VT foreground_pgid handover
#   - controlling-tty + job-control on /dev/ttyS0
#   - busybox login-shell startup
#
# Usage:
#   tools/boot-smoke-login.sh x86            # default 600s
#   tools/boot-smoke-login.sh arm 1200
#   SMOKE_TIMEOUT=1200 tools/boot-smoke-login.sh x86
set -uo pipefail

usage() {
    cat >&2 <<EOF
usage: $0 <x86|arm> [timeout_seconds]
       SMOKE_TIMEOUT env var also accepted (defaults to 600).
EOF
    exit 2
}

ARCH="${1:-}"
case "$ARCH" in
    x86) MAKE_TARGET=qemu-x86 ;;
    arm) MAKE_TARGET=qemu-arm ;;
    *)   usage ;;
esac
TIMEOUT="${2:-${SMOKE_TIMEOUT:-600}}"

LOG="$(mktemp /tmp/oxide-login-smoke-${ARCH}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-login-smoke-${ARCH}-XXXXXX.pid)"
QIN="$(mktemp -u /tmp/oxide-login-smoke-${ARCH}-qin-XXXXXX)"
mkfifo "$QIN"
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
    rm -f "$LOG" "$PIDFILE" "$QIN"
}
trap cleanup EXIT

echo "boot-smoke-login: arch=$ARCH timeout=${TIMEOUT}s log=$LOG"

# Hold the FIFO open writable for the entire run via fd 9 so qemu
# doesn't see EOF the moment our `printf` finishes.
exec 9<>"$QIN"

OXIDE_QEMU_HEADLESS=1 setsid bash -c "exec make '$MAKE_TARGET' > '$LOG' 2>&1 < '$QIN'" &
echo $! > "$PIDFILE"

wait_for() {
    local pat="$1" label="$2" deadline="$3"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local pid
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "boot-smoke-login: FAIL — qemu exited before $label" >&2
            tail -n 80 "$LOG" >&2
            exit 1
        fi
        if grep -aq "$pat" "$LOG" 2>/dev/null; then
            return 0
        fi
        sleep 2
    done
    echo "boot-smoke-login: FAIL — timeout waiting for $label" >&2
    tail -n 80 "$LOG" >&2
    exit 1
}

deadline=$(( $(date +%s) + TIMEOUT ))
wait_for "oxide login:" "login prompt" "$deadline"

sleep 1
printf 'alice\n'     >&9
sleep 2
printf 'swordfish\n' >&9
# Wait for the shell prompt and then drive `id` through it.
wait_for 'oxide:~\$' "shell prompt" "$deadline"
printf 'id\n' >&9
wait_for 'uid=1000(alice)' "id output" "$deadline"

elapsed=$(( $(date +%s) - (deadline - TIMEOUT) ))
echo "boot-smoke-login: PASS — $ARCH console login → shell → id in ${elapsed}s"
exit 0
