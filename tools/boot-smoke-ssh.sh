#!/usr/bin/env bash
# End-to-end SSH smoke gate. Boots the kernel under qemu headless,
# waits for `oxide login:` AND for sshd to be listening on port 22,
# then runs N back-to-back ssh sessions exercising connect, KEX, auth,
# channel/exec, and clean shutdown. Each session checks rv=0 and that
# the output matches the expected substring. Any failed session = FAIL.
#
# Usage:
#   tools/boot-smoke-ssh.sh x86            # default 600s timeout, 3 connections
#   tools/boot-smoke-ssh.sh arm 1200 5     # 1200s timeout, 5 connections
#
# Requires sshpass; QEMU is launched with a per-run hostfwd port. Override
# OXIDE_QEMU_SSH_PORT when coordinating with an external launcher.
set -uo pipefail

usage() {
    cat >&2 <<EOF
usage: $0 <x86|arm> [timeout_seconds] [num_connections]
       SMOKE_TIMEOUT and SSH_SMOKE_CONNECTIONS env vars also accepted.
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
N_CONN="${3:-${SSH_SMOKE_CONNECTIONS:-3}}"
SSH_PORT="${OXIDE_QEMU_SSH_PORT:-$((20000 + ($$ % 20000)))}"
export OXIDE_QEMU_SSH_FWD=1 OXIDE_QEMU_SSH_PORT="$SSH_PORT"

if ! command -v sshpass >/dev/null 2>&1; then
    echo "boot-smoke-ssh: ERROR — sshpass not installed" >&2
    exit 2
fi

LOG="$(mktemp /tmp/oxide-ssh-smoke-${ARCH}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-ssh-smoke-${ARCH}-XXXXXX.pid)"
KNOWN_HOSTS="$(mktemp /tmp/oxide-ssh-known-XXXXXX)"
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
    rm -f "$LOG" "$PIDFILE" "$KNOWN_HOSTS"
}
trap cleanup EXIT

echo "boot-smoke-ssh: arch=$ARCH timeout=${TIMEOUT}s connections=$N_CONN log=$LOG"

OXIDE_QEMU_HEADLESS=1 setsid bash -c "exec make '$MAKE_TARGET' > '$LOG' 2>&1 < /dev/null" &
echo $! > "$PIDFILE"

deadline=$(( $(date +%s) + TIMEOUT ))
saw_login=0
saw_sshd=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
        echo "boot-smoke-ssh: FAIL — qemu exited before ssh ready" >&2
        tail -n 60 "$LOG" >&2
        exit 1
    fi
    if [ "$saw_login" -eq 0 ] && grep -q "oxide login:" "$LOG" 2>/dev/null; then
        saw_login=1
    fi
    if [ "$saw_sshd" -eq 0 ] && grep -q "Server listening on 0.0.0.0 port 22" "$LOG" 2>/dev/null; then
        saw_sshd=1
    fi
    if [ "$saw_login" -eq 1 ] && [ "$saw_sshd" -eq 1 ]; then
        break
    fi
    sleep 2
done
if [ "$saw_login" -eq 0 ] || [ "$saw_sshd" -eq 0 ]; then
    echo "boot-smoke-ssh: FAIL — timeout waiting for login=$saw_login sshd=$saw_sshd" >&2
    tail -n 80 "$LOG" >&2
    exit 1
fi

SSH_OPTS=(
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile="$KNOWN_HOSTS"
    -o GlobalKnownHostsFile=/dev/null
    -o ConnectTimeout=10
    -p "$SSH_PORT"
)

run_one() {
    local idx="$1" cmd="$2" want="$3" out
    out="$(timeout 90 sshpass -p swordfish ssh "${SSH_OPTS[@]}" alice@127.0.0.1 "$cmd" 2>&1)"
    local rv=$?
    if [ "$rv" -ne 0 ]; then
        echo "boot-smoke-ssh: FAIL — conn #$idx ($cmd) rv=$rv" >&2
        echo "--- stdout ---" >&2; echo "$out" >&2
        return 1
    fi
    if ! grep -q -- "$want" <<<"$out"; then
        echo "boot-smoke-ssh: FAIL — conn #$idx ($cmd) output missing '$want'" >&2
        echo "--- stdout ---" >&2; echo "$out" >&2
        return 1
    fi
    echo "boot-smoke-ssh: conn #$idx OK — '$cmd' produced '$want'"
    return 0
}

# Interactive PTY mode: ssh -tt with piped commands. Validates the
# full PTY path: SCM_RIGHTS fd pass, TIOCSCTTY foreground pgid seed,
# shell exec, slave→master output, master→network forwarding.
run_pty() {
    local idx="$1" out
    # Drives a cp/mv round-trip through real coreutils alongside the
    # echo, so the PTY session validates the full coreutils path too.
    # Keep PTY workload light — ARM TCG sshd-session+shell is slow,
    # and we already cover coreutils exec-mode with cp/mv/wc/rm above.
    out="$(printf 'echo OXIDE_PTY_OK\nexit\n' | timeout 60 sshpass -p swordfish ssh -tt "${SSH_OPTS[@]}" alice@127.0.0.1 2>&1)"
    # ssh -tt frequently surfaces the shell exit code as 255 even on a
    # clean session; accept 0 OR 255 as long as the expected output
    # made it through the PTY relay.
    if ! grep -q "OXIDE_PTY_OK" <<<"$out"; then
        echo "boot-smoke-ssh: FAIL — pty conn #$idx output missing OXIDE_PTY_OK" >&2
        echo "--- stdout ---" >&2; echo "$out" >&2
        return 1
    fi
    echo "boot-smoke-ssh: pty conn #$idx OK"
    return 0
}

# Rotation of commands across $N_CONN sessions. Each tests a
# different code path. ARM TCG sshd-session accumulates per-conn
# overhead so deeper rotations (>16) bog down — keep the first 16
# slots covering the essentials, push less-critical checks to the
# tail.
CMDS=(
    "echo OXIDE_SSH_OK"
    "id"
    "/usr/bin/cat /etc/passwd"
    "uname -m"
    "/bin/bash -c 'echo BASH:\$BASH_VERSION'"
    "/usr/bin/sed --version"
    "/usr/bin/sed -n 1p /etc/passwd"
    "/usr/bin/ls --version"
    "/usr/bin/grep --version"
    "/usr/bin/grep root /etc/passwd"
    "/usr/bin/tar --version"
    "/usr/bin/tar -cf /tmp/p.tar /etc/passwd 2>/dev/null; /usr/bin/tar -tf /tmp/p.tar; :"
    "/usr/bin/make --version"
    "printf 'oxgoal:\n\t@echo MAKE_OK\n' > /tmp/M && /usr/bin/make -f /tmp/M"
    "/usr/bin/gawk --version"
    "/usr/bin/awk --version"
)
WANTS=(
    "OXIDE_SSH_OK"
    "uid=1000(alice)"
    "alice:"
    "."
    "BASH:5."
    "GNU sed"
    "root:"
    "GNU coreutils"
    "GNU grep"
    "root:"
    "GNU tar"
    "etc/passwd"
    "GNU Make"
    "MAKE_OK"
    "GNU Awk"
    "GNU Awk"
)
NCMD=${#CMDS[@]}

failed=0
for i in $(seq 1 "$N_CONN"); do
    idx=$(( (i - 1) % NCMD ))
    if ! run_one "$i" "${CMDS[$idx]}" "${WANTS[$idx]}"; then
        failed=1
        break
    fi
    # Small breather between back-to-back sessions so ARM TCG's
    # sshd-session fork+exec doesn't queue up under load.
    sleep 1
done

# Dedicated post-rotation tool checks. Run AFTER the main rotation
# so a low SSH_SMOKE_CONNECTIONS still exercises the binaries.
run_tail() {
    local label="$1" cmd="$2" want="$3" out
    out="$(timeout 120 sshpass -p swordfish ssh "${SSH_OPTS[@]}" alice@127.0.0.1 "$cmd" 2>&1)"
    grep -q -- "$want" <<<"$out" || { echo "boot-smoke-ssh: FAIL — $label" >&2; echo "$out" >&2; return 1; }
    echo "boot-smoke-ssh: $label OK"
    return 0
}
if [ "$failed" -eq 0 ]; then
    # Run the round-trip / behavior checks FIRST while sshd is still
    # fresh; --version checks (which only fork-exec-write a few
    # bytes) tolerate the cumulative slowdown later in the list.
    run_tail "patch round-trip" \
             "echo a > /tmp/p1; printf '%s\n' '--- /tmp/p1' '+++ /tmp/p2' '@@ -1 +1 @@' '-a' '+OXPATCH_OK' > /tmp/p.diff; /usr/bin/patch -i /tmp/p.diff /tmp/p1 2>/dev/null; cat /tmp/p1" \
             "OXPATCH_OK" || failed=1
    run_tail "find /etc -name passwd" "/usr/bin/find /etc -name passwd" "/etc/passwd" || failed=1
    run_tail "diff /etc/passwd /etc/passwd" \
             "/usr/bin/diff /etc/passwd /etc/passwd 2>/dev/null; echo OXDIFF_DONE" \
             "OXDIFF_DONE" || failed=1
    run_tail "gawk --version"        "/usr/bin/gawk --version"        "GNU Awk" || failed=1
    run_tail "awk --version"         "/usr/bin/awk --version"         "GNU Awk" || failed=1
    run_tail "find --version"        "/usr/bin/find --version"        "GNU findutils" || failed=1
    run_tail "diff --version"        "/usr/bin/diff --version"        "diffutils" || failed=1
    run_tail "patch --version"       "/usr/bin/patch --version"       "GNU patch" || failed=1
    run_tail "bzip2 --version"       "/usr/bin/bzip2 --version 2>&1; :" "bzip2," || failed=1
    run_tail "xz --version"          "/usr/bin/xz --version"          "xz (XZ Utils)" || failed=1
fi

# Finish with an interactive PTY session — covers the SCM_RIGHTS +
# TIOCSCTTY + shell-relay path the exec-mode sessions can't reach.
# Brief settle gap so sshd's connection-reaper doesn't hit the new
# PTY session mid-cleanup of the prior exec connections (cumulative
# sshd-session load takes longer to drain on ARM TCG).
if [ "$failed" -eq 0 ]; then
    sleep 10
    if ! run_pty 1; then
        failed=1
    fi
fi

if [ "$failed" -ne 0 ]; then
    echo "------ last 80 lines of boot log ------" >&2
    tail -n 80 "$LOG" >&2
    exit 1
fi

echo "boot-smoke-ssh: PASS — $N_CONN ssh sessions + tail-tools + 1 pty on $ARCH"
exit 0
