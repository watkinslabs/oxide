#!/usr/bin/env bash
# Console-login regression gate (B18). Boots the kernel headless,
# waits for `oxide login:` on serial, types `alice` + `swordfish`,
# then runs `id` and checks the shell prints
# `uid=1000(alice) gid=1000`. Catches regressions in:
#   - SysV stack envp/argv ordering (process_title_init memset trap)
#   - PAM auth → session → setcred chain
#   - TIOCSCTTY VT foreground_pgid handover
#   - controlling-tty + job-control on /dev/ttyS0
#   - bash login-shell startup
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
    x86)  MAKE_TARGET=qemu-x86 ;;
    arm)  MAKE_TARGET=qemu-arm ;;
    # GRUB self-bootstrap path (F372): same headless stdio serial, so
    # the QIN fifo reaches the guest UART RX exactly as the Limine path.
    grub) MAKE_TARGET=qemu-x86-grub ;;
    *)    usage ;;
esac
TIMEOUT="${2:-${SMOKE_TIMEOUT:-600}}"

# Credentials are image-specific: the lite image ships alice/swordfish, the
# glibc GNOME image ships oxide/oxide (uid 1000). Overridable so one harness
# gates both rather than silently testing the wrong account.
LOGIN_USER="${LOGIN_USER:-alice}"
LOGIN_PASS="${LOGIN_PASS:-swordfish}"
LOGIN_UID="${LOGIN_UID:-1000}"

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
printf '%s\n' "$LOGIN_USER" >&9
sleep 2
printf '%s\n' "$LOGIN_PASS" >&9
# Wait for the shell prompt and then drive `id` through it.
wait_for 'oxide:~\$' "shell prompt" "$deadline"
printf 'id\n' >&9
wait_for "uid=${LOGIN_UID}(${LOGIN_USER})" "id output" "$deadline"
# Box C: assert util-linux login exec'd a LOGIN shell (argv[0]="-sh"), so
# /etc/profile + /etc/profile.d/*.sh sourced. `shopt login_shell` == on proves it.
printf 'shopt login_shell\n' >&9
wait_for 'login_shell[[:space:]]\+on' "login-shell (shopt login_shell on)" "$deadline"
# Box C: python3 (CPython 3.13 static-musl) actually runs — the interpreter
# loads the `encodings` module at init from /usr/lib/python313.zip, so a
# successful print proves stdlib-zip on sys.path (no "No module named
# 'encodings'"). Distinctive palindrome avoids false log matches.
printf 'python3 -c "print(123454321)"\n' >&9
wait_for '123454321' "python3 (encodings/stdlib zip)" "$deadline"
# Box C: stty (coreutils applet) is staged + works — queries the tty winsize.
# /dev/console is the unified fb-primary console (console-plan B4): its winsize
# is the framebuffer cell grid (50 rows x 160 cols at the default 8x16 font on
# the QEMU fb), not the pre-unification serial 24x80 default.
printf 'stty size\n' >&9
wait_for '50 160' "stty (coreutils applet)" "$deadline"
# Box D: vendor base-set apps actually run (real cross-built upstream binaries).
# BACKGROUND each + count which produced output (a foreground `{ a|head; b|head; }`
# chain intermittently stalled under TCG — one slow/SIGPIPE'd app blocked the
# whole pipe and the marker never printed). Computed marker BASEAPPS=$M is
# output-only (no echo false-match); gates on real execution.
printf 'for a in "rg --version" "jq --version" "curl --version" "tmux -V" "bat --version"; do ($a >/tmp/ba_${a%% *} 2>&1 &); done; sleep 20; M=0; for x in rg jq curl tmux bat; do [ -s /tmp/ba_$x ] && M=$((M+1)); done; echo BASEAPPS=$M\n' >&9
wait_for 'BASEAPPS=5' "vendor base-set apps (rg/jq/curl/tmux/bat run)" "$deadline"
# Box D / B42: Go (micro) + Rust (starship) apps run — no nested-epoll spin.
# BACKGROUND them (an unkillable-spin app would block a foreground `timeout`,
# and arm TCG is slow), then count which produced output. Computed marker
# GOAPPS=$M is output-only (no echo false-match).
printf 'micro --version >/tmp/mv 2>&1 & starship --version >/tmp/sv 2>&1 & sleep 20; M=0; [ -s /tmp/mv ] && M=$((M+1)); [ -s /tmp/sv ] && M=$((M+1)); echo GOAPPS=$M\n' >&9
wait_for 'GOAPPS=2' "go/rust apps (micro+starship run)" "$deadline"
# Box C / B45: iproute2 `ip link` + `ip addr` dump cleanly (rtnetlink NLMSG_DONE
# carries the 4-byte err payload; header-only DONE → "Dump terminated"). Counts
# lo/eth0 links + the two seeded addrs; marker output-only (no echo false-match).
printf 'L=$(ip -o link 2>&1 | grep -cE ": (lo|eth0):"); A=$(ip -o addr 2>&1 | grep -cE "127.0.0.1/8 scope host lo|10.0.2.15/24 brd 10.0.2.255 scope global eth0"); echo IPDUMP_L=${L}_A=${A}\n' >&9
wait_for 'IPDUMP_L=2_A=2' "ip link + ip addr dump (rtnetlink)" "$deadline"

# Optional logout → getty-respawn check (CHECK_LOGOUT=1): exit the
# shell and confirm a fresh `oxide login:` prompt reappears (systemd
# Restart=always on console-getty.service). Count prompts so we don't
# re-match the first one.
if [ -n "${CHECK_LOGOUT:-}" ]; then
    before=$(grep -ac 'oxide login:' "$LOG" 2>/dev/null || echo 0)
    printf 'exit\n' >&9
    deadline2=$(( $(date +%s) + 60 ))
    while [ "$(date +%s)" -lt "$deadline2" ]; do
        now=$(grep -ac 'oxide login:' "$LOG" 2>/dev/null || echo 0)
        if [ "$now" -gt "$before" ]; then
            echo "boot-smoke-login: getty respawned after logout"
            break
        fi
        sleep 2
    done
    now=$(grep -ac 'oxide login:' "$LOG" 2>/dev/null || echo 0)
    if [ "$now" -le "$before" ]; then
        echo "boot-smoke-login: FAIL — getty did NOT respawn after logout" >&2
        tail -n 40 "$LOG" >&2
        exit 1
    fi
fi

elapsed=$(( $(date +%s) - (deadline - TIMEOUT) ))
echo "boot-smoke-login: PASS — $ARCH console login → shell → id in ${elapsed}s"
exit 0
