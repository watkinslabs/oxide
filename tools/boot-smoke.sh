#!/usr/bin/env bash
# Boot-smoke gate. Boots the kernel under qemu headless and waits
# for `oxide login:` on serial within $SMOKE_TIMEOUT seconds. Exit
# 0 on success, 1 on timeout, 2 on argument / build error.
#
# Usage:
#   tools/boot-smoke.sh x86            # default 600s timeout
#   tools/boot-smoke.sh arm 1200       # explicit timeout
#   SMOKE_TIMEOUT=1200 tools/boot-smoke.sh x86
#
# CI uses this as the PR-time gate; local devs can run it the same
# way. `make qemu-arm` exiting at login on a dev box (~30s) takes
# ~10-15min under TCG on a hosted runner — pick the timeout
# accordingly.
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
    # Default boot path = GRUB on both arches (F376). x86 multiboot2; arm
    # OVMF→GRUB→EFI-stub `linux`.
    x86)  MAKE_TARGET=qemu-x86 ;;
    arm)  MAKE_TARGET=qemu-arm ;;
    # Back-compat aliases for the GRUB path (== x86/arm now).
    grub) MAKE_TARGET=qemu-x86-grub ;;
    arm-grub) MAKE_TARGET=qemu-arm-grub ;;
    # Legacy Limine UEFI boot (kept until Limine is removed).
    x86-limine) MAKE_TARGET=qemu-x86-limine ;;
    arm-limine) MAKE_TARGET=qemu-arm-limine ;;
    # Limine-free aarch64 self-boot (F376): -kernel flat Image, no OVMF.
    arm-self) MAKE_TARGET=qemu-arm-self ;;
    *)    usage ;;
esac
TIMEOUT="${2:-${SMOKE_TIMEOUT:-600}}"

# Serial marker signalling success. Defaults to the login prompt (the
# real boot target); override e.g. SMOKE_MARKER='MB2' for incremental
# bring-up milestones on the GRUB path.
MARKER="${SMOKE_MARKER:-oxide login:}"

# Bounded retry. SMP=2 boot has a known intermittent late-boot timing
# race (~25%: reaches deep into rcS but the getty/login prompt doesn't
# land within the timeout) that always clears on a clean re-boot. Retry
# tolerates it WITHOUT hiding real regressions: a deterministic break
# (ABI/syscall-table/arch-routing — what this gate exists to catch)
# fails EVERY attempt, while the flake passes on a retry. Each attempt's
# outcome is logged so a worsening flake stays visible. Override count
# with OXIDE_SMOKE_ATTEMPTS (default 3).
ATTEMPTS="${OXIDE_SMOKE_ATTEMPTS:-3}"

LOG=""
PIDFILE="$(mktemp /tmp/oxide-boot-smoke-${ARCH}-XXXXXX.pid)"
kill_boot() {
    if [ -s "$PIDFILE" ]; then
        local pid
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        # `setsid` made the child a new process-group leader, so
        # `kill -- -PID` sends to the whole group (make → xtask →
        # qemu-system-*). Without the leading `-` we'd kill bash
        # but leave qemu running.
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "-$pid" 2>/dev/null || true
            sleep 1
            kill -KILL "-$pid" 2>/dev/null || true
        fi
        : > "$PIDFILE"
    fi
}
# SMOKE_KEEP_LOG=<path>: copy the last attempt's serial log there
# before cleanup so a failed boot can be inspected (the temp log is
# otherwise removed on exit).
cleanup() {
    kill_boot
    if [ -n "${SMOKE_KEEP_LOG:-}" ] && [ -s "$LOG" ]; then
        cp "$LOG" "$SMOKE_KEEP_LOG" 2>/dev/null || true
    fi
    rm -f "$LOG" "$PIDFILE"
}
trap cleanup EXIT

# Headless + no-stdin: feed /dev/null so qemu's stdio chardev
# doesn't try to read from CI's missing TTY.
#
# Boot -smp 2 on BOTH arches so AP bring-up + the periodic load balancer
# (`13§11`) are exercised every push: x86 via Limine SMP + LAPIC IPI,
# arm via Limine SMP (APs MMU-on at our entry, F327) + GIC SGI. Override
# with OXIDE_SMP=N.
# The Limine-free arm paths (GRUB EFI-stub + -kernel self-boot) have no
# bootloader to start APs and the kernel doesn't PSCI-CPU_ON them itself
# yet, so they are UP — default SMP=1. Everything else (x86 GRUB, all
# Limine paths) exercises SMP=2.
case "$ARCH" in
    arm|arm-grub|arm-self) OXIDE_SMP="${OXIDE_SMP:-1}" ;;
    *)                     OXIDE_SMP="${OXIDE_SMP:-2}" ;;
esac

# Run one boot; return 0 if `oxide login:` appears within TIMEOUT.
attempt_boot() {
    LOG="$(mktemp /tmp/oxide-boot-smoke-${ARCH}-XXXXXX.log)"
    echo "boot-smoke: arch=$ARCH attempt=$1/$ATTEMPTS timeout=${TIMEOUT}s log=$LOG"
    OXIDE_QEMU_HEADLESS=1 setsid bash -c "exec make SMP='$OXIDE_SMP' '$MAKE_TARGET' > '$LOG' 2>&1 < /dev/null" &
    echo $! > "$PIDFILE"
    local deadline
    deadline=$(( $(date +%s) + TIMEOUT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local pid
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "boot-smoke: attempt $1 — qemu exited before login marker" >&2
            echo "------ last 60 lines of log ------" >&2
            tail -n 60 "$LOG" >&2
            return 1
        fi
        if grep -qF "$MARKER" "$LOG" 2>/dev/null; then
            local elapsed=$(( $(date +%s) - (deadline - TIMEOUT) ))
            echo "boot-smoke: PASS — $ARCH reached marker '$MARKER' in ${elapsed}s (attempt $1)"
            return 0
        fi
        sleep 2
    done
    echo "boot-smoke: attempt $1 — timeout after ${TIMEOUT}s without login marker" >&2
    echo "------ last 80 lines of log ------" >&2
    tail -n 80 "$LOG" >&2
    return 1
}

a=1
while [ "$a" -le "$ATTEMPTS" ]; do
    if attempt_boot "$a"; then
        [ "$a" -gt 1 ] && echo "boot-smoke: NOTE — passed on retry $a (SMP late-boot flake; see tools/boot-smoke.sh)" >&2
        exit 0
    fi
    kill_boot
    if [ -n "${SMOKE_KEEP_LOG:-}" ] && [ -s "$LOG" ]; then
        cp "$LOG" "$SMOKE_KEEP_LOG" 2>/dev/null || true
    fi
    rm -f "$LOG"
    a=$(( a + 1 ))
done

echo "boot-smoke: FAIL — $ARCH did not reach login in $ATTEMPTS attempts" >&2
exit 1
