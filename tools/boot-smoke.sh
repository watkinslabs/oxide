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
    x86)  MAKE_TARGET=qemu-x86 ;;
    arm)  MAKE_TARGET=qemu-arm ;;
    # GRUB self-bootstrap path (F372): multiboot2-loads the kernel via a
    # GRUB ISO instead of Limine. Same headless capture + marker grep.
    grub) MAKE_TARGET=qemu-x86-grub ;;
    *)    usage ;;
esac
TIMEOUT="${2:-${SMOKE_TIMEOUT:-600}}"

# Serial marker signalling success. The quick-boot root is now a glibc
# systemd image (images repo), which logs to serial (journald
# forward_to_console) and boots to gdm on the framebuffer — it does NOT
# print a serial `oxide login:`. `Reached target basic.target` proves the
# glibc userspace + systemd came up (sysinit/sockets/timers done, before
# any greeter), which is what this gate exists to catch (ABI/syscall-table/
# arch-routing breaks fault long before basic.target). Override e.g.
# SMOKE_MARKER='oxide login:' for a serial-getty profile, or 'MB2' for a
# GRUB bring-up milestone.
MARKER="${SMOKE_MARKER:-Reached target basic.target}"

# Failure marker: an unrecoverable kernel fault. The boot is dead the moment this
# appears — the fault handler parks the PE and nothing further will be printed, so
# waiting out the remaining timeout gains nothing and costs a pegged core per
# attempt (a TCG arm boot that faulted at 11s used to burn the full 600s x 3).
# Fail the attempt immediately and print the fault instead. Override/disable with
# SMOKE_FAIL_MARKER='' if a profile legitimately expects a recoverable oops.
FAIL_MARKER="${SMOKE_FAIL_MARKER-[FAULT]}"

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
# SMOKE_KEEP_LOG_DIR=<dir>: copy every attempt's serial log into this
# directory as <arch>-attempt-<n>-<status>.log.
keep_log_copy() {
    local attempt="$1"
    local status="$2"
    [ -s "$LOG" ] || return 0
    if [ -n "${SMOKE_KEEP_LOG:-}" ]; then
        cp "$LOG" "$SMOKE_KEEP_LOG" 2>/dev/null || true
    fi
    if [ -n "${SMOKE_KEEP_LOG_DIR:-}" ]; then
        mkdir -p "$SMOKE_KEEP_LOG_DIR" 2>/dev/null || true
        cp "$LOG" "$SMOKE_KEEP_LOG_DIR/${ARCH}-attempt-${attempt}-${status}.log" 2>/dev/null || true
    fi
}

cleanup() {
    kill_boot
    [ -n "$LOG" ] && keep_log_copy "cleanup" "last"
    rm -f "$LOG" "$PIDFILE"
}
trap cleanup EXIT

# Headless + no-stdin: feed /dev/null so qemu's stdio chardev
# doesn't try to read from CI's missing TTY.
#
# SMP per arch, both -smp 2 to exercise the AP bring-up + per-CPU paths
# every push. arm SMP=2 now boots → systemd → login (#1564 fixed the
# AttrIdx-Device page-attr bug + #1552 PSCI AP bring-up). Note arm -smp 2
# under single-threaded TCG ~halves throughput (emulated idle AP), so the
# arm boot budget is larger. Override with OXIDE_SMP=N.
case "$ARCH" in
    arm) OXIDE_SMP="${OXIDE_SMP:-2}" ;;
    *)   OXIDE_SMP="${OXIDE_SMP:-2}" ;;
esac

# On timeout, ask the wedged kernel to self-report before we kill it:
# feed the serial-sysrq sequence (`<NUL> t` = task dump, `<NUL> w` =
# current/switch summary, `<NUL> c` = per-CPU heartbeat) into qemu's stdin FIFO. The guest's timer tick
# polls the UART RX even in a parked late-boot wedge, so the drv-serial
# prefilter fires and the (default-on) `debug-watchdog` dump lands in the
# log — turning an opaque "did not reach login" into a task-state dump
# (who's Runnable/Sleeping, last syscall) for the SMP late-boot race.
inject_sysrq() {
    [ -n "${SYSRQ_WFD:-}" ] || return 0
    echo "boot-smoke: timeout — injecting serial-sysrq task/CPU dump (<NUL>t,<NUL>w,<NUL>c)" >&2
    printf '\000t' >&"$SYSRQ_WFD" 2>/dev/null || true
    sleep 3
    printf '\000w' >&"$SYSRQ_WFD" 2>/dev/null || true
    sleep 2
    printf '\000c' >&"$SYSRQ_WFD" 2>/dev/null || true
    sleep 2
}

# Run one boot; return 0 if `oxide login:` appears within TIMEOUT.
attempt_boot() {
    LOG="$(mktemp /tmp/oxide-boot-smoke-${ARCH}-XXXXXX.log)"
    echo "boot-smoke: arch=$ARCH attempt=$1/$ATTEMPTS timeout=${TIMEOUT}s log=$LOG"
    # Writable stdin: a FIFO held open by our own RDWR fd ($SYSRQ_WFD) so
    # it never EOFs and we can inject sysrq on timeout. Equivalent to the
    # old `< /dev/null` for a clean boot (no bytes sent until timeout).
    SYSRQ_FIFO="$(mktemp -u /tmp/oxide-smoke-sysrq-${ARCH}-XXXXXX.fifo)"
    mkfifo "$SYSRQ_FIFO" 2>/dev/null || SYSRQ_FIFO=""
    if [ -n "$SYSRQ_FIFO" ]; then
        exec {SYSRQ_WFD}<>"$SYSRQ_FIFO"
        OXIDE_QEMU_HEADLESS=1 setsid bash -c "exec make SMP='$OXIDE_SMP' '$MAKE_TARGET' > '$LOG' 2>&1 < '$SYSRQ_FIFO'" &
    else
        SYSRQ_WFD=""
        OXIDE_QEMU_HEADLESS=1 setsid bash -c "exec make SMP='$OXIDE_SMP' '$MAKE_TARGET' > '$LOG' 2>&1 < /dev/null" &
    fi
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
            keep_log_copy "$1" "qemu-exited"
            close_sysrq
            return 1
        fi
        if [ -n "$FAIL_MARKER" ] && grep -qF "$FAIL_MARKER" "$LOG" 2>/dev/null; then
            local elapsed=$(( $(date +%s) - (deadline - TIMEOUT) ))
            echo "boot-smoke: attempt $1 — KERNEL FAULT after ${elapsed}s ('$FAIL_MARKER'); boot is dead, not waiting out the timeout" >&2
            echo "------ fault + 20 lines of context ------" >&2
            grep -F -B12 -A8 "$FAIL_MARKER" "$LOG" 2>/dev/null | head -n 40 >&2
            keep_log_copy "$1" "fault"
            close_sysrq
            return 1
        fi
        if grep -qF "$MARKER" "$LOG" 2>/dev/null; then
            local elapsed=$(( $(date +%s) - (deadline - TIMEOUT) ))
            echo "boot-smoke: PASS — $ARCH reached marker '$MARKER' in ${elapsed}s (attempt $1)"
            keep_log_copy "$1" "pass"
            close_sysrq
            return 0
        fi
        sleep 2
    done
    echo "boot-smoke: attempt $1 — timeout after ${TIMEOUT}s without login marker" >&2
    inject_sysrq
    echo "------ last 80 lines of log (incl. sysrq dump if it landed) ------" >&2
    tail -n 80 "$LOG" >&2
    keep_log_copy "$1" "timeout"
    close_sysrq
    return 1
}

# Close + remove the sysrq FIFO between attempts.
close_sysrq() {
    if [ -n "${SYSRQ_WFD:-}" ]; then exec {SYSRQ_WFD}>&- 2>/dev/null || true; SYSRQ_WFD=""; fi
    [ -n "${SYSRQ_FIFO:-}" ] && rm -f "$SYSRQ_FIFO" 2>/dev/null || true
    SYSRQ_FIFO=""
}

a=1
while [ "$a" -le "$ATTEMPTS" ]; do
    if attempt_boot "$a"; then
        [ "$a" -gt 1 ] && echo "boot-smoke: NOTE — passed on retry $a (SMP late-boot flake; see tools/boot-smoke.sh)" >&2
        exit 0
    fi
    kill_boot
    keep_log_copy "$a" "post-fail"
    rm -f "$LOG"
    a=$(( a + 1 ))
done

echo "boot-smoke: FAIL — $ARCH did not reach login in $ATTEMPTS attempts" >&2
exit 1
