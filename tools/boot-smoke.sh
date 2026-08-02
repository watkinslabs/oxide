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
    # Same x86 GRUB path with xtask's default features. Same headless
    # capture + marker grep.
    grub) MAKE_TARGET=qemu-x86-grub ;;
    *)    usage ;;
esac
TIMEOUT="${2:-${SMOKE_TIMEOUT:-600}}"

# Vendor preflight. `vendor/` holds fetched, gitignored boot artifacts, so a
# fresh feature worktree has none — and an arm boot then fails on missing
# arm64-efi GRUB modules, which reads as a kernel fault but is not one. Five
# separate lanes lost an ARM smoke to this and hand-symlinked from the main
# tree. Fetch instead: fetch-vendor.sh restores firmware from the shared cache
# and delegates the GRUB modules to fetch-grub.sh.
SMOKE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ ! -d "$SMOKE_ROOT/vendor/grub/arm64-efi" ] || [ ! -f "$SMOKE_ROOT/vendor/firmware/ovmf-aarch64.fd" ]; then
    echo "boot-smoke: vendor/ incomplete in this tree — running tools/fetch-vendor.sh" >&2
    if ! sh "$SMOKE_ROOT/tools/fetch-vendor.sh" >&2; then
        echo "boot-smoke: vendor fetch FAILED — boot would fail on missing boot artifacts, not on kernel code" >&2
        exit 2
    fi
fi

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

# ...but the passive marker CANNOT be the only proof, because whether it is
# printed at all is the IMAGE's decision, not the kernel's. Measured on a
# healthy boot: systemd's status messages reach the serial line until journald
# starts at t=6.4s, and after `Received client request to flush runtime
# journal.` the serial console is SILENT for the next 547 seconds while the
# guest boots all the way to a GNOME session. `basic.target` is activated in
# that silent window, so the marker never appears and the gate times out on a
# kernel that is completely healthy. Enabling `debug-boot` does not change it
# (measured): the missing line is userspace's, not klog's.
#
# So the gate ALSO asks the guest a question and waits for its answer. The
# serial line already has a writable FIFO ($SYSRQ_WFD, used for the sysrq RX
# probe below) and the boot command line already carries
# `systemd.debug_shell=ttyS0`, so typing a shell command and matching its
# output proves — with no dependence on any log routing — that init ran, that
# a service started, that fork/exec works, and that the tty carries bytes in
# BOTH directions. A boot that reaches a desktop always answers it; a boot
# whose userspace is broken cannot.
#
# Either proof passes the attempt. Set SMOKE_ALIVE_PROBE='' to require the
# passive marker alone (a profile with no debug shell), or override the
# command with SMOKE_ALIVE_CMD.
ALIVE_PROBE="${SMOKE_ALIVE_PROBE-1}"
# The nonce is SPLIT BY QUOTES in the command and whole only in the OUTPUT, so
# the guest's echo of what we typed can never match it — only a shell that
# actually evaluated the line can produce it. That makes the probe proof of
# evaluation rather than of byte-mirroring, and it removes the need for a `^`
# anchor: the reply carries a bracketed-paste escape prefix, so an anchored
# match silently never fires (measured — the first version of this probe was
# answered correctly and still failed to match).
# The serial echo path is known to duplicate a character occasionally; a
# corrupted typing simply fails to match and the next cycle retypes it.
ALIVE_NONCE="OXIDE-ALIVE-OK"
ALIVE_CMD="${SMOKE_ALIVE_CMD:-echo OXIDE-AL\"IVE\"-OK}"
ALIVE_MARKER="${SMOKE_ALIVE_MARKER:-$ALIVE_NONCE}"

# Failure marker: an unrecoverable kernel fault. The boot is dead the moment this
# appears — the fault handler parks the PE and nothing further will be printed, so
# waiting out the remaining timeout gains nothing and costs a pegged core per
# attempt (a TCG arm boot that faulted at 11s used to burn the full 600s x 3).
# Fail the attempt immediately and print the fault instead. Override/disable with
# SMOKE_FAIL_MARKER='' if a profile legitimately expects a recoverable oops.
# Markers that mean "this boot is dead, stop waiting". Extended-regex,
# matched with grep -aE so binary serial bytes cannot silence it:
#   [FAULT]    unrecoverable fault oops
#   [BADSTACK] exception entry with SP outside the current kernel stack; the
#              handler PARKS that CPU, so without this the run burns the whole
#              timeout with a wedged guest instead of failing in seconds
#   [BUG]      scheduling while atomic (sched refused to switch)
FAIL_MARKER="${SMOKE_FAIL_MARKER-\[FAULT\]|\[BADSTACK\]|\[BUG\]}"

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

# QEMU image the boot will open, per architecture. Globbed over the build
# namespaces because this run does not choose which one `make` will use.
case "$ARCH" in
    arm) IMG_GLOB="$SMOKE_ROOT/target/builds/"'*'"/root-aarch64.img" ;;
    *)   IMG_GLOB="$SMOKE_ROOT/target/builds/"'*'"/root-x86_64.img" ;;
esac

# Reap a QEMU left holding THIS TREE'"'"'S boot image.
#
# A smoke that is killed (a harness timeout, a cancelled run) can leave its
# QEMU alive, and it keeps the image open. The next boot then dies with
# `Is another process using the image [...]` and writes a log containing ZERO
# kernel output — which reads exactly like a boot failure and is not one. That
# has already produced retracted before/after claims.
#
# The image path is the discriminator, and it is safe precisely because it is
# specific: `$SMOKE_ROOT` is this worktree, so a QEMU holding it cannot be
# another lane'"'"'s live boot, which runs out of a different tree. A blanket
# `pkill qemu-system` would kill those, so it is never used. Anything that is
# not a `qemu-system-*` holding one of OUR images is left strictly alone.
reap_stale_image_holders() {
    local img pid exe found=0
    for img in $IMG_GLOB; do
        [ -e "$img" ] || continue
        for fd in /proc/[0-9]*/fd/*; do
            [ -e "$fd" ] || continue
            [ "$(readlink -f "$fd" 2>/dev/null)" = "$img" ] || continue
            pid="${fd#/proc/}"; pid="${pid%%/*}"
            exe="$(basename "$(readlink -f "/proc/$pid/exe" 2>/dev/null)" 2>/dev/null || true)"
            case "$exe" in qemu-system-*) ;; *) continue ;; esac
            echo "boot-smoke: reaping stale $exe pid=$pid still holding $img" >&2
            echo "boot-smoke:   (a previous smoke was killed without releasing it; NOT a kernel failure)" >&2
            kill -TERM "$pid" 2>/dev/null || true
            found=1
        done
    done
    [ "$found" -eq 0 ] && return 0
    sleep 2
    for img in $IMG_GLOB; do
        [ -e "$img" ] || continue
        for fd in /proc/[0-9]*/fd/*; do
            [ -e "$fd" ] || continue
            [ "$(readlink -f "$fd" 2>/dev/null)" = "$img" ] || continue
            pid="${fd#/proc/}"; pid="${pid%%/*}"
            exe="$(basename "$(readlink -f "/proc/$pid/exe" 2>/dev/null)" 2>/dev/null || true)"
            case "$exe" in qemu-system-*) ;; *) continue ;; esac
            kill -KILL "$pid" 2>/dev/null || true
        done
    done
    return 0
}

# Headless + no-stdin: feed /dev/null so qemu's stdio chardev
# doesn't try to read from CI's missing TTY.
#
# Both arches default to SMP=2. The old arm SMP=1 default was there for a
# data-abort ~11s into an SMP=2 boot; that is fixed and three consecutive arm
# SMP=2 boots now reach basic.target in 68-88s with real work on both CPUs.
# Gating arm at one CPU is worse than the boot cost: an SMP defect cannot
# reproduce in a uniprocessor gate, which is exactly how the secondary CPU
# came to run nothing but its idle task for an entire release. Override with
# OXIDE_SMP=N.
OXIDE_SMP="${OXIDE_SMP:-2}"


# On timeout, ask the wedged kernel to self-report before we kill it:
# feed the serial-sysrq sequence (`<NUL> t` = task dump, `<NUL> w` =
# current/switch summary, `<NUL> c` = per-CPU heartbeat) into qemu's stdin FIFO.
# UART RX is interrupt-driven and a parked late-boot wedge still takes
# interrupts, so the drv-serial
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

# Serial RX gate. Booting proves the console TX path; it proves nothing about
# RX, and an unreachable RX path is invisible to every other marker in this
# script — an interrupt that never reaches the dispatcher looks exactly like a
# quiet console. It stayed broken on one arch for months precisely because
# nothing typed at it.
#
# The probe is the serial-sysrq unknown-key sequence (<NUL> then '?'), because
# it exercises the whole RX chain — UART FIFO, interrupt delivery, driver
# drain, the drv-serial prefilter — inside the kernel, with no getty, shell, or
# userspace of any kind involved. The kernel answers with its sysrq key list.
# Set SMOKE_RX_MARKER='' to skip (e.g. a profile built without the diag).
RX_MARKER="${SMOKE_RX_MARKER-\[sysrq\] keys:}"
RX_TIMEOUT="${SMOKE_RX_TIMEOUT:-30}"

check_serial_rx() {
    [ -n "$RX_MARKER" ] || return 0
    if [ -z "${SYSRQ_WFD:-}" ]; then
        echo "boot-smoke: no writable serial FIFO — cannot verify serial RX" >&2
        return 1
    fi
    echo "boot-smoke: probing serial RX (<NUL>? -> '$RX_MARKER')"
    local rx_deadline
    rx_deadline=$(( $(date +%s) + RX_TIMEOUT ))
    while [ "$(date +%s)" -lt "$rx_deadline" ]; do
        printf '\000?' >&"$SYSRQ_WFD" 2>/dev/null || true
        sleep 2
        if grep -qaE "$RX_MARKER" "$LOG" 2>/dev/null; then
            echo "boot-smoke: serial RX OK — guest answered the typed sysrq probe"
            return 0
        fi
    done
    echo "boot-smoke: FAIL — $ARCH booted but typed serial input never reached the kernel" >&2
    echo "boot-smoke: (nothing matched '$RX_MARKER' within ${RX_TIMEOUT}s of typing)" >&2
    return 1
}

# Type a command at the guest's serial debug shell and report whether its
# output came back. Called once per poll cycle; each call types the command
# again, so a shell that starts late (or a typing corrupted by the known serial
# echo defect) is simply retried on the next cycle rather than failing the run.
#
# Cheap by construction: one short write per 2s cycle, and the match is the
# same `grep` over the same log the passive marker uses. # Returns 0 once the
# guest has answered.
probe_userspace_alive() {
    [ -n "$ALIVE_PROBE" ] || return 1
    [ -n "${SYSRQ_WFD:-}" ] || return 1
    # Nothing to talk to until the kernel has handed off to userspace; typing
    # into the kernel's own console before that just adds noise to the log.
    grep -qa '^\[[0-9]' "$LOG" 2>/dev/null || return 1
    printf '%s\n' "$ALIVE_CMD" >&"$SYSRQ_WFD" 2>/dev/null || return 1
    grep -qaE "$ALIVE_MARKER" "$LOG" 2>/dev/null
}

# Run one boot; return 0 if the guest proves itself alive within TIMEOUT.
attempt_boot() {
    # Before anything opens the image: release it if a killed predecessor is
    # still holding it, or this attempt fails with no kernel output at all.
    reap_stale_image_holders
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
        if [ -n "$FAIL_MARKER" ] && grep -qaE "$FAIL_MARKER" "$LOG" 2>/dev/null; then
            local elapsed=$(( $(date +%s) - (deadline - TIMEOUT) ))
            echo "boot-smoke: attempt $1 — KERNEL FAULT after ${elapsed}s ('$FAIL_MARKER'); boot is dead, not waiting out the timeout" >&2
            echo "------ fault + 20 lines of context ------" >&2
            grep -aE -B12 -A8 "$FAIL_MARKER" "$LOG" 2>/dev/null | head -n 40 >&2
            keep_log_copy "$1" "fault"
            close_sysrq
            return 1
        fi
        # Ask the guest whether its userspace is alive, once the kernel has
        # printed enough that init could plausibly have run. Typing costs
        # nothing on a boot that is going to print the passive marker anyway.
        local proof=""
        if grep -qF "$MARKER" "$LOG" 2>/dev/null; then
            proof="marker '$MARKER'"
        elif probe_userspace_alive; then
            proof="userspace answered '$ALIVE_CMD' on serial"
        fi
        if [ -n "$proof" ]; then
            local elapsed=$(( $(date +%s) - (deadline - TIMEOUT) ))
            echo "boot-smoke: $ARCH proved alive by $proof in ${elapsed}s (attempt $1)"
            if ! check_serial_rx; then
                keep_log_copy "$1" "no-serial-rx"
                close_sysrq
                return 1
            fi
            echo "boot-smoke: PASS — $ARCH proved alive by $proof in ${elapsed}s (attempt $1)"
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

# A failed attempt whose log holds NO kernel output never booted, so it says
# nothing about the kernel. Name that out loud: the two logs look identical
# otherwise, and reading one as a boot failure is how this cost a retraction.
diagnose_empty_log() {
    local lines
    lines="$(grep -c '"'"'^\[[0-9]'"'"' "$LOG" 2>/dev/null || echo 0)"
    [ "$lines" -gt 0 ] && return 0
    echo "boot-smoke: attempt $1 produced ZERO kernel output lines — the kernel never ran." >&2
    echo "boot-smoke:   This is a harness/build/image-lock failure, NOT a kernel failure." >&2
    echo "boot-smoke:   Check the log for an image lock, a build error, or a GRUB stall." >&2
}

a=1
while [ "$a" -le "$ATTEMPTS" ]; do
    if attempt_boot "$a"; then
        [ "$a" -gt 1 ] && echo "boot-smoke: NOTE — passed on retry $a (SMP late-boot flake; see tools/boot-smoke.sh)" >&2
        exit 0
    fi
    kill_boot
    diagnose_empty_log "$a"
    keep_log_copy "$a" "post-fail"
    rm -f "$LOG"
    a=$(( a + 1 ))
done

echo "boot-smoke: FAIL — $ARCH did not reach login in $ATTEMPTS attempts" >&2
exit 1
