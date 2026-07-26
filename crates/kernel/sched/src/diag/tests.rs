// Host tests for the pure diagnostic logic: the watchdog stall
// state machine and the allocation-free formatting helpers. The
// kernel glue (current_task / klog emit) is exercised live under qemu.

use super::*;

const STALL: u64 = STALL_NS;
const SEC: u64 = 1_000_000_000;

fn beat(tid: u32, runnable: bool, switches: u64, now_ns: u64) -> Beat {
    Beat { tid, runnable, switches, now_ns }
}

#[test]
fn idle_never_fires() {
    let mut w = WatchdogState::new();
    // CPU idle / task parked for a long time: never a lockup.
    for s in 0..60u64 {
        assert_eq!(w.step(beat(0, false, 0, s * SEC)), None);
    }
}

#[test]
fn runnable_stall_fires_once_at_threshold() {
    let mut w = WatchdogState::new();
    // tid 7 runnable, no switches, time advances.
    assert_eq!(w.step(beat(7, true, 0, 0)), None); // window opens
    assert_eq!(w.step(beat(7, true, 0, STALL - 1)), None); // not yet
    let fired = w.step(beat(7, true, 0, STALL));
    assert_eq!(fired, Some(STALL / SEC));
    // Latched: a further tick in the same stall does not re-fire.
    assert_eq!(w.step(beat(7, true, 0, STALL + 5 * SEC)), None);
}

#[test]
fn context_switch_resets_window() {
    let mut w = WatchdogState::new();
    w.step(beat(7, true, 0, 0));
    // A switch happened just before threshold → progress, reset.
    assert_eq!(w.step(beat(7, true, 1, STALL - 1)), None);
    // The clock keeps running but the window restarted at STALL-1, so
    // crossing requires another full STALL from there.
    assert_eq!(w.step(beat(7, true, 1, STALL)), None);
    assert_eq!(w.step(beat(7, true, 1, (STALL - 1) + STALL)), Some(STALL / SEC));
}

#[test]
fn tid_change_resets_window() {
    let mut w = WatchdogState::new();
    w.step(beat(7, true, 0, 0));
    // A different task is now on-CPU → forward progress.
    assert_eq!(w.step(beat(9, true, 0, STALL - 1)), None);
    // tid 9 must itself stall a full window to fire.
    assert_eq!(w.step(beat(9, true, 0, STALL)), None);
    assert_eq!(w.step(beat(9, true, 0, (STALL - 1) + STALL)), Some(STALL / SEC));
}

#[test]
fn becoming_idle_clears_latch_and_rearms() {
    let mut w = WatchdogState::new();
    w.step(beat(7, true, 0, 0));
    assert_eq!(w.step(beat(7, true, 0, STALL)), Some(STALL / SEC));
    // Task parks (read blocks) → idle/healthy.
    assert_eq!(w.step(beat(7, false, 0, STALL + SEC)), None);
    // Same task wakes and stalls again → fires again (fresh window).
    assert_eq!(w.step(beat(7, true, 0, STALL + 2 * SEC)), None);
    assert_eq!(w.step(beat(7, true, 0, STALL + 2 * SEC + STALL)), Some(STALL / SEC));
}

#[test]
fn fmt_dec_tail_and_start() {
    let mut buf = [0u8; 20];
    let s = fmt_dec(0, &mut buf);
    assert_eq!(&buf[s..], b"0");
    let mut buf = [0u8; 20];
    let s = fmt_dec(12345, &mut buf);
    assert_eq!(&buf[s..], b"12345");
    let mut buf = [0u8; 20];
    let s = fmt_dec(u64::MAX, &mut buf);
    assert_eq!(&buf[s..], b"18446744073709551615");
}

#[test]
fn copy_into_truncates() {
    let mut dst = [b'.'; 4];
    assert_eq!(copy_into(&mut dst, b"ab"), 2);
    assert_eq!(&dst, b"ab..");
    let mut dst = [b'.'; 4];
    assert_eq!(copy_into(&mut dst, b"abcdef"), 4);
    assert_eq!(&dst, b"abcd");
}

#[test]
fn syscall_name_known_and_unknown() {
    use syscall::nrs::*;
    assert_eq!(syscall_name(NR_READ as u32), Some("read"));
    assert_eq!(syscall_name(NR_WAIT4 as u32), Some("wait4"));
    assert_eq!(syscall_name(NR_FUTEX as u32), Some("futex"));
    assert_eq!(syscall_name(0xDEAD), None);
    assert_eq!(syscall_name(u32::MAX), None);
}

// docs/15§ syscall diag: the table in `diag::syscall_names` is the FULL Linux
// x86_64 table, keyed off `syscall::nrs::NR_*` — not a hand-typed subset. This
// is the exact wedge-diagnosis sample from the boot-hang campaign: every
// number below used to hand-decode against nrs.rs on every task dump.
#[test]
fn syscall_name_covers_full_table_sample() {
    use syscall::nrs::*;
    assert_eq!(syscall_name(NR_READ as u32), Some("read"));
    assert_eq!(syscall_name(NR_WRITE as u32), Some("write"));
    assert_eq!(syscall_name(NR_CLOSE as u32), Some("close"));
    assert_eq!(syscall_name(NR_EXIT_GROUP as u32), Some("exit_group"));
    assert_eq!(syscall_name(NR_OPENAT as u32), Some("openat"));
    assert_eq!(syscall_name(NR_FUTEX as u32), Some("futex"));
    assert_eq!(syscall_name(NR_EPOLL_WAIT as u32), Some("epoll_wait"));
    assert_eq!(syscall_name(NR_ACCEPT4 as u32), Some("accept4"));
    assert_eq!(syscall_name(NR_RECVMSG as u32), Some("recvmsg"));
    assert_eq!(syscall_name(NR_RENAMEAT as u32), Some("renameat"));
}

// Same numbering serves both arches: the dispatcher remaps aarch64's
// arch-native syscall numbers to these x86_64-numbered dispatch keys
// (crates/kernel/syscalls/src/dispatch/core.rs, aarch64_nr_to_x86) before
// `note_syscall` ever stamps `last_syscall_nr`, so there is no separate
// aarch64 name table to keep in sync — this one table is authoritative on
// both arches.
#[test]
fn syscall_name_out_of_range_falls_back() {
    assert_eq!(syscall_name(0xFFFF_FFFE), None);
    assert_eq!(syscall_name(100_000), None);
}

// The table cannot silently disagree with nrs.rs: every NR_* constant we
// probe must resolve to a name derived from ITS OWN identifier, not a
// re-typed number. If a constant's value ever moves, this call site still
// resolves through the same identifier, so numeric drift is structurally
// impossible — only a renamed/removed constant could break this, and that
// fails the build, not this assertion.
#[test]
fn syscall_name_never_disagrees_with_nrs_self_check() {
    use syscall::nrs::*;
    for (nr, want) in [
        (NR_READ, "read"),
        (NR_WRITE, "write"),
        (NR_MMAP, "mmap"),
        (NR_CLONE, "clone"),
        (NR_EXECVE, "execve"),
        (NR_FUTEX, "futex"),
        (NR_OPENAT, "openat"),
        (NR_EPOLL_WAIT, "epoll_wait"),
        (NR_ACCEPT4, "accept4"),
        (NR_EXIT_GROUP, "exit_group"),
        (NR_PIDFD_OPEN, "pidfd_open"),
        (NR_CLONE3, "clone3"),
        (NR_RSEQ, "rseq"),
    ] {
        assert_eq!(syscall_name(nr as u32), Some(want));
    }
}
