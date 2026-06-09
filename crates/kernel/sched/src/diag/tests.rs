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
