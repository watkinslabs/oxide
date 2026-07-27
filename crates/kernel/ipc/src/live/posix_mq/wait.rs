// Blocking edge of `mq_timedsend(2)`/`mq_timedreceive(2)` — Linux
// `ipc/mqueue.c` `prepare_timeout` (`:838-846`) and `wq_sleep` (`:708-752`).
//
// Split out of `posix_mq.rs` at the 500-line cap (`docs/08§7`). The pure
// decision rules live in the non-gated `crate::mqueue_wait`; this file owns
// only the user read and the clock.

use crate::mqueue_wait;

/// Linux `prepare_timeout` (`ipc/mqueue.c:838-846`) applied to the raw user
/// pointer, plus the absolute-deadline conversion `wq_sleep` waits on
/// (`mqueue.c:722-723`: `HRTIMER_MODE_ABS, CLOCK_REALTIME`).
///
/// Runs in the SYSCALL WRAPPER position — before the `mqdes` lookup — because
/// `SYSCALL_DEFINE5(mq_timedsend)` (`mqueue.c:1236-1244`) validates the
/// timespec before `do_mq_timedsend` reaches `fdget`, so a malformed timespec
/// beats EBADF. `Ok(None)` = NULL pointer = wait forever.
/// # C: O(1)
pub(super) fn mq_abs_deadline(abstime: u64) -> Result<Option<u64>, i64> {
    use syscall::errno::Errno;
    if abstime == 0 { return Ok(None); }
    if abstime >= hal::USER_VA_END { return Err(-(Errno::Efault.as_i32() as i64)); }
    // SAFETY: abstime validated below USER_VA_END; a user timespec is 2x i64
    // at +0/+8, read through the caller's active address space at CPL=0.
    let (sec, nsec) = unsafe {
        (core::ptr::read_unaligned(abstime as *const i64),
         core::ptr::read_unaligned((abstime + 8) as *const i64))
    };
    let target = mqueue_wait::prepare_timeout(sec, nsec)
        .map_err(|e| -(e.as_i32() as i64))?;
    // The timespec is absolute CLOCK_REALTIME; the wait list runs on the
    // monotonic clock, so rebase onto it.
    let now_real = mq_clock_realtime_ns();
    let now_mono = mq_clock_monotonic_ns();
    Ok(Some(if target <= now_real { now_mono } else { now_mono + (target - now_real) }))
}

/// # C: O(1)
pub(super) fn mq_clock_monotonic_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// # C: O(1)
pub(super) fn mq_clock_realtime_ns() -> u64 { timekeeper::realtime_ns() }

/// One `wq_sleep` iteration's terminal check (`ipc/mqueue.c:734-744`), shared
/// by send and receive so the signal-before-timeout order cannot drift.
/// `None` = park again.
/// # C: O(N_sig)
pub(super) fn mq_wait_verdict(deadline: Option<u64>) -> Option<i64> {
    let signalled = sched::live::deliverable_signals_self() != 0;
    let timed_out = deadline.map(|d| mq_clock_monotonic_ns() >= d).unwrap_or(false);
    mqueue_wait::wq_sleep_verdict(false, signalled, timed_out).to_return()
}
