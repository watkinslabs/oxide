// Blocking edge of `mq_timedsend(2)`/`mq_timedreceive(2)`: timeout parsing
// and the parked-wait terminal check.
//
// Split out of `posix_mq.rs` at the 500-line cap (`docs/08§7`). The pure
// decision rules live in the non-gated `crate::mqueue_wait`; this file owns
// only the user read and the clock.

use crate::mqueue_wait;

/// Timeout validation applied to the raw user
/// pointer, plus the absolute-deadline conversion the wait loop waits on
/// (`CLOCK_REALTIME`, absolute mode).
///
/// Runs in the SYSCALL WRAPPER position — before the `mqdes` lookup — because
/// the timespec is validated before the descriptor is fetched, so a
/// malformed timespec beats EBADF. `Ok(None)` = NULL pointer = wait forever.
/// # C: O(1)
pub(super) fn mq_abs_deadline(abstime: u64) -> Result<Option<u64>, i64> {
    use syscall::errno::Errno;
    if abstime == 0 { return Ok(None); }
    // `get_timespec64` copies BOTH words through the exception table, so the
    // whole struct has to be reachable — not merely its first byte — and an
    // in-range address with nothing mapped under it is EFAULT.
    let Ok((sec, nsec)) = crate::useraccess::read_timespec(abstime) else {
        return Err(-(Errno::Efault.as_i32() as i64));
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

/// One parked-wait iteration's terminal check, shared
/// by send and receive so the signal-before-timeout order cannot drift.
/// `None` = park again.
/// # C: O(N_sig)
pub(super) fn mq_wait_verdict(deadline: Option<u64>) -> Option<i64> {
    let signalled = sched::live::interruptible_work_pending_self();
    let timed_out = deadline.map(|d| mq_clock_monotonic_ns() >= d).unwrap_or(false);
    mqueue_wait::wq_sleep_verdict(false, signalled, timed_out).to_return()
}
