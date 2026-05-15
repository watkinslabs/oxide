// sys_clock_nanosleep per docs/15§5. Extracted from proc.rs to
// keep that file under the 1000-line cap.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_clock_nanosleep(clk_id, flags, req, rem)` — slot 230.
/// TIMER_ABSTIME treats req as an absolute timestamp; otherwise
/// req is the relative sleep duration.
/// # C: O(1) + sleep cost
pub fn sys_clock_nanosleep(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    const TIMER_ABSTIME: u64 = 0x1;
    let flags = args.a1;
    let req   = args.a2;
    let rem   = args.a3;
    if req == 0 || req >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: req validated < USER_VA_END; struct timespec is 16 B; CPL=0 reads through caller's AS.
    let (secs, nsec) = unsafe {
        let s = core::ptr::read_volatile(req as *const i64);
        let n = core::ptr::read_volatile((req + 8) as *const i64);
        (s, n)
    };
    if secs < 0 || nsec < 0 || nsec >= 1_000_000_000 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let target_ns = (secs as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64);
    let rel_ns = if (flags & TIMER_ABSTIME) != 0 {
        let now = monotonic();
        if target_ns <= now { return 0; }
        target_ns - now
    } else {
        target_ns
    };
    let start = monotonic();
    let deadline = start.saturating_add(rel_ns);
    loop {
        if monotonic() >= deadline { break; }
        // SAFETY: process ctx; runqueue installed; preempt-off; voluntary tick_yield re-enters scheduler.
        unsafe { sched::live::tick_yield(); }
    }
    let _ = rem;
    0
}

#[inline]
fn monotonic() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}
