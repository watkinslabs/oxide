// 037 alarm — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_alarm(seconds)` — slot 37. Sets a per-task SIGALRM
/// deadline at monotonic_ns + seconds*1e9. Returns the seconds
/// remaining on the previous alarm, or 0 if none.
/// # C: O(1)
pub fn sys_alarm(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use hal::TimerOps;
    let secs = args.a0;
    let now = {
        #[cfg(target_arch = "x86_64")]
        { hal_x86_64::X86TimerOps::monotonic_ns().0 }
        #[cfg(target_arch = "aarch64")]
        { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    };
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    let prev = cur.alarm_ns.load(Ordering::Acquire);
    let prev_remaining = if prev > now { (prev - now) / 1_000_000_000 } else { 0 };
    let new = if secs == 0 { 0 } else { now.saturating_add(secs.saturating_mul(1_000_000_000)) };
    cur.alarm_ns.store(new, Ordering::Release);
    prev_remaining as i64
}
