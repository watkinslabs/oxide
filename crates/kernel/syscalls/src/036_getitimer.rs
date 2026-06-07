// 036 getitimer — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_getitimer(which, curr)` — slot 36. Reports remaining +
/// interval for ITIMER_REAL.
/// # C: O(1)
pub fn sys_getitimer(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use hal::TimerOps;
    const ITIMER_REAL: u64 = 0;
    let which = args.a0;
    let curr = args.a1;
    if curr == 0 || curr >= hal::USER_VA_END { return 0; }
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    let now = {
        #[cfg(target_arch = "x86_64")] { hal_x86_64::X86TimerOps::monotonic_ns().0 }
        #[cfg(target_arch = "aarch64")] { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    };
    let (interval, remain) = if which == ITIMER_REAL {
        let i = cur.alarm_interval_ns.load(Ordering::Acquire);
        let dl = cur.alarm_ns.load(Ordering::Acquire);
        (i, if dl > now { dl - now } else { 0 })
    } else { (0, 0) };
    let (i_s, i_us) = sched::clock::ns_to_timeval(interval);
    let (r_s, r_us) = sched::clock::ns_to_timeval(remain);
    // SAFETY: curr validated < USER_VA_END; CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_volatile( curr       as *mut u64, i_s);
        core::ptr::write_volatile((curr +  8) as *mut u64, i_us);
        core::ptr::write_volatile((curr + 16) as *mut u64, r_s);
        core::ptr::write_volatile((curr + 24) as *mut u64, r_us);
    }
    0
}
