// 038 setitimer — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_setitimer(which, new, old)` — slot 38. ITIMER_REAL only.
/// new = `struct itimerval { it_interval: timeval, it_value: timeval }`.
/// # C: O(1)
pub fn sys_setitimer(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use hal::TimerOps;
    const ITIMER_REAL: u64 = 0;
    let which = args.a0;
    let new = args.a1;
    let old = args.a2;
    if which != ITIMER_REAL { return 0; } // VIRTUAL/PROF accept-and-ignore
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    let now = {
        #[cfg(target_arch = "x86_64")] { hal_x86_64::X86TimerOps::monotonic_ns().0 }
        #[cfg(target_arch = "aarch64")] { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    };
    if old != 0 && old < hal::USER_VA_END {
        // Render the previous interval + remaining time into user `old`.
        let prev_int = cur.alarm_interval_ns.load(Ordering::Acquire);
        let prev_dl  = cur.alarm_ns.load(Ordering::Acquire);
        let remain   = if prev_dl > now { prev_dl - now } else { 0 };
        let (i_s, i_us) = sched::clock::ns_to_timeval(prev_int);
        let (r_s, r_us) = sched::clock::ns_to_timeval(remain);
        // SAFETY: old validated < USER_VA_END; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile( old        as *mut u64, i_s);
            core::ptr::write_volatile((old +  8)  as *mut u64, i_us);
            core::ptr::write_volatile((old + 16)  as *mut u64, r_s);
            core::ptr::write_volatile((old + 24)  as *mut u64, r_us);
        }
    }
    if new != 0 && new < hal::USER_VA_END {
        // SAFETY: new validated; CPL=0 reads through caller's AS.
        let (i_s, i_us, v_s, v_us) = unsafe {
            let a = core::ptr::read_volatile( new        as *const u64);
            let b = core::ptr::read_volatile((new +  8)  as *const u64);
            let c = core::ptr::read_volatile((new + 16)  as *const u64);
            let d = core::ptr::read_volatile((new + 24)  as *const u64);
            (a, b, c, d)
        };
        let interval_ns = i_s.saturating_mul(1_000_000_000).saturating_add(i_us.saturating_mul(1000));
        let value_ns    = v_s.saturating_mul(1_000_000_000).saturating_add(v_us.saturating_mul(1000));
        cur.alarm_interval_ns.store(interval_ns, Ordering::Release);
        cur.alarm_ns.store(if value_ns == 0 { 0 } else { now.saturating_add(value_ns) }, Ordering::Release);
    }
    0
}
