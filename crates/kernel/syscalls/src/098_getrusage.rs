// 098 getrusage — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_getrusage(who, usage)` — slot 98. ru_utime reports
/// `monotonic_ns - spawn_ns` for the calling task; ru_stime + the
/// 14 trailing counters all zero.
/// # C: O(1)
pub fn sys_getrusage(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use hal::TimerOps;
    use syscall::errno::Errno;
    const RUSAGE_CHILDREN: i32 = -1;
    let who = args.a0 as i32;
    let buf = args.a1;
    if buf == 0 || buf >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let now = {
        #[cfg(target_arch = "x86_64")]
        { hal_x86_64::X86TimerOps::monotonic_ns().0 }
        #[cfg(target_arch = "aarch64")]
        { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    };
    let elapsed = if who == RUSAGE_CHILDREN {
        cur.cumulative_child_ns.load(Ordering::Acquire)
    } else {
        now.saturating_sub(cur.spawn_ns.load(Ordering::Acquire))
    };
    let (sec, usec) = sched::clock::ns_to_timeval(elapsed);
    // SAFETY: validated 144-byte user buf < USER_VA_END; CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_volatile( buf       as *mut u64, sec);
        core::ptr::write_volatile((buf + 8)  as *mut u64, usec);
        for off in (16..144u64).step_by(8) {
            core::ptr::write_volatile((buf + off) as *mut u64, 0);
        }
    }
    0
}
