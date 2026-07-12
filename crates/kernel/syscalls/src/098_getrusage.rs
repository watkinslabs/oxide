// 098 getrusage — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_getrusage(who, usage)` — slot 98. ru_utime/ru_stime report the
/// calling task's tick-sampled user/kernel CPU time (RUSAGE_SELF/THREAD)
/// or the reaped children's cumulative user/kernel CPU time
/// (RUSAGE_CHILDREN); the 14 trailing counters (ru_maxrss …) stay zero.
/// # C: O(1)
pub fn sys_getrusage(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    const RUSAGE_CHILDREN: i32 = -1;
    const RUSAGE_SELF:     i32 = 0;
    const RUSAGE_THREAD:   i32 = 1;
    const RUSAGE_BYTES:    u64 = 144;
    let who = args.a0 as i32;
    let buf = args.a1;
    if who != RUSAGE_CHILDREN && who != RUSAGE_SELF && who != RUSAGE_THREAD { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(buf, RUSAGE_BYTES, 1) { return rv; }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let (utime_ns, stime_ns) = if who == RUSAGE_CHILDREN {
        (cur.cumulative_child_utime_ns.load(Ordering::Acquire),
         cur.cumulative_child_stime_ns.load(Ordering::Acquire))
    } else {
        (cur.utime_ns.load(Ordering::Acquire),
         cur.stime_ns.load(Ordering::Acquire))
    };
    let (u_sec, u_usec) = sched::clock::ns_to_timeval(utime_ns);
    let (s_sec, s_usec) = sched::clock::ns_to_timeval(stime_ns);
    // SAFETY: full rusage byte range validated writable; Linux copyout accepts unaligned storage.
    unsafe {
        core::ptr::write_unaligned( buf        as *mut u64, u_sec);   // ru_utime.tv_sec
        core::ptr::write_unaligned((buf + 8)   as *mut u64, u_usec);  // ru_utime.tv_usec
        core::ptr::write_unaligned((buf + 16)  as *mut u64, s_sec);   // ru_stime.tv_sec
        core::ptr::write_unaligned((buf + 24)  as *mut u64, s_usec);  // ru_stime.tv_usec
        for off in (32..RUSAGE_BYTES).step_by(8) {
            core::ptr::write_unaligned((buf + off) as *mut u64, 0);
        }
    }
    0
}
