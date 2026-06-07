// 127 rt_sigpending — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_rt_sigpending(set, sz)` — slot 127.
/// # C: O(1)
pub fn sys_rt_sigpending(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let set = args.a0;
    let sz  = args.a1;
    if sz != 8 { return -(Errno::Einval.as_i32() as i64); }
    if set == 0 || set >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    let p = cur.sigpending.load(Ordering::Acquire);
    // SAFETY: set validated < USER_VA_END; CPL=0 writes through caller's AS.
    unsafe { core::ptr::write_volatile(set as *mut u64, p); }
    0
}
