// 014 rt_sigprocmask — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_rt_sigprocmask(how, set, oldset, sz)` — slot 14.
/// # C: O(1)
pub fn sys_rt_sigprocmask(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    const SIG_BLOCK:   u64 = 0;
    const SIG_UNBLOCK: u64 = 1;
    const SIG_SETMASK: u64 = 2;
    let how    = args.a0;
    let set    = args.a1;
    let oldset = args.a2;
    let sz     = args.a3;
    if sz != 8 { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return 0,
    };
    let prior = cur.sigmask.load(Ordering::Acquire);
    if oldset != 0 && oldset < hal::USER_VA_END {
        // SAFETY: oldset validated < USER_VA_END; CPL=0 writes through caller's AS.
        unsafe { core::ptr::write_volatile(oldset as *mut u64, prior); }
    }
    if set == 0 { return 0; }
    if set >= hal::USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    // SAFETY: set validated < USER_VA_END; CPL=0 reads through caller's AS.
    let new_set = unsafe { core::ptr::read_volatile(set as *const u64) };
    let new_mask = match how {
        SIG_BLOCK   => prior | new_set,
        SIG_UNBLOCK => prior & !new_set,
        SIG_SETMASK => new_set,
        _           => return -(Errno::Einval.as_i32() as i64),
    };
    let new_mask = new_mask & !(1u64 << 8) & !(1u64 << 18);
    cur.sigmask.store(new_mask, Ordering::Release);
    debug_ssh! { crate::signal_trace::sigprocmask(cur.tid, how, prior, new_mask); }
    0
}
