// 013 rt_sigaction — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_rt_sigaction(sig, act, oldact, sz)` — slot 13. Reads + stores
/// the user-supplied `struct sigaction` into the per-task `sigactions`
/// array; writes the prior to `oldact` if non-NULL. Layout:
///   { sa_handler: u64, sa_flags: u64, sa_restorer: u64, sa_mask: u64 }
/// # C: O(1)
pub fn sys_rt_sigaction(args: &SyscallArgs) -> i64 {
    use sched::SaHandler;
    use syscall::errno::Errno;
    let sig = args.a0 as usize;
    let act    = args.a1;
    let oldact = args.a2;
    let _sz    = args.a3;
    if sig == 0 || sig > 64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match sched::live::current() {
        Some(c) => c, None => return 0,
    };
    let idx = sig - 1;
    // SAFETY: running task on this CPU; preempt-off; sole writer to sigactions slot per single-mutator invariant.
    let table = unsafe { &mut *cur.sigactions.get() };
    let prior = table[idx];
    if oldact != 0 && oldact < hal::USER_VA_END {
        // SAFETY: oldact validated < USER_VA_END; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile( oldact         as *mut u64, prior.handler);
            core::ptr::write_volatile((oldact +   8)  as *mut u64, prior.flags);
            core::ptr::write_volatile((oldact +  16)  as *mut u64, prior.restorer);
            core::ptr::write_volatile((oldact +  24)  as *mut u64, prior.mask);
        }
    }
    if act != 0 {
        if act >= hal::USER_VA_END {
            return -(Errno::Efault.as_i32() as i64);
        }
        // SAFETY: act validated < USER_VA_END; user page mapped via active CR3 (caller's AS); CPL=0 reads through user mapping per `15§3`; 8-byte aligned per Linux ABI.
        let (h, f, r, m) = unsafe { (
            core::ptr::read_volatile( act         as *const u64),
            core::ptr::read_volatile((act +   8)  as *const u64),
            core::ptr::read_volatile((act +  16)  as *const u64),
            core::ptr::read_volatile((act +  24)  as *const u64),
        ) };
        table[idx] = SaHandler { handler: h, flags: f, restorer: r, mask: m };
        debug_ssh! { crate::signal_trace::sigaction(cur.tid, sig as u64, h, f, r); }
    }
    0
}
