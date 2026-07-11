// 013 rt_sigaction — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

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
    let sz     = args.a3;
    if sig == 0 || sig > 64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    if sz != 8 {
        return -(Errno::Einval.as_i32() as i64);
    }
    // Linux do_sigaction: SIGKILL/SIGSTOP are sig_kernel_only — installing
    // (act != NULL) a disposition for them is -EINVAL, so a program can
    // never catch/ignore them and make itself unkillable. Querying oldact
    // (act == NULL) is still allowed. Checked before oldact is written, as
    // in Linux. Pairs with the wait4 EINTR fix: SIGKILL must stay fatal.
    if act != 0 {
        use sched::live::sigpend::Signum;
        if sig == Signum::Sigkill.as_u8() as usize || sig == Signum::Sigstop.as_u8() as usize {
            return -(Errno::Einval.as_i32() as i64);
        }
    }
    let cur = match sched::live::current() {
        Some(c) => c, None => return 0,
    };
    let idx = sig - 1;
    // SAFETY: running task on this CPU; preempt-off; sole writer to sigactions slot per single-mutator invariant.
    let table = unsafe { &mut *cur.sigactions.get() };
    let prior = table[idx];
    if oldact != 0 {
        if let Err(rv) = validate_user_buf_writable(oldact, 32, 1) { return rv; }
        // SAFETY: oldact validated writable for the 32-byte sigaction result.
        unsafe {
            core::ptr::write_unaligned( oldact         as *mut u64, prior.handler);
            core::ptr::write_unaligned((oldact +   8)  as *mut u64, prior.flags);
            core::ptr::write_unaligned((oldact +  16)  as *mut u64, prior.restorer);
            core::ptr::write_unaligned((oldact +  24)  as *mut u64, prior.mask);
        }
    }
    if act != 0 {
        if let Err(rv) = validate_user_buf(act, 32, 1) { return rv; }
        // SAFETY: act validated readable for the 32-byte sigaction input.
        let (h, f, r, m) = unsafe { (
            core::ptr::read_unaligned( act         as *const u64),
            core::ptr::read_unaligned((act +   8)  as *const u64),
            core::ptr::read_unaligned((act +  16)  as *const u64),
            core::ptr::read_unaligned((act +  24)  as *const u64),
        ) };
        table[idx] = SaHandler { handler: h, flags: f, restorer: r, mask: m };
        debug_ssh! { crate::signal_trace::sigaction(cur.tid, sig as u64, h, f, r); }
    }
    0
}
