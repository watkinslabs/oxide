// 014 rt_sigprocmask — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

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
    if set != 0 {
        if let Err(rv) = validate_user_buf(set, 8, 8) { return rv; }
        // SAFETY: set validated as a readable 8-byte user sigset_t.
        let new_set = unsafe { core::ptr::read_volatile(set as *const u64) };
        let mut new_mask = match how {
            SIG_BLOCK   => prior | new_set,
            SIG_UNBLOCK => prior & !new_set,
            SIG_SETMASK => new_set,
            _           => return -(Errno::Einval.as_i32() as i64),
        };
        // signal(7): SIGKILL and SIGSTOP can never be blocked — strip them from
        // any new mask. Without this a task could mask SIGKILL and then wedge in
        // a blocking syscall (see the wait4 EINTR fix), unkillable.
        use sched::live::sigpend::Signum;
        new_mask &= !(Signum::Sigkill.bit() | Signum::Sigstop.bit());
        cur.sigmask.store(new_mask, Ordering::Release);
    }
    if oldset != 0 {
        if let Err(rv) = validate_user_buf_writable(oldset, 8, 8) { return rv; }
        // SAFETY: oldset validated as writable 8-byte user sigset_t storage.
        unsafe { core::ptr::write_volatile(oldset as *mut u64, prior); }
    }
    debug_ssh! {
        let applied = cur.sigmask.load(Ordering::Acquire);
        crate::signal_trace::sigprocmask(cur.tid, how, prior, applied);
    }
    0
}
