// 014 rt_sigprocmask — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};
use crate::user_mem as um;

const KERNEL_SIGSET_SIZE: u64 = 8;
const USER_SIGSET_ALIGN: u64 = 1;

/// `sys_rt_sigprocmask(how, set, oldset, sz)` — slot 14.
/// # C: O(1)
pub fn sys_rt_sigprocmask(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let how    = args.a0;
    let set    = args.a1;
    let oldset = args.a2;
    let sz     = args.a3;
    if sz != KERNEL_SIGSET_SIZE { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return 0,
    };
    let new_set = if set != 0 {
        if let Err(rv) = validate_user_buf(set, KERNEL_SIGSET_SIZE, USER_SIGSET_ALIGN) { return rv; }
        Some(match um::get_u64(set) { Ok(v) => v, Err(_) => return um::EFAULT })
    } else { None };
    let prior = match cur.rt_sigprocmask(how, new_set) {
        Ok(mask) => mask,
        Err(()) => return -(Errno::Einval.as_i32() as i64),
    };
    if oldset != 0 {
        if let Err(rv) = validate_user_buf_writable(oldset, KERNEL_SIGSET_SIZE, USER_SIGSET_ALIGN) { return rv; }
        if um::put_u64(oldset, prior).is_err() { return um::EFAULT; }
    }
    debug_ssh! {
        let applied = cur.sigmask.load(core::sync::atomic::Ordering::Acquire);
        crate::signal_trace::sigprocmask(cur.tid, how, prior, applied);
    }
    0
}
