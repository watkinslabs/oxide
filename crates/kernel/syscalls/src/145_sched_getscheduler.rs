// 145 sched_getscheduler — one syscall, one file (docs/53 §0).
// Linux `sys_sched_getscheduler`: `pid < 0` → EINVAL, missing pid → ESRCH,
// otherwise `p->policy` with `SCHED_RESET_ON_FORK` ORed back in.
#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;
use syscall::{errno::Errno, SyscallArgs};
use crate::sched_policy;

/// `sys_sched_getscheduler(pid)` — slot 145. Returns the target's scheduling
/// policy (`SCHED_NORMAL`=0, `FIFO`=1, `RR`=2, `BATCH`=3, `IDLE`=5), ORed with
/// `SCHED_RESET_ON_FORK` when the flag is set. `pid==0` = caller.
/// # C: O(N_tasks) on non-self lookup
pub fn sys_sched_getscheduler(args: &SyscallArgs) -> i64 {
    let pid = match sched_policy::pid_arg(args.a0) { Ok(v) => v, Err(rv) => return rv };
    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else {
        sched::live::registry::resolve_user_pid(pid)
    };
    let t = match task { Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64) };
    let mut policy = sched_policy::task_policy(&t);
    if t.sched_reset_on_fork.load(Ordering::Acquire) { policy |= sched_policy::SCHED_RESET_ON_FORK; }
    policy as i32 as i64
}
