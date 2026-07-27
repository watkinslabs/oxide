// 143 sched_getparam — one syscall, one file (docs/53 §0).
// Linux `sys_sched_getparam`: `!param || pid < 0` → EINVAL, missing pid →
// ESRCH, and only THEN the copy-out EFAULT. The write is the last step, so a
// bad pid beats a bad (non-NULL) pointer.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::sched_policy;
use crate::userbuf::validate_user_buf_writable;

/// `sys_sched_getparam(pid, param)` — slot 143. Writes the target task's RT
/// priority (1..=99 for FIFO/RR; 0 for every non-RT policy). `pid==0` = caller.
/// # C: O(N_tasks) on non-self lookup
pub fn sys_sched_getparam(args: &SyscallArgs) -> i64 {
    let p = args.a1;
    if p == 0 { return -(Errno::Einval.as_i32() as i64); }
    let pid = match sched_policy::pid_arg(args.a0) { Ok(v) => v, Err(rv) => return rv };
    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else {
        sched::live::registry::resolve_user_pid(pid)
    };
    let t = match task { Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64) };
    let prio = sched_policy::task_rt_priority(&t) as i32;
    if let Err(rv) = validate_user_buf_writable(p, 4, 1) { return rv; }
    // SAFETY: p validated writable for struct sched_param.sched_priority.
    unsafe { core::ptr::write_unaligned(p as *mut i32, prio); }
    0
}
