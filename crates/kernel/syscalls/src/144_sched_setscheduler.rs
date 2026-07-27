// 144 sched_setscheduler — one syscall, one file (docs/53 §0).
// sched_setscheduler(pid, policy, param): set BOTH the scheduling policy and
// (for RT policies) the priority of `pid`. Thin shim: every rule lives in
// `crate::sched_policy` (Linux `sys_sched_setscheduler` →
// `do_sched_setscheduler` → `__sched_setscheduler`), which the hosted suite
// exercises.
#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;
use syscall::{errno::Errno, SyscallArgs};
use crate::sched_policy;
use crate::userbuf::validate_user_buf;

/// `sys_sched_setscheduler(pid, policy, param)` — slot 144.
/// # C: O(log N) requeue
pub fn sys_sched_setscheduler(args: &SyscallArgs) -> i64 {
    let policy = args.a1 as i32;
    // Linux `sys_sched_setscheduler`: a negative policy is EINVAL before
    // anything else — it would otherwise alias the SETPARAM_POLICY sentinel.
    if policy < 0 { return -(Errno::Einval.as_i32() as i64); }
    do_sched_setscheduler(args.a0, policy, args.a2)
}

/// Linux `do_sched_setscheduler()`: shared by slots 144 and 142. Ordering is
/// Linux's — `!param || pid < 0` is EINVAL (NOT EFAULT), then the copy-in
/// EFAULT, then the ESRCH lookup, then policy/priority validation, then the
/// permission check.
/// # C: O(log N) requeue
pub(crate) fn do_sched_setscheduler(pid_raw: u64, policy: i32, uparam: u64) -> i64 {
    if uparam == 0 { return -(Errno::Einval.as_i32() as i64); }
    let pid = match sched_policy::pid_arg(pid_raw) { Ok(p) => p, Err(rv) => return rv };
    // struct sched_param { int sched_priority; } — 4 bytes.
    if let Err(rv) = validate_user_buf(uparam, 4, 1) { return rv; }
    // SAFETY: uparam validated readable for struct sched_param.sched_priority.
    let prio = unsafe { core::ptr::read_unaligned(uparam as *const i32) };
    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else {
        sched::live::registry::resolve_user_pid(pid)
    };
    let t = match task { Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64) };
    let caller = match sched::live::current() { Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64) };
    // Linux `_sched_setscheduler` seeds attr.sched_nice from the TARGET's
    // current nice — sched_setscheduler(2) never changes nice.
    let nice = t.nice.load(Ordering::Acquire) as i32;
    // A `struct sched_param` carries no runtime/deadline/period, so a
    // SCHED_DEADLINE request can never satisfy Linux `__checkparam_dl` here.
    sched_policy::setscheduler(caller, &t, policy, prio, nice, false)
}
