// 142 sched_setparam — one syscall, one file (docs/53 §0).
// sched_setparam(pid, param): set the RT priority of `pid` (struct sched_param
// { i32 sched_priority; }) KEEPING its current policy. Linux implements it as
// `do_sched_setscheduler(pid, SETPARAM_POLICY, param)` — the identical path as
// slot 144 with the "don't change the policy" sentinel — so this shim does the
// same rather than re-deriving per-class rules.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::sched_policy::SETPARAM_POLICY;

/// `sys_sched_setparam(pid, param)` — slot 142.
/// # C: O(log N) requeue
pub fn sys_sched_setparam(args: &SyscallArgs) -> i64 {
    crate::s144_sched_setscheduler::do_sched_setscheduler(args.a0, SETPARAM_POLICY, args.a1)
}
