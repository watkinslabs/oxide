// 144 sched_setscheduler — one syscall, one file (docs/53 §0).
// sched_setscheduler(pid, policy, param): set BOTH the scheduling policy and
// (for RT policies) the priority of `pid`. Previously this NR was wrongly
// dispatched to sched_getscheduler — chrt / RT services silently got the OLD
// policy back and no change took effect. Now it really changes the policy via
// the shared apply_sched_policy() core (Linux `do_sched_setscheduler`).
#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;
use syscall::{errno::Errno, SyscallArgs};

/// SCHED_RESET_ON_FORK is ORed into the policy arg; mask it (the reset-on-fork
/// flag itself is a follow-up — accepted, not yet enforced).
const SCHED_RESET_ON_FORK: u32 = 0x4000_0000;

/// `sys_sched_setscheduler(pid, policy, param)` — slot 144.
/// # C: O(log N) requeue
pub fn sys_sched_setscheduler(args: &SyscallArgs) -> i64 {
    let pid = args.a0 as u32;
    let policy = (args.a1 as u32) & !SCHED_RESET_ON_FORK;
    let uparam = args.a2;
    // struct sched_param { int sched_priority; } — 4 bytes.
    if uparam == 0 || uparam.saturating_add(4) > hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: uparam range-checked for 4 bytes < USER_VA_END; read sched_priority.
    let prio = unsafe { core::ptr::read_unaligned(uparam as *const i32) };
    if prio < 0 { return -(Errno::Einval.as_i32() as i64); }
    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else {
        sched::live::registry::resolve_user_pid(pid)
    };
    let t = match task { Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64) };
    // sched_setscheduler does not change `nice` for the normal classes — keep
    // the task's current nice (sched_setattr is the path that sets nice).
    let nice = t.nice.load(Ordering::Acquire) as i32;
    crate::s314_sched_setattr::apply_sched_policy(&t, policy, nice, prio as u32)
}
