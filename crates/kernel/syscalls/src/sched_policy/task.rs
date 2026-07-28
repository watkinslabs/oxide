// Live `Task` accessors and the `sched_setattr`/`sched_setscheduler`
// permission ladder. Linux `kernel/sched/syscalls.c`
// (`user_check_sched_setscheduler`, `check_same_owner`, `is_nice_reduction`,
// `get_params`) and `kernel/sched/sched.h`.

use core::sync::atomic::Ordering;
use syscall::errno::Errno;
use crate::sched_attr::{SchedAttr, UclampSe};
use super::*;

/// Live policy of `t` — Linux `p->policy`, stored separately from the
/// scheduler class exactly as Linux does, so `SCHED_BATCH`/`SCHED_IDLE`
/// round-trip through `sched_getscheduler` instead of collapsing onto the
/// class that implements them.
/// # C: O(1)
pub fn task_policy(t: &sched::Task) -> u32 { t.policy.load(Ordering::Acquire) }

/// Linux `p->rt_priority`: the RT priority, 0 for every non-RT policy.
/// # C: O(1)
pub fn task_rt_priority(t: &sched::Task) -> u32 {
    match t.sched_class() { sched::SchedClass::Rt { prio, .. } => prio as u32, _ => 0 }
}

/// Linux `p->se.slice` — the CFS slice `sched_getattr` reports in
/// `sched_runtime` and `sched_setattr` sets from it (`__setparam_fair`).
/// `Task::sched_slice_ns == 0` is Linux's `!se.custom_slice`, which reads back
/// as `sysctl_sched_base_slice`.
/// # C: O(1)
pub fn task_slice_ns(t: &sched::Task) -> u64 {
    match t.sched_slice_ns.load(Ordering::Acquire) { 0 => SCHED_BASE_SLICE_NS, v => v }
}

/// Linux `p->uclamp_req[UCLAMP_MIN]` / `[UCLAMP_MAX]`.
/// # C: O(1)
pub fn uclamp_req(t: &sched::Task) -> (UclampSe, UclampSe) {
    let ud = t.uclamp_user_defined.load(Ordering::Acquire);
    (UclampSe { value: t.uclamp_min.load(Ordering::Acquire), user_defined: ud & 1 != 0 },
     UclampSe { value: t.uclamp_max.load(Ordering::Acquire), user_defined: ud & 2 != 0 })
}

/// Store back a `uclamp_req` pair after `__setscheduler_uclamp`.
/// # C: O(1)
pub(super) fn set_uclamp_req(t: &sched::Task, min: UclampSe, max: UclampSe) {
    t.uclamp_min.store(min.value, Ordering::Release);
    t.uclamp_max.store(max.value, Ordering::Release);
    let ud = (min.user_defined as u8) | ((max.user_defined as u8) << 1);
    t.uclamp_user_defined.store(ud, Ordering::Release);
}

/// Linux `is_nice_reduction()`: is `nice` within the target's `RLIMIT_NICE`
/// allowance (expressed as `20 - nice`)?
/// # C: O(1)
fn is_nice_reduction(target: &sched::Task, nice: i32) -> bool {
    let lim = target.rlimit(sched::rlimit::rlim::NICE).0;
    nice_to_rlimit(nice) as i64 <= lim as i64
}

/// Linux `check_same_owner()`: caller's euid matches the target's euid or ruid.
/// # C: O(1)
pub fn check_same_owner(caller: &sched::Task, target: &sched::Task) -> bool {
    let euid = caller.creds.euid.load(Ordering::Acquire);
    euid == target.creds.euid.load(Ordering::Acquire)
        || euid == target.creds.ruid.load(Ordering::Acquire)
}

/// Linux `user_check_sched_setscheduler()` verbatim: every branch that needs
/// privilege falls through to a single `capable(CAP_SYS_NICE)` test, so
/// `CAP_SYS_NICE` is an override rather than a precondition. Returns `0` or
/// `-EPERM`.
/// # C: O(1)
pub fn user_check(caller: &sched::Task, target: &sched::Task,
                  policy: u32, nice: i32, prio: u32, reset_on_fork: bool) -> i64 {
    let mut req_priv = false;
    let target_nice = target.nice.load(Ordering::Acquire) as i32;

    if fair_policy(policy) && nice < target_nice && !is_nice_reduction(target, nice) { req_priv = true; }

    if rt_policy(policy) {
        let rlim_rtprio = target.rlimit(sched::rlimit::rlim::RTPRIO).0;
        let old_policy = task_policy(target);
        let old_prio = task_rt_priority(target);
        // Can't set/change the rt policy:
        if policy != old_policy && rlim_rtprio == 0 { req_priv = true; }
        // Can't increase priority:
        if prio > old_prio && prio as u64 > rlim_rtprio { req_priv = true; }
    }

    // Unprivileged tasks may never request SCHED_DEADLINE.
    if dl_policy(policy) { req_priv = true; }

    // SCHED_IDLE is treated as nice 20: leaving it needs the RLIMIT_NICE room.
    if idle_policy(task_policy(target)) && !idle_policy(policy)
        && !is_nice_reduction(target, target_nice) { req_priv = true; }

    if !check_same_owner(caller, target) { req_priv = true; }

    // Normal users shall not reset the sched_reset_on_fork flag.
    if target.sched_reset_on_fork.load(Ordering::Acquire) && !reset_on_fork { req_priv = true; }

    if req_priv && !caller.has_cap(sched::cap::SYS_NICE) { return err(Errno::Eperm); }
    0
}

/// Linux `get_params()` (`kernel/sched/syscalls.c:913`): fill the
/// policy-relevant fields of `attr` from the task's live state. Drives both
/// `sched_getattr` and `SCHED_FLAG_KEEP_PARAMS`.
/// # C: O(1)
pub fn get_params(t: &sched::Task, attr: &mut SchedAttr) {
    let policy = task_policy(t);
    if rt_policy(policy) || dl_policy(policy) {
        // `__getparam_dl` additionally reports runtime/deadline/period from the
        // deadline entity; no task can hold `SCHED_DEADLINE` here (`setattr`
        // refuses it), so only the shared `p->rt_priority` line is reachable.
        attr.priority = task_rt_priority(t);
    } else {
        attr.nice = t.nice.load(Ordering::Acquire) as i32;
        attr.runtime = task_slice_ns(t);
    }
}
