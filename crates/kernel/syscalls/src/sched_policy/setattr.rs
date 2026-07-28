// Linux `__sched_setscheduler()` (`kernel/sched/syscalls.c:490`) and
// `_sched_setscheduler()` (`:721`): validation order, the no-change fast path,
// the util-clamp update, and the commit onto the runqueue.

use core::sync::atomic::Ordering;
use alloc::sync::Arc;
use syscall::errno::Errno;
use crate::sched_attr::{self as sa, SchedAttr};
use super::*;
use super::task::set_uclamp_req;

/// Linux `__sched_setscheduler(p, attr, user = true, pi = true)`.
///
/// Order is Linux's and matters: policy validity → flag mask → priority range →
/// DL/RT parameter agreement → permission (`EPERM`) → `SCHED_FLAG_SUGOV` →
/// util-clamp range → no-change fast path → commit. A bad priority is therefore
/// `EINVAL` even for a caller who would otherwise have been denied `EPERM`.
/// # C: O(log N) requeue
pub fn setattr(caller: &sched::Task, t: &Arc<sched::Task>, attr: &SchedAttr) -> i64 {
    // `int policy = attr->sched_policy`: negative means "keep the task's own",
    // reachable via sched_setparam(2) and SCHED_FLAG_KEEP_POLICY.
    let (policy, reset_on_fork) = if (attr.policy as i32) < 0 {
        (task_policy(t), t.sched_reset_on_fork.load(Ordering::Acquire))
    } else {
        if !valid_policy(attr.policy) { return err(Errno::Einval); }
        (attr.policy, attr.flags & sa::FLAG_RESET_ON_FORK != 0)
    };
    if let Err(rv) = check_flags(attr.flags) { return rv; }
    if let Err(rv) = check_params(policy, attr.priority as i32, checkparam_dl(attr)) { return rv; }

    let authorization = user_check(caller, t, policy, attr.nice, attr.priority, reset_on_fork);
    trace_admission(caller, t, policy, attr.priority, authorization);
    if authorization != 0 { return authorization; }
    // SCHED_FLAG_SUGOV is kernel-internal: it survives the flag mask so
    // `__checkparam_dl` can honour it, then the `user` path rejects it.
    if attr.flags & sa::FLAG_SUGOV != 0 { return err(Errno::Einval); }

    let (mut uc_min, mut uc_max) = uclamp_req(t);
    if attr.flags & sa::FLAG_UTIL_CLAMP != 0 {
        if let Err(rv) = sa::uclamp_validate(attr, uc_min.value, uc_max.value) { return rv; }
    }

    // A policy this scheduler cannot honour must not be silently recorded and
    // then run as SCHED_NORMAL. SCHED_DEADLINE has no deadline class here.
    if dl_policy(policy) { return err(Errno::Eopnotsupp); }

    // Linux's "if not changing anything there's no need to proceed further,
    // but store a possible modification of reset_on_fork". Skipping the commit
    // also skips `__setscheduler_uclamp`, so an auto clamp survives a no-op.
    if policy == task_policy(t) && !params_changed(t, attr, policy) {
        t.sched_reset_on_fork.store(reset_on_fork, Ordering::Release);
        return 0;
    }

    let new_is_rt = rt_policy(policy);
    uc_min = sa::uclamp_apply(attr, true, uc_min, new_is_rt);
    uc_max = sa::uclamp_apply(attr, false, uc_max, new_is_rt);
    if attr.flags & sa::FLAG_KEEP_PARAMS == 0 { apply(t, attr, policy); }
    set_uclamp_req(t, uc_min, uc_max);
    t.sched_reset_on_fork.store(reset_on_fork, Ordering::Release);
    0
}

/// Linux's `goto change` ladder: would this request alter anything the task
/// already has?
/// # C: O(1)
fn params_changed(t: &sched::Task, attr: &SchedAttr, policy: u32) -> bool {
    if fair_policy(policy)
        && (attr.nice != t.nice.load(Ordering::Acquire) as i32 || attr.runtime != task_slice_ns(t)) {
        return true;
    }
    if rt_policy(policy) && attr.priority != task_rt_priority(t) { return true; }
    attr.flags & sa::FLAG_UTIL_CLAMP != 0
}

/// Linux `_sched_setscheduler()`: the `sched_param`-shaped entry slots 142/144
/// use, expressed as the `sched_attr` one so there is a single policy path.
/// `policy_arg` carries the legacy `SCHED_RESET_ON_FORK` bit, or
/// `SETPARAM_POLICY` for `sched_setparam(2)`.
/// # C: O(log N) requeue
pub fn setscheduler(caller: &sched::Task, t: &Arc<sched::Task>,
                    policy_arg: i32, prio: i32, nice: i32) -> i64 {
    let (policy_i, reset_on_fork) = split_reset_on_fork(policy_arg);
    let mut attr = SchedAttr {
        policy: policy_i as u32,
        priority: prio as u32,
        nice,
        flags: if reset_on_fork { sa::FLAG_RESET_ON_FORK } else { 0 },
        ..Default::default()
    };
    // Linux carries a custom CFS slice across a sched_setparam/setscheduler.
    let slice = t.sched_slice_ns.load(Ordering::Acquire);
    if slice != 0 { attr.runtime = slice; }
    setattr(caller, t, &attr)
}

/// Commit validated + authorized parameters onto `t`, moving it between the RT
/// and CFS trees under the runqueue lock (Linux `__setscheduler_params` +
/// `__setparam_fair` + the dequeue/enqueue around the class change).
/// # C: O(log N)
fn apply(t: &Arc<sched::Task>, attr: &SchedAttr, policy: u32) {
    use sched::{SchedClass, SchedPolicy};
    let new_class = match policy {
        SCHED_FIFO | SCHED_RR => {
            let p = if policy == SCHED_FIFO { SchedPolicy::Fifo } else { SchedPolicy::Rr };
            SchedClass::Rt { prio: attr.priority as u8, policy: p }
        }
        SCHED_IDLE => {
            t.load_weight.store(SCHED_IDLE_WEIGHT, Ordering::Release);
            SchedClass::Normal { weight: SCHED_IDLE_WEIGHT }
        }
        // SCHED_NORMAL / SCHED_BATCH
        _ => {
            let n = sched::rlimit::clamp_nice(attr.nice);
            let w = sched::cputime::nice_to_weight(n);
            t.nice.store(n, Ordering::Release);
            t.load_weight.store(w, Ordering::Release);
            SchedClass::Normal { weight: w }
        }
    };
    // `__setscheduler_params` calls `__setparam_fair` for NORMAL/BATCH only —
    // SCHED_IDLE and the RT policies leave `se.slice` alone.
    if fair_policy(policy) { t.sched_slice_ns.store(fair_slice(attr), Ordering::Release); }
    t.policy.store(policy, Ordering::Release);
    sched::live::runqueue::set_class(t, new_class);
}

/// Linux `__setparam_fair()` (`kernel/sched/fair.c:5951`): a non-zero
/// `sched_runtime` becomes a custom CFS slice clamped to `[100us, 100ms]`;
/// zero clears the custom slice back to `sysctl_sched_base_slice`.
/// # C: O(1)
fn fair_slice(attr: &SchedAttr) -> u64 {
    /// Linux `NSEC_PER_MSEC / 10`.
    const SLICE_MIN_NS: u64 = 100_000;
    /// Linux `NSEC_PER_MSEC * 100`.
    const SLICE_MAX_NS: u64 = 100_000_000;
    if attr.runtime == 0 { return 0; }
    attr.runtime.clamp(SLICE_MIN_NS, SLICE_MAX_NS)
}

/// Bounded scheduler-admission record. Kept behind `debug-boot` so desktop
/// bring-up can separate an RLIMIT denial from a credential denial without
/// perturbing normal scheduling.
#[cfg(all(feature = "debug-boot", target_os = "oxide-kernel"))]
pub fn trace_admission(caller: &sched::Task, target: &sched::Task, policy: u32, prio: u32, result: i64) {
    let rtprio = target.rlimit(sched::rlimit::rlim::RTPRIO).0;
    klog::write_raw(b"[SCHEDCTL caller="); klog::write_dec_u64(caller.tid as u64);
    klog::write_raw(b" target="); klog::write_dec_u64(target.tid as u64);
    klog::write_raw(b" policy="); klog::write_dec_u64(policy as u64);
    klog::write_raw(b" prio="); klog::write_dec_u64(prio as u64);
    klog::write_raw(b" rlimit_rtprio="); klog::write_dec_u64(rtprio);
    klog::write_raw(b" cap_sys_nice="); klog::write_dec_u64(caller.has_cap(sched::cap::SYS_NICE) as u64);
    klog::write_raw(b" rv=");
    if result < 0 { klog::write_raw(b"-"); klog::write_dec_u64(result.wrapping_neg() as u64); }
    else { klog::write_dec_u64(result as u64); }
    klog::write_raw(b"]\n");
}

/// # C: O(1)
#[cfg(not(all(feature = "debug-boot", target_os = "oxide-kernel")))]
pub fn trace_admission(_caller: &sched::Task, _target: &sched::Task, _policy: u32, _prio: u32, _result: i64) {}
