// Linux `__sched_setscheduler()` and
// `_sched_setscheduler()` (`:721`): validation order, the no-change fast path,
// the util-clamp update, and the commit onto the runqueue.

use core::sync::atomic::Ordering;
use alloc::sync::Arc;
use syscall::errno::Errno;
use crate::sched_attr::{self as sa, SchedAttr};
use super::*;
use super::task::make_uclamp_req;

/// Linux `__sched_setscheduler(p, attr, user = true, pi = true)`.
///
/// Order is Linux's and matters: policy validity → flag mask → priority range →
/// DL/RT parameter agreement → permission (`EPERM`) → `SCHED_FLAG_SUGOV` →
/// util-clamp range → no-change fast path → commit. A bad priority is therefore
/// `EINVAL` even for a caller who would otherwise have been denied `EPERM`.
/// # C: O(log N) requeue
pub fn setattr(caller: &sched::Task, t: &Arc<sched::Task>, attr: &SchedAttr) -> i64 {
    loop {
    let observed = t.sched_policy_generation();
    let observed_policy = observed.0;
    // `int policy = attr->sched_policy`: negative means "keep the task's own",
    // reachable via sched_setparam(2) and SCHED_FLAG_KEEP_POLICY.
    let (policy, reset_on_fork) = if (attr.policy as i32) < 0 {
        (observed_policy, t.priority_snapshot().reset_on_fork)
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
    if let Err(rv) = security::lsm::task_setscheduler(caller, t) { return rv; }

    let (mut uc_min, mut uc_max) = uclamp_req(t);
    if attr.flags & sa::FLAG_UTIL_CLAMP != 0 {
        if let Err(rv) = sa::uclamp_validate(attr, uc_min.value, uc_max.value) { return rv; }
    }

    // "If not changing anything there's no need to proceed further, but store a
    // possible modification of reset_on_fork". A util-clamp request always
    // forces the change path, matching Linux's `SCHED_FLAG_UTIL_CLAMP` check.
    if policy == observed_policy && !params_changed(t, attr, policy) {
        if crate::sched_policy::commit::reset(t, observed, reset_on_fork) { return 0; }
        continue;
    }

    // Deadline admission runs LAST, after every argument and permission answer:
    // `EBUSY` means "the machine is full", and reporting it ahead of a bad
    // argument or a denied caller would misattribute the refusal.
    let was_dl = dl_policy(observed_policy);
    if dl_policy(policy) || was_dl {
        // Applies to EVERY syscall caller, privileged or not: `CAP_SYS_NICE`
        // overrides the ownership and priority ladders, not the question of
        // whether the reservation can be honoured at all. A task that cannot
        // reach the whole span, or a class with no bandwidth to give, cannot be
        // promised a deadline by anyone.
        if dl_policy(policy)
            && !crate::sched_policy::dl::user_dl_allowed(dl_span(), dl_task_mask(t),
                                                        sched::deadline::bw::DL_BW.bw()) {
            return err(Errno::Eperm);
        }
    }

    let new_is_rt = rt_policy(policy);
    uc_min = sa::uclamp_apply(attr, true, uc_min, new_is_rt);
    uc_max = sa::uclamp_apply(attr, false, uc_max, new_is_rt);
    let clamp = make_uclamp_req(uc_min, uc_max);
    if attr.flags & sa::FLAG_KEEP_PARAMS == 0 {
        match apply(t, attr, observed, policy, clamp, reset_on_fork) {
            sched::SchedUpdateResult::Applied => {}
            sched::SchedUpdateResult::Stale => continue,
            sched::SchedUpdateResult::DeadlineBusy => return err(Errno::Ebusy),
            sched::SchedUpdateResult::DeadlineDenied => return err(Errno::Eperm),
        }
    } else {
        if !crate::sched_policy::commit::controls(t, observed, clamp, reset_on_fork) {
            continue;
        }
    }
    return 0;
    }
}

/// The CPU span the deadline class is admitted against.
/// # C: O(1)
fn dl_span() -> cpu::CpuMask { sched::deadline::span() }

/// The CPUs `t` may actually run on.
/// # C: O(1)
fn dl_task_mask(t: &sched::Task) -> cpu::CpuMask { t.cpus_allowed.load(Ordering::Acquire) }

/// Linux's `goto change` ladder: would this request alter anything the task
/// already has?
/// # C: O(1)
fn params_changed(t: &sched::Task, attr: &SchedAttr, policy: u32) -> bool {
    if dl_policy(policy)
        && crate::sched_policy::dl::dl_param_changed(&t.sched_deadline_snapshot().0, attr) {
        return true;
    }
    if fair_policy(policy)
        && (attr.nice != t.nice_value() as i32 || attr.runtime != task_slice_ns(t)) {
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
    let slice = t.sched_entity_snapshot().slice;
    if slice != 0 { attr.runtime = slice; }
    setattr(caller, t, &attr)
}

/// Commit validated + authorized parameters onto `t`, moving it between the RT
/// and CFS trees under the runqueue lock (Linux `__setscheduler_params` +
/// `__setparam_fair` + the dequeue/enqueue around the class change).
/// # C: O(log N)
fn apply(t: &Arc<sched::Task>, attr: &SchedAttr, expected: (u32, u32), policy: u32,
         clamp: sched::SchedUclamp, reset_on_fork: bool) -> sched::SchedUpdateResult {
    use sched::{SchedClass, SchedPolicy};
    let mut nice = None;
    let new_class = match policy {
        SCHED_DEADLINE => {
            SchedClass::Deadline
        }
        SCHED_FIFO | SCHED_RR => {
            let p = if policy == SCHED_FIFO { SchedPolicy::Fifo } else { SchedPolicy::Rr };
            SchedClass::Rt { prio: attr.priority as u8, policy: p }
        }
        SCHED_IDLE => {
            SchedClass::Normal { weight: SCHED_IDLE_WEIGHT }
        }
        // SCHED_NORMAL / SCHED_BATCH
        _ => {
            let n = sched::rlimit::clamp_nice(attr.nice);
            let w = sched::cputime::nice_to_weight(n);
            nice = Some(n);
            SchedClass::Normal { weight: w }
        }
    };
    let result = crate::sched_policy::commit::apply(t, expected, sched::SchedUpdate {
        class: new_class, policy, clamp, reset_on_fork, nice,
        // `__setparam_fair` runs for NORMAL/BATCH only; SCHED_IDLE and RT keep it.
        fair_slice: fair_policy(policy).then(|| fair_slice(attr)),
        reload_rt_timeslice: rt_policy(policy),
        clear_rt_timeout: !sched::sched_enc::is_rt_class_policy(policy),
        deadline: dl_policy(policy).then(|| crate::sched_policy::dl::attr_params(attr)),
    });
    result
}

/// Linux `__setparam_fair()`: a non-zero
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
    let cap_nice = nscg::proc_ns::has_cap_in_initial_user_ns(caller, sched::cap::SYS_NICE);
    klog::write_raw(b" cap_sys_nice="); klog::write_dec_u64(cap_nice as u64);
    klog::write_raw(b" rv=");
    if result < 0 { klog::write_raw(b"-"); klog::write_dec_u64(result.wrapping_neg() as u64); }
    else { klog::write_dec_u64(result as u64); }
    klog::write_raw(b"]\n");
}

/// # C: O(1)
#[cfg(not(all(feature = "debug-boot", target_os = "oxide-kernel")))]
pub fn trace_admission(_caller: &sched::Task, _target: &sched::Task, _policy: u32, _prio: u32, _result: i64) {}
