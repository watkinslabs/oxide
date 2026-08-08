// End-to-end `sched_setattr(2)` rules that only the `sched_attr`-shaped entry
// can express: the flag mask, SCHED_FLAG_KEEP_{POLICY,PARAMS}, the util-clamp
// request, the custom CFS slice, and Linux's no-change fast path.
// Reference: Linux's `__sched_setscheduler` and `__setparam_fair`.

use super::*;
use crate::sched_attr as sa;

/// A privileged, same-owner caller so every test below reaches the rule it is
/// about rather than stopping at `EPERM`.
fn root_caller() -> Arc<Task> { let c = normal(1, 0); privileged(&c); c }

fn attr(policy: u32, priority: u32, flags: u64) -> SchedAttr {
    SchedAttr { policy, priority, flags, ..Default::default() }
}

#[test]
fn unknown_sched_flags_are_einval() {
    let caller = root_caller();
    let t = normal(2, 0);
    // SCHED_FLAG_ALL is 0x7f; the next bit up is not a flag Linux knows.
    assert_eq!(setattr(&caller, &t, &attr(SCHED_NORMAL, 0, 0x80)), EINVAL);
    assert_eq!(setattr(&caller, &t, &attr(SCHED_NORMAL, 0, u64::MAX)), EINVAL);
    // Every documented flag combination passes the mask.
    assert_eq!(setattr(&caller, &t, &attr(SCHED_NORMAL, 0, sa::FLAG_ALL & !sa::FLAG_UTIL_CLAMP)), 0);
}

#[test]
fn sugov_survives_the_mask_but_a_syscall_caller_is_refused() {
    // SCHED_FLAG_SUGOV is inside `~(SCHED_FLAG_ALL | SCHED_FLAG_SUGOV)` so
    // `__checkparam_dl` can honour it, then the `if (user)` block rejects it.
    let caller = root_caller();
    let t = normal(2, 0);
    assert_eq!(setattr(&caller, &t, &attr(SCHED_NORMAL, 0, sa::FLAG_SUGOV)), EINVAL);
}

#[test]
fn keep_policy_leaves_the_policy_and_still_applies_the_priority() {
    let caller = root_caller();
    let t = normal(2, 0);
    assert_eq!(setattr(&caller, &t, &attr(SCHED_FIFO, 20, 0)), 0);
    // SETPARAM_POLICY is what slot 314 folds SCHED_FLAG_KEEP_POLICY onto.
    let mut a = attr(SETPARAM_POLICY as u32, 44, sa::FLAG_KEEP_POLICY);
    a.nice = 0;
    assert_eq!(setattr(&caller, &t, &a), 0);
    assert_eq!(task_policy(&t), SCHED_FIFO);
    assert_eq!(task_rt_priority(&t), 44);
}

#[test]
fn keep_params_commits_nothing_but_reset_on_fork() {
    let caller = root_caller();
    let t = normal(2, 0);
    assert_eq!(setattr(&caller, &t, &attr(SCHED_FIFO, 20, 0)), 0);
    // A NORMAL request with KEEP_PARAMS must not move the task off SCHED_FIFO:
    // Linux guards `__setscheduler_params` + the class switch with the flag.
    let a = attr(SCHED_NORMAL, 0, sa::FLAG_KEEP_PARAMS | sa::FLAG_RESET_ON_FORK);
    assert_eq!(setattr(&caller, &t, &a), 0);
    assert_eq!(task_policy(&t), SCHED_FIFO);
    assert_eq!(task_rt_priority(&t), 20);
    assert!(t.sched_reset_on_fork.load(Ordering::Acquire));
}

#[test]
fn a_no_change_request_still_records_reset_on_fork() {
    let caller = root_caller();
    let t = normal(2, 0);
    // Same policy, same nice, same slice ⇒ Linux's "no need to proceed further,
    // but store a possible modification of reset_on_fork".
    let mut a = attr(SCHED_NORMAL, 0, sa::FLAG_RESET_ON_FORK);
    a.runtime = SCHED_BASE_SLICE_NS;
    assert_eq!(setattr(&caller, &t, &a), 0);
    assert!(t.sched_reset_on_fork.load(Ordering::Acquire));
    assert_eq!(task_slice_ns(&t), SCHED_BASE_SLICE_NS);
}

// --- util clamp ------------------------------------------------------------

#[test]
fn a_util_clamp_request_is_stored_and_marked_user_defined() {
    let caller = root_caller();
    let t = normal(2, 0);
    let mut a = attr(SCHED_NORMAL, 0, sa::FLAG_UTIL_CLAMP_MIN);
    a.util_min = 300;
    assert_eq!(setattr(&caller, &t, &a), 0);
    let (min, max) = uclamp_req(&t);
    assert_eq!(min, sa::UclampSe { value: 300, user_defined: true });
    assert_eq!(max, sa::UclampSe { value: sa::CAPACITY_SCALE, user_defined: false });
}

#[test]
fn a_util_clamp_above_capacity_scale_is_einval_and_changes_nothing() {
    let caller = root_caller();
    let t = normal(2, 0);
    let mut a = attr(SCHED_NORMAL, 0, sa::FLAG_UTIL_CLAMP_MAX);
    a.util_max = sa::CAPACITY_SCALE + 1;
    assert_eq!(setattr(&caller, &t, &a), EINVAL);
    assert_eq!(uclamp_req(&t).1.value, sa::CAPACITY_SCALE);
}

#[test]
fn an_auto_min_clamp_follows_the_task_onto_an_rt_policy() {
    // `__setscheduler_uclamp` resets a non-user-defined clamp on every commit,
    // and RT tasks default to a 100% min boost.
    let caller = root_caller();
    let t = normal(2, 0);
    assert_eq!(uclamp_req(&t).0.value, 0);
    assert_eq!(setattr(&caller, &t, &attr(SCHED_FIFO, 20, 0)), 0);
    assert_eq!(uclamp_req(&t).0, sa::UclampSe { value: sa::CAPACITY_SCALE, user_defined: false });
}

#[test]
fn a_user_defined_clamp_survives_a_policy_change() {
    let caller = root_caller();
    let t = normal(2, 0);
    let mut a = attr(SCHED_NORMAL, 0, sa::FLAG_UTIL_CLAMP_MIN);
    a.util_min = 200;
    assert_eq!(setattr(&caller, &t, &a), 0);
    assert_eq!(setattr(&caller, &t, &attr(SCHED_FIFO, 20, 0)), 0);
    assert_eq!(uclamp_req(&t).0, sa::UclampSe { value: 200, user_defined: true });
}

#[test]
fn the_minus_one_sentinel_clears_a_user_defined_clamp() {
    let caller = root_caller();
    let t = normal(2, 0);
    let mut a = attr(SCHED_NORMAL, 0, sa::FLAG_UTIL_CLAMP_MIN);
    a.util_min = 200;
    assert_eq!(setattr(&caller, &t, &a), 0);
    a.util_min = sa::UCLAMP_RESET;
    assert_eq!(setattr(&caller, &t, &a), 0);
    assert_eq!(uclamp_req(&t).0, sa::UclampSe { value: 0, user_defined: false });
}

// --- custom CFS slice ------------------------------------------------------

#[test]
fn sched_runtime_becomes_a_clamped_custom_slice_for_a_fair_task() {
    let caller = root_caller();
    let t = normal(2, 0);
    // `__setparam_fair` clamps to [NSEC_PER_MSEC/10, NSEC_PER_MSEC*100].
    let mut a = attr(SCHED_NORMAL, 0, 0);
    a.runtime = 1;
    assert_eq!(setattr(&caller, &t, &a), 0);
    assert_eq!(task_slice_ns(&t), 100_000);
    a.runtime = 1_000_000_000;
    assert_eq!(setattr(&caller, &t, &a), 0);
    assert_eq!(task_slice_ns(&t), 100_000_000);
    // Zero clears `custom_slice`, which reads back as the base slice.
    a.runtime = 0;
    assert_eq!(setattr(&caller, &t, &a), 0);
    assert_eq!(task_slice_ns(&t), SCHED_BASE_SLICE_NS);
}

#[test]
fn get_params_reports_the_live_state_keep_params_would_reuse() {
    let caller = root_caller();
    let t = normal(2, 0);
    let mut a = attr(SCHED_NORMAL, 0, 0);
    a.runtime = 5_000_000;
    a.nice = 7;
    assert_eq!(setattr(&caller, &t, &a), 0);
    let mut out = SchedAttr::default();
    get_params(&t, &mut out, false);
    assert_eq!(out.nice, 7);
    assert_eq!(out.runtime, 5_000_000);
    // An RT task reports its priority instead, and no slice.
    assert_eq!(setattr(&caller, &t, &attr(SCHED_RR, 31, 0)), 0);
    let mut out = SchedAttr::default();
    get_params(&t, &mut out, false);
    assert_eq!(out.priority, 31);
    assert_eq!(out.runtime, 0);
}

// --- the SCHED_RR quantum ---------------------------------------------------

/// The quantum `sched_rr_get_interval(2)` reports is the one the periodic tick
/// enforces — one number, not two constants in two crates. They were written
/// in different units (ticks vs. nanoseconds) with nothing tying them together,
/// so a SCHED_RR task was reported a 100 ms slice and given a 1 s one.
#[test]
fn the_reported_rr_interval_is_the_enforced_quantum() {
    assert_eq!(SCHED_RR_TIMESLICE_NS, 100_000_000, "RR quantum is 100 ms");
    assert_eq!(rr_interval_ns(SCHED_RR, false), SCHED_RR_TIMESLICE_NS);
    assert_eq!(SCHED_RR_TIMESLICE_NS,
               sched::sched_enc::RR_TIMESLICE_TICKS as u64 * sched::posix_clock::TICK_NSEC,
               "reported interval must equal the ticks the quantum is enforced in");
}

/// Becoming a real-time task hands over a WHOLE quantum. The field is only
/// ever loaded with the full slice upstream, so a task must never resume on
/// the residue an earlier stint (or an older quantum in different units) left
/// behind and get an arbitrary fraction of its first slice.
#[test]
fn entering_an_rt_policy_reloads_a_full_quantum() {
    let caller = root_caller();
    let t = normal(2, 0);
    t.rt_time_slice.store(1, Ordering::Release);

    assert_eq!(setattr(&caller, &t, &attr(SCHED_RR, 40, 0)), 0);
    assert_eq!(t.rt_time_slice.load(Ordering::Acquire), sched::sched_enc::RR_TIMESLICE_TICKS);

    // Draining the quantum and switching away then back re-arms it in full.
    t.rt_time_slice.store(1, Ordering::Release);
    assert_eq!(setattr(&caller, &t, &attr(SCHED_NORMAL, 0, 0)), 0);
    assert_eq!(setattr(&caller, &t, &attr(SCHED_FIFO, 40, 0)), 0);
    assert_eq!(t.rt_time_slice.load(Ordering::Acquire), sched::sched_enc::RR_TIMESLICE_TICKS);
}
