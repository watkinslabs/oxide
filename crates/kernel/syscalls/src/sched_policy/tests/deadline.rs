// `SCHED_DEADLINE` at the syscall boundary: admission, the errno precedence
// around it, what `sched_getattr` reports, and the fork rules.
//
// Split from the parent test module at the 500-line cutoff (`08§7`).

use super::super::*;
use super::{dl, normal, privileged, task, EINVAL, EPERM};
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use sched::{SchedClass, SchedUpdate, SchedUpdateResult, TaskState};
use crate::sched_attr::SchedAttr;
use syscall::errno::Errno;

const EBUSY: i64 = -(Errno::Ebusy as i32 as i64);

fn normal_update() -> SchedUpdate {
    SchedUpdate {
        class: SchedClass::Normal { weight: 1024 }, policy: SCHED_NORMAL,
        clamp: sched::SchedUclamp::new(0, sched::sched_enc::UCLAMP_CAPACITY_SCALE, 0).unwrap(),
        reset_on_fork: false, nice: Some(0), fair_slice: Some(0),
        reload_rt_timeslice: false, clear_rt_timeout: true, deadline: None,
    }
}

#[test]
fn stale_keep_policy_commit_cannot_restore_the_policy_it_observed() {
    let caller = normal(1, 0);
    privileged(&caller);
    let t = normal(2, 0);
    let stale = t.sched_policy_generation();
    let stale_keep_policy = normal_update();

    let newer = SchedAttr { policy: SCHED_FIFO, priority: 80, ..Default::default() };
    assert_eq!(setattr(&caller, &t, &newer), 0);
    assert_ne!(t.sched_policy_generation(), stale);

    assert_eq!(crate::sched_policy::commit::apply(&t, stale, stale_keep_policy),
               SchedUpdateResult::Stale);
    assert_eq!(task_policy(&t), SCHED_FIFO);
    assert_eq!(task_rt_priority(&t), 80);

    // Positive control: an explicit test-local stale mutation can still
    // reproduce the policy rollback the checked boundary prevents.
    sched::hosted_test::set_policy_controls(&t, stale_keep_policy.class,
        stale_keep_policy.policy, stale_keep_policy.clamp,
        stale_keep_policy.reset_on_fork);
    assert_eq!(task_policy(&t), SCHED_NORMAL);
    assert!(matches!(t.sched_class(), SchedClass::Normal { .. }));
}

#[test]
fn stale_post_commit_slack_write_cannot_escape_the_policy_transaction() {
    let caller = normal(10, 0);
    privileged(&caller);
    let t = normal(11, 0);
    let stale = t.sched_policy_generation();
    let stale_normal = normal_update();
    let default = t.security.default_timer_slack_ns.load(Ordering::Acquire);

    let fifo = SchedAttr { policy: SCHED_FIFO, priority: 80, ..Default::default() };
    assert_eq!(setattr(&caller, &t, &fifo), 0);
    assert_eq!(t.security.timer_slack_ns.load(Ordering::Acquire), 0);
    assert_eq!(crate::sched_policy::commit::apply(&t, stale, stale_normal),
               SchedUpdateResult::Stale);
    assert_eq!(task_policy(&t), SCHED_FIFO);
    assert_eq!(t.security.timer_slack_ns.load(Ordering::Acquire), 0,
        "stale commit cannot restore fair-policy slack after RT won");

    // Positive control for the removed post-commit write: if it ran after the
    // newer RT commit, policy and slack would disagree deterministically.
    t.security.timer_slack_ns.store(default, Ordering::Release);
    assert_eq!(task_policy(&t), SCHED_FIFO);
    assert_eq!(t.security.timer_slack_ns.load(Ordering::Acquire), default);

    assert_eq!(setattr(&caller, &t, &SchedAttr::default()), 0);
    assert_eq!(task_policy(&t), SCHED_NORMAL);
    assert_eq!(t.security.timer_slack_ns.load(Ordering::Acquire), default,
        "fair policy and restored slack publish in the same commit");
}

#[test]
fn a_sched_param_shaped_deadline_request_is_einval_not_a_silent_success() {
    // `sched_setscheduler(2)` carries no runtime/deadline/period, so a DEADLINE
    // request through it can never satisfy the parameter ladder — and must fail
    // on the ARGUMENT, before any permission or capacity answer.
    let caller = normal(1, 0);
    privileged(&caller);
    let t = normal(2, 0);
    assert_eq!(setscheduler(&caller, &t, SCHED_DEADLINE as i32, 0, 0), EINVAL);
    assert_eq!(task_policy(&t), SCHED_NORMAL);
}

#[test]
fn a_privileged_deadline_request_is_admitted_and_committed() {
    let _ledger = dl_ledger();
    let caller = normal(1, 0);
    privileged(&caller);
    let t = normal(2, 0);
    assert_eq!(setattr(&caller, &t, &dl(1_000_000, 10_000_000, 10_000_000)), 0);
    assert_eq!(task_policy(&t), SCHED_DEADLINE);
    assert!(matches!(t.sched_class(), SchedClass::Deadline));
    // The reservation is live: a full budget against a deadline in the future.
    let p = t.sched_deadline_snapshot().0;
    assert_eq!(p.runtime, 1_000_000);
    assert_eq!(p.deadline, 10_000_000);
    assert_eq!(p.period, 10_000_000);
    assert_eq!(t.sched_deadline_snapshot().1.runtime, 1_000_000);
    // ... and it is booked against the machine.
    assert_eq!(sched::deadline::bw::DL_BW.total_bw(), p.bw);
}

#[test]
fn a_deadline_request_is_reported_back_by_get_params() {
    let _ledger = dl_ledger();
    let caller = normal(1, 0);
    privileged(&caller);
    let t = normal(2, 0);
    let mut req = dl(1_000_000, 5_000_000, 10_000_000);
    req.flags = crate::sched_attr::FLAG_DL_OVERRUN;
    assert_eq!(setattr(&caller, &t, &req), 0);
    let mut out = SchedAttr::default();
    get_params(&t, &mut out, false);
    assert_eq!(out.runtime, 1_000_000);
    assert_eq!(out.deadline, 5_000_000, "the STATIC relative deadline");
    assert_eq!(out.period, 10_000_000);
    assert_eq!(out.priority, 0);
    assert_eq!(out.flags & crate::sched_attr::FLAG_DL_OVERRUN,
        crate::sched_attr::FLAG_DL_OVERRUN);
}

#[test]
fn the_dynamic_getattr_flag_reports_the_live_instance_not_the_reservation() {
    let _ledger = dl_ledger();
    let caller = normal(1, 0);
    privileged(&caller);
    let t = normal(2, 0);
    assert_eq!(setattr(&caller, &t, &dl(1_000_000, 10_000_000, 10_000_000)), 0);
    // Burn half the instance.
    let mut s = t.sched_deadline_snapshot().1;
    s.runtime = 400_000;
    sched::hosted_test::set_deadline_state(&t, &s);

    let mut stat = SchedAttr::default();
    get_params(&t, &mut stat, false);
    assert_eq!(stat.runtime, 1_000_000, "static reservation");
    assert_eq!(stat.deadline, 10_000_000, "static RELATIVE deadline");

    let mut dyn_out = SchedAttr::default();
    get_params(&t, &mut dyn_out, true);
    assert_eq!(dyn_out.runtime, 400_000, "REMAINING budget");
    assert_eq!(dyn_out.deadline, s.deadline, "ABSOLUTE instance deadline");
}

#[test]
fn an_unprivileged_caller_can_never_request_deadline() {
    let _ledger = dl_ledger();
    let caller = normal(1, 500);
    let t = normal(2, 500);
    // Same owner, well-formed parameters, ample capacity — still EPERM.
    assert_eq!(setattr(&caller, &t, &dl(1_000_000, 10_000_000, 10_000_000)), EPERM);
    assert_eq!(task_policy(&t), SCHED_NORMAL);
    assert_eq!(sched::deadline::bw::DL_BW.total_bw(), 0);
}

#[test]
fn a_bad_parameter_beats_the_permission_answer() {
    // Argument errors are decided before privilege, so an unprivileged caller
    // with malformed parameters learns EINVAL, not EPERM.
    let caller = normal(1, 500);
    let t = normal(2, 500);
    assert_eq!(setattr(&caller, &t, &dl(1_000_000, 0, 10_000_000)), EINVAL);
}

#[test]
fn a_reservation_larger_than_the_machine_is_ebusy_not_einval() {
    let _ledger = dl_ledger();
    let caller = normal(1, 0);
    privileged(&caller);
    // 9ms/10ms is well-formed and permitted; two of them do not fit one CPU.
    let a = normal(2, 0);
    let b = normal(3, 0);
    assert_eq!(setattr(&caller, &a, &dl(9_000_000, 10_000_000, 10_000_000)), 0);
    assert_eq!(setattr(&caller, &b, &dl(9_000_000, 10_000_000, 10_000_000)), EBUSY);
    assert_eq!(task_policy(&b), SCHED_NORMAL, "a refused request commits nothing");
}

#[test]
fn leaving_the_class_returns_the_bandwidth_to_the_machine() {
    let _ledger = dl_ledger();
    sched::deadline::clock::set_now_ns(0);
    let caller = normal(1, 0);
    privileged(&caller);
    let a = normal(2, 0);
    assert_eq!(setattr(&caller, &a, &dl(9_000_000, 10_000_000, 10_000_000)), 0);
    assert_ne!(sched::deadline::bw::DL_BW.total_bw(), 0);
    let mut state = a.sched_deadline_snapshot().1;
    state.runtime = 4_500_000;
    sched::hosted_test::set_deadline_state(&a, &state);
    // Back to a fair policy: the booking remains until zero lag.
    assert_eq!(setscheduler(&caller, &a, SCHED_NORMAL as i32, 0, 0), 0);
    assert_ne!(sched::deadline::bw::DL_BW.total_bw(), 0);
    assert_eq!(a.sched_deadline_snapshot().0.runtime, 9_000_000);
    let b = normal(3, 0);
    assert_eq!(setattr(&caller, &b, &dl(9_000_000, 10_000_000, 10_000_000)), EBUSY);
    sched::deadline::live::expire_throttled(5_000_000);
    assert_eq!(sched::deadline::bw::DL_BW.total_bw(), 0);
    assert_eq!(a.sched_deadline_snapshot().0.runtime, 0);
    // ... so the next task of the same size fits only after inactive expiry.
    assert_eq!(setattr(&caller, &b, &dl(9_000_000, 10_000_000, 10_000_000)), 0);
}

#[test]
fn leaving_a_throttled_runnable_deadline_task_requeues_it_as_normal() {
    let _ledger = dl_ledger();
    let _rq = hosted_runqueue();
    sched::deadline::clock::set_now_ns(0);
    let caller = normal(1, 0);
    privileged(&caller);
    let t = normal(2, 0);

    let rq = sched::live::runqueue::global().unwrap();
    assert!(t.claim_wake(), "fixture owns the Sleeping-to-Waking transition");
    {
        let mut inner = rq.inner.lock();
        assert!(inner.enqueue(Arc::clone(&t)));
        rq.publish_nr_running(inner.nr_running());
    }
    assert_eq!(setattr(&caller, &t, &dl(2_000_000, 10_000_000, 10_000_000)), 0);

    let running = {
        let mut inner = rq.inner.lock();
        let (picked, already_owned) = inner.pick_next_task_claim();
        assert!(!already_owned, "fixture task was already executing");
        rq.publish_nr_running(inner.nr_running());
        picked
    };
    assert_eq!(running.tid, t.tid);
    sched::hosted_test::set_deadline_exec_start(&running, 0);
    sched::deadline::clock::set_now_ns(2_000_000);
    assert_eq!(sched::hosted_test::charge_deadline(&running, 2_000_000),
               sched::deadline::Charged::Throttle);
    {
        let mut inner = rq.inner.lock();
        inner.put_prev_task(running);
        rq.publish_nr_running(inner.nr_running());
    }
    t.on_cpu.store(false, Ordering::Release);
    assert_eq!(t.state(), TaskState::Runnable);
    assert!(!t.on_rq.load(Ordering::Acquire));
    assert!(!t.on_class_rq.load(Ordering::Acquire));
    assert_ne!(sched::deadline::replenish::earliest_ns(), u64::MAX);

    assert_eq!(setattr(&caller, &t, &SchedAttr::default()), 0);
    assert_eq!(task_policy(&t), SCHED_NORMAL);
    assert_eq!(t.state(), TaskState::Runnable);
    assert!(t.on_rq.is_queued(Ordering::Acquire), "runnable task regained canonical rq ownership");
    assert!(t.on_class_rq.load(Ordering::Acquire), "runnable task re-entered a class tree");
    assert_eq!(rq.inner.lock().peek_next_task().tid, t.tid, "fair tree owns the task");
    assert_eq!(t.sched_deadline_snapshot().0.runtime, 2_000_000,
        "deadline parameters remain attached until zero lag");
    assert_eq!(t.sched_deadline_replenish_at(), 0, "throttle timer was cancelled");
    let inactive_at = t.sched_deadline_inactive_at();
    assert_eq!(inactive_at, 10_000_000);
    sched::deadline::live::expire_throttled(inactive_at);
    assert_eq!(t.sched_deadline_snapshot().0.runtime, 0);
    assert_eq!(sched::deadline::replenish::earliest_ns(), u64::MAX);
}

#[test]
fn re_issuing_the_same_reservation_never_fails_on_capacity() {
    let _ledger = dl_ledger();
    let caller = normal(1, 0);
    privileged(&caller);
    let a = normal(2, 0);
    // Fill the machine, then ask for exactly what is already held.
    assert_eq!(setattr(&caller, &a, &dl(10_000_000, 10_000_000, 10_000_000)), 0);
    assert_eq!(setattr(&caller, &a, &dl(10_000_000, 10_000_000, 10_000_000)), 0);
    assert_eq!(sched::deadline::bw::DL_BW.total_bw(), a.sched_deadline_snapshot().0.bw);
}

#[test]
fn shrinking_a_reservation_is_judged_against_the_bandwidth_already_held() {
    let _ledger = dl_ledger();
    let caller = normal(1, 0);
    privileged(&caller);
    let a = normal(2, 0);
    assert_eq!(setattr(&caller, &a, &dl(10_000_000, 10_000_000, 10_000_000)), 0);
    // The machine is full, but this task owns all of it: asking for LESS must
    // succeed. Judged as a fresh reservation it would be refused.
    assert_eq!(setattr(&caller, &a, &dl(5_000_000, 10_000_000, 10_000_000)), 0);
    assert_eq!(sched::deadline::bw::DL_BW.total_bw(), a.sched_deadline_snapshot().0.bw);
}

#[test]
fn a_task_that_cannot_reach_the_whole_span_is_refused_even_with_cap_sys_nice() {
    // The reservation is booked against the span; a task confined below it has
    // a guarantee the ledger never checked. Capability overrides the ownership
    // and priority ladders, not whether the promise can be kept at all.
    let _ledger = dl_ledger();
    let caller = normal(1, 0);
    privileged(&caller);
    let t = normal(2, 0);
    let span = sched::deadline::span();
    let mut confined = span;
    for cpu in 0..cpu::MAX_CPUS {
        if confined.remove(cpu) { break; }
    }
    t.cpus_allowed.store(confined, Ordering::Release);
    assert_eq!(setattr(&caller, &t, &dl(1_000_000, 10_000_000, 10_000_000)), EPERM);
    assert_eq!(task_policy(&t), SCHED_NORMAL);
}

#[test]
fn a_deadline_priority_must_be_zero() {
    let caller = normal(1, 0);
    privileged(&caller);
    let t = normal(2, 0);
    let mut req = dl(1_000_000, 10_000_000, 10_000_000);
    req.priority = 1;
    assert_eq!(setattr(&caller, &t, &req), EINVAL);
}

/// Exclusive access to the admitted-bandwidth ledger for the duration of a
/// test. The ledger is a process-wide static and the harness runs tests in
/// parallel, so two admission tests would otherwise see each other's
/// reservations and fail intermittently. Reset on both acquire and release, so
/// a test always starts on an empty machine.
struct DlLedger;

struct HostedRunqueue {
    _serial: std::sync::MutexGuard<'static, ()>,
}

static DL_LEDGER_BUSY: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

fn dl_ledger() -> DlLedger {
    while DL_LEDGER_BUSY.swap(true, Ordering::AcqRel) { core::hint::spin_loop(); }
    reset_dl_ledger();
    DlLedger
}

impl Drop for DlLedger {
    fn drop(&mut self) {
        reset_dl_ledger();
        DL_LEDGER_BUSY.store(false, Ordering::Release);
    }
}

fn hosted_runqueue() -> HostedRunqueue {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    assert!(sched::live::runqueue::global().is_none());
    let idle = Arc::new(sched::Task::new(999, "sched-policy-idle", SchedClass::Idle));
    // SAFETY: SERIAL makes this test the sole hosted writer of CPU 0's slot,
    // and Drop removes the runqueue before releasing that exclusion.
    unsafe { sched::live::runqueue::install_global(sched::live::Runqueue::new(0, idle)); }
    HostedRunqueue { _serial: serial }
}

impl Drop for HostedRunqueue {
    fn drop(&mut self) {
        // SAFETY: the fixture still owns SERIAL and no task is executing on
        // this hosted runqueue; teardown is the matching single-writer action.
        let removed = unsafe { sched::live::runqueue::uninstall_global() };
        assert!(removed.is_some());
    }
}

fn reset_dl_ledger() {
    sched::deadline::bw::init_default();
    sched::deadline::bw::DL_BW.release(sched::deadline::bw::DL_BW.total_bw());
}


#[test]
fn a_deadline_parent_cannot_fork() {
    // The child would inherit a reservation admitted for exactly one task.
    let parent = task(1, 0, SchedClass::Deadline, SCHED_DEADLINE);
    assert!(sched::live::sched_fork::dl_fork_refused(&parent));
}

#[test]
fn reset_on_fork_is_how_a_deadline_task_forks() {
    let parent = task(1, 0, SchedClass::Deadline, SCHED_DEADLINE);
    sched::hosted_test::set_reset_on_fork(&parent, true);
    assert!(!sched::live::sched_fork::dl_fork_refused(&parent));
}

#[test]
fn a_deadline_child_is_a_plain_fair_task_carrying_no_reservation() {
    let parent = task(1, 0, SchedClass::Deadline, SCHED_DEADLINE);
    sched::hosted_test::set_deadline_params(&parent, &sched::DlParams::from_request(
        1_000_000, 10_000_000, 10_000_000, 0));
    sched::hosted_test::set_reset_on_fork(&parent, true);
    let mut child = sched::Task::new(2, "sched-policy-test", SchedClass::Normal { weight: 1024 });
    sched::live::sched_fork::inherit_sched_params(&mut child, &parent);
    assert_eq!(task_policy(&child), SCHED_NORMAL);
    assert!(matches!(child.sched_class(), SchedClass::Normal { .. }));
    assert_eq!(child.sched_deadline_snapshot().0.runtime, 0, "no reservation is inherited");
    assert_eq!(child.sched_deadline_bw(), 0);
    assert_eq!(child.nice_value(), 0);
    assert!(!child.priority_snapshot().reset_on_fork);
    // The parent keeps its own reservation.
    assert_eq!(parent.sched_deadline_snapshot().0.runtime, 1_000_000);
}
