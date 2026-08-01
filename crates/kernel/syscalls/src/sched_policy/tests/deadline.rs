// `SCHED_DEADLINE` at the syscall boundary: admission, the errno precedence
// around it, what `sched_getattr` reports, and the fork rules.
//
// Split from the parent test module at the 500-line cutoff (`08§7`).

use super::super::*;
use super::{dl, normal, privileged, task, EINVAL, EPERM};
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use sched::{SchedClass, Task};
use crate::sched_attr::SchedAttr;
use syscall::errno::Errno;

const EBUSY: i64 = -(Errno::Ebusy as i32 as i64);

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
    let p = t.dl.params();
    assert_eq!(p.runtime, 1_000_000);
    assert_eq!(p.deadline, 10_000_000);
    assert_eq!(p.period, 10_000_000);
    assert_eq!(t.dl.sched().runtime, 1_000_000);
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
    let mut s = t.dl.sched();
    s.runtime = 400_000;
    t.dl.store_sched(&s);

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
    let caller = normal(1, 0);
    privileged(&caller);
    let a = normal(2, 0);
    assert_eq!(setattr(&caller, &a, &dl(9_000_000, 10_000_000, 10_000_000)), 0);
    assert_ne!(sched::deadline::bw::DL_BW.total_bw(), 0);
    // Back to a fair policy: the booking is released, and the entity is inert.
    assert_eq!(setscheduler(&caller, &a, SCHED_NORMAL as i32, 0, 0), 0);
    assert_eq!(sched::deadline::bw::DL_BW.total_bw(), 0);
    assert_eq!(a.dl.params().runtime, 0);
    // ... so the next task of the same size fits.
    let b = normal(3, 0);
    assert_eq!(setattr(&caller, &b, &dl(9_000_000, 10_000_000, 10_000_000)), 0);
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
    assert_eq!(sched::deadline::bw::DL_BW.total_bw(), a.dl.params().bw);
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
    assert_eq!(sched::deadline::bw::DL_BW.total_bw(), a.dl.params().bw);
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
    parent.sched_reset_on_fork.store(true, Ordering::Release);
    assert!(!sched::live::sched_fork::dl_fork_refused(&parent));
}

#[test]
fn a_deadline_child_is_a_plain_fair_task_carrying_no_reservation() {
    let parent = task(1, 0, SchedClass::Deadline, SCHED_DEADLINE);
    parent.dl.set_params(&sched::DlParams::from_request(1_000_000, 10_000_000, 10_000_000, 0));
    parent.sched_reset_on_fork.store(true, Ordering::Release);
    let child = normal(2, 0);
    sched::live::sched_fork::inherit_sched_params(&child, &parent);
    assert_eq!(task_policy(&child), SCHED_NORMAL);
    assert!(matches!(child.sched_class(), SchedClass::Normal { .. }));
    assert_eq!(child.dl.params().runtime, 0, "no reservation is inherited");
    assert_eq!(child.dl.bw(), 0);
    assert_eq!(child.nice.load(Ordering::Acquire), 0);
    assert!(!child.sched_reset_on_fork.load(Ordering::Acquire));
    // The parent keeps its own reservation.
    assert_eq!(parent.dl.params().runtime, 1_000_000);
}

