// Dispatch order for waiting block requests. These encode the behaviour
// verified against the reference deadline scheduler's priority arm.

use super::*;
use sched::ioprio::{prio_value, CLASS_BE, CLASS_IDLE, CLASS_NONE, CLASS_RT};

fn w(class: u32, level: u32, queued_ns: u64) -> Waiting {
    Waiting { ioprio: prio_value(class, level), queued_ns }
}

#[test]
fn an_unset_priority_dispatches_as_best_effort() {
    assert_eq!(dispatch_prio(prio_value(CLASS_NONE, 0)), DispatchPrio::Be);
    assert_eq!(dispatch_prio(prio_value(CLASS_BE, 7)), DispatchPrio::Be);
    assert_eq!(dispatch_prio(prio_value(CLASS_RT, 0)), DispatchPrio::Rt);
    assert_eq!(dispatch_prio(prio_value(CLASS_IDLE, 0)), DispatchPrio::Idle);
    // Undefined classes are not more urgent than best-effort.
    assert_eq!(dispatch_prio(prio_value(5, 0)), DispatchPrio::Be);
}

#[test]
fn an_empty_queue_selects_nothing() {
    assert_eq!(select(&[], 0, PRIO_AGING_EXPIRE_NS), None);
}

#[test]
fn one_class_dispatches_in_arrival_order() {
    let q = [w(CLASS_BE, 0, 30), w(CLASS_BE, 7, 10), w(CLASS_BE, 4, 20)];
    // Level does not reorder within a class; arrival time does.
    assert_eq!(select(&q, 100, PRIO_AGING_EXPIRE_NS), Some(1));
}

#[test]
fn a_real_time_request_starts_before_an_older_best_effort_one() {
    let q = [w(CLASS_BE, 0, 10), w(CLASS_RT, 7, 90)];
    assert_eq!(select(&q, 100, PRIO_AGING_EXPIRE_NS), Some(1));
}

#[test]
fn best_effort_starts_before_idle() {
    let q = [w(CLASS_IDLE, 0, 10), w(CLASS_BE, 7, 90)];
    assert_eq!(select(&q, 100, PRIO_AGING_EXPIRE_NS), Some(1));
}

#[test]
fn an_unset_request_outranks_an_explicit_idle_one() {
    // This is the case that matters in practice: ordinary I/O from a task
    // that never called ioprio_set must not queue behind an idle-class job.
    let q = [w(CLASS_IDLE, 0, 10), w(CLASS_NONE, 0, 90)];
    assert_eq!(select(&q, 100, PRIO_AGING_EXPIRE_NS), Some(1));
}

#[test]
fn the_aging_guard_promotes_a_starved_lower_class() {
    // A best-effort request that has waited past the aging bound goes first
    // even though a real-time request is queued behind it.
    let q = [w(CLASS_RT, 0, 9_000), w(CLASS_BE, 0, 100)];
    assert_eq!(select(&q, 10_000, 1_000), Some(1));
}

#[test]
fn the_aging_guard_prefers_the_more_urgent_starved_class() {
    let q = [w(CLASS_RT, 0, 9_000), w(CLASS_IDLE, 0, 50), w(CLASS_BE, 0, 100)];
    // Both the idle and the best-effort request are past the bound; the
    // best-effort one is the more urgent of the two even though it is younger.
    assert_eq!(select(&q, 10_000, 1_000), Some(2));
}

#[test]
fn the_aging_guard_never_fires_for_a_single_class() {
    // Every request is best-effort and ancient; with nothing to be starved
    // by, plain arrival order still decides.
    let q = [w(CLASS_BE, 0, 200), w(CLASS_BE, 0, 100)];
    assert_eq!(select(&q, 1_000_000, 1), Some(1));
}

#[test]
fn a_request_inside_the_aging_bound_does_not_jump_the_class_order() {
    let q = [w(CLASS_RT, 0, 500), w(CLASS_BE, 0, 400)];
    // The best-effort request has waited 600ns against a 1000ns bound.
    assert_eq!(select(&q, 1_000, 1_000), Some(0));
}

#[test]
fn real_time_requests_are_never_promoted_by_aging() {
    // Aging exists to rescue the classes BELOW real time; a real-time
    // request is already first, so it must not be selected by the guard in
    // preference to an older starved one.
    let q = [w(CLASS_RT, 0, 0), w(CLASS_BE, 0, 10)];
    assert_eq!(select(&q, 1_000_000, 1), Some(1));
}

#[test]
fn a_submitter_priority_fills_in_only_an_unset_request() {
    let rt = prio_value(CLASS_RT, 2);
    let be = prio_value(CLASS_BE, 5);
    assert_eq!(stamp(prio_value(CLASS_NONE, 0), be), be);
    // An explicitly classed request keeps what its caller asked for.
    assert_eq!(stamp(rt, be), rt);
    assert_eq!(stamp(prio_value(CLASS_IDLE, 0), be), prio_value(CLASS_IDLE, 0));
}
