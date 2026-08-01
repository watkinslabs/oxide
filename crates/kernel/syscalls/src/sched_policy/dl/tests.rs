// Deadline admission + affinity decisions at the syscall boundary.

use super::*;
use crate::sched_attr::{FLAG_DL_OVERRUN, FLAG_RECLAIM};

const MS: u64 = 1_000_000;
const EBUSY: i64 = -(Errno::Ebusy as i32 as i64);

fn attr(runtime: u64, deadline: u64, period: u64, flags: u64) -> SchedAttr {
    SchedAttr { runtime, deadline, period, flags, ..Default::default() }
}

#[test]
fn an_identical_request_is_not_a_parameter_change() {
    let a = attr(MS, 10 * MS, 10 * MS, 0);
    let cur = attr_params(&a);
    assert!(!dl_param_changed(&cur, &a));
}

#[test]
fn every_field_of_the_reservation_counts_as_a_change() {
    let cur = attr_params(&attr(MS, 10 * MS, 10 * MS, 0));
    assert!(dl_param_changed(&cur, &attr(2 * MS, 10 * MS, 10 * MS, 0)));
    assert!(dl_param_changed(&cur, &attr(MS, 9 * MS, 10 * MS, 0)));
    assert!(dl_param_changed(&cur, &attr(MS, 10 * MS, 20 * MS, 0)));
    // The deadline flags are part of the reservation: turning overrun reporting
    // on must not be silently dropped by the no-change fast path.
    assert!(dl_param_changed(&cur, &attr(MS, 10 * MS, 10 * MS, FLAG_DL_OVERRUN)));
    assert!(dl_param_changed(&cur, &attr(MS, 10 * MS, 10 * MS, FLAG_RECLAIM)));
}

#[test]
fn a_flag_outside_the_deadline_set_is_not_a_reservation_change() {
    // `SCHED_FLAG_RESET_ON_FORK` is not stored on the entity, so a request that
    // only sets it does not re-derive the reservation or re-consult the ledger.
    let cur = attr_params(&attr(MS, 10 * MS, 10 * MS, 0));
    assert!(!dl_param_changed(&cur, &attr(MS, 10 * MS, 10 * MS, 0x01)));
}

#[test]
fn an_omitted_period_matches_the_reservation_it_produced() {
    // A request with `sched_period == 0` describes the same reservation as one
    // naming the deadline, so re-issuing it either way is a no-op.
    let cur = attr_params(&attr(MS, 10 * MS, 0, 0));
    assert!(!dl_param_changed(&cur, &attr(MS, 10 * MS, 10 * MS, 0)));
}

#[test]
fn a_task_that_can_use_every_cpu_covers_the_span() {
    assert!(affinity_covers_span(0b0011, 0b0011));
    assert!(affinity_covers_span(0b0011, 0b1111));
}

#[test]
fn a_task_confined_below_the_span_does_not_cover_it() {
    assert!(!affinity_covers_span(0b0011, 0b0001));
    assert!(!affinity_covers_span(0b1111, 0b0111));
}

#[test]
fn an_unprivileged_deadline_request_needs_the_whole_span_and_a_nonzero_cap() {
    assert!(user_dl_allowed(0b0011, 0b0011, 1024));
    assert!(!user_dl_allowed(0b0011, 0b0001, 1024), "confined below the span");
    assert!(!user_dl_allowed(0b0011, 0b0011, 0), "the class has no bandwidth");
}

#[test]
fn narrowing_a_deadline_tasks_affinity_is_ebusy() {
    // A capacity answer, not a permission or argument one: the reservation was
    // booked against the span and the narrower mask cannot honour it.
    assert_eq!(setaffinity_allowed(true, 0b0011, 0b0001), Err(EBUSY));
}

#[test]
fn a_deadline_task_may_keep_the_whole_span() {
    assert_eq!(setaffinity_allowed(true, 0b0011, 0b0011), Ok(()));
    assert_eq!(setaffinity_allowed(true, 0b0011, 0b1111), Ok(()));
}

#[test]
fn a_non_deadline_task_is_never_refused_on_this_rule() {
    assert_eq!(setaffinity_allowed(false, 0b1111, 0b0001), Ok(()));
}
