//! Wait-slot arithmetic and result encoding.
use super::*;

#[test]
fn the_queue_takes_the_slot_after_the_named_objects() {
    assert_eq!(queue_result(0), WAIT_OBJECT_0);
    assert_eq!(queue_result(3), WAIT_OBJECT_0 + 3);
    assert_eq!(object_result(2), WAIT_OBJECT_0 + 2);
}

#[test]
fn a_count_that_leaves_no_slot_for_the_queue_is_refused() {
    assert!(count_admitted(0));
    assert!(count_admitted(MAXIMUM_WAIT_OBJECTS - 1));
    assert!(!count_admitted(MAXIMUM_WAIT_OBJECTS));
    assert!(!count_admitted(u32::MAX));
}

#[test]
fn an_infinite_timeout_has_no_deadline_and_a_finite_one_converts_to_nanoseconds() {
    assert_eq!(deadline_ns(1_000, INFINITE), None);
    assert_eq!(deadline_ns(1_000, 0), Some(1_000));
    assert_eq!(deadline_ns(1_000, 5), Some(5_001_000));
    assert_eq!(deadline_ns(u64::MAX, 5), Some(u64::MAX));
}

#[test]
fn only_an_input_available_wait_consults_the_queue_first() {
    assert!(!checks_before_waiting(0));
    assert!(!checks_before_waiting(MWMO_ALERTABLE));
    assert!(checks_before_waiting(MWMO_INPUTAVAILABLE));
    assert!(checks_before_waiting(MWMO_INPUTAVAILABLE | MWMO_ALERTABLE));
}

#[test]
fn wait_message_reports_success_for_every_outcome_but_failure() {
    assert_eq!(wait_message_result(WAIT_OBJECT_0), 1);
    assert_eq!(wait_message_result(WAIT_TIMEOUT), 1);
    assert_eq!(wait_message_result(WAIT_IO_COMPLETION), 1);
    assert_eq!(wait_message_result(WAIT_FAILED), 0);
}
