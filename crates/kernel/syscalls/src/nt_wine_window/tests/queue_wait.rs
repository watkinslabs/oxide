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

/// The row's scenario: a thread waits on a queue mask plus one event handle,
/// another thread signals the event, and the waiter answers with the object
/// index rather than waiting for the next queue post or timer wake.
#[test]
fn an_object_another_thread_signals_releases_the_wait_with_its_index() {
    let mut signaled = [false, false];
    assert_eq!(step(signaled, false, false), Step::Park);
    assert!(!wake_condition(false, signaled.iter().any(|ready| *ready)));
    signaled[1] = true;
    assert!(wake_condition(false, signaled.iter().any(|ready| *ready)));
    assert_eq!(step(signaled, false, false), Step::Object(1));
    assert_eq!(step_result(step(signaled, false, false), 2), Some(WAIT_OBJECT_0 + 1));
}

#[test]
fn a_queue_post_releases_the_same_wait_at_the_slot_after_the_objects() {
    let signaled = [false, false];
    assert!(wake_condition(true, false));
    assert_eq!(step(signaled, true, false), Step::Queue);
    assert_eq!(step_result(step(signaled, true, false), 2), Some(WAIT_OBJECT_0 + 2));
}

#[test]
fn the_lowest_wait_index_answers_first() {
    assert_eq!(step([true, true], true, true), Step::Object(0));
    assert_eq!(step([false, true], true, true), Step::Object(1));
    assert_eq!(step([false, false], true, true), Step::Queue);
    assert_eq!(step([false, false], false, true), Step::TimedOut);
}

#[test]
fn a_wait_naming_no_object_still_answers_at_the_queue_slot() {
    assert_eq!(step_result(step([], true, false), 0), Some(WAIT_OBJECT_0));
    assert_eq!(step_result(step([], false, true), 0), Some(WAIT_TIMEOUT));
    assert_eq!(step_result(step([], false, false), 0), None);
}
