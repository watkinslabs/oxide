use super::*;

#[test]
fn no_limit_admits_everything() {
    let mut st = RateState::default();
    for i in 0..10_000 { assert!(rate_check(&mut st, 0, i)); }
    assert_eq!(st, RateState::default(), "an unlimited stream charges no state");
}

/// The window holds `limit - 1` records before it starts refusing: the record
/// that reaches the limit is the one the window can no longer take.
#[test]
fn a_limit_admits_until_the_window_is_full() {
    let mut st = RateState { messages: 0, last_check_ms: 0 };
    for _ in 0..4 { assert!(rate_check(&mut st, 5, 500)); }
    assert!(!rate_check(&mut st, 5, 500), "the fifth is refused inside the window");
    assert!(!rate_check(&mut st, 5, 1_000));
}

/// A whole second past the last rollover reopens the window, and the record
/// that reopened it is admitted.
#[test]
fn the_window_reopens_after_a_second() {
    let mut st = RateState { messages: 0, last_check_ms: 0 };
    for _ in 0..4 { assert!(rate_check(&mut st, 5, 100)); }
    assert!(!rate_check(&mut st, 5, 1_000), "exactly one second is not yet past");
    assert!(rate_check(&mut st, 5, 1_001));
    assert_eq!(st.messages, 0);
    assert_eq!(st.last_check_ms, 1_001);
    for _ in 0..4 { assert!(rate_check(&mut st, 5, 1_100)); }
    assert!(!rate_check(&mut st, 5, 1_500));
}

/// A limit of one refuses every record but the ones that roll the window over,
/// which is the tightest the ceiling goes without being an off switch.
#[test]
fn a_limit_of_one_admits_one_record_per_window() {
    let mut st = RateState { messages: 0, last_check_ms: 0 };
    assert!(!rate_check(&mut st, 1, 10), "the window has no room before it rolls");
    assert!(rate_check(&mut st, 1, 1_100));
    assert!(!rate_check(&mut st, 1, 1_200));
    assert!(rate_check(&mut st, 1, 2_200));
}

#[test]
fn the_lost_warning_is_unthrottled_without_a_rate_limit() {
    let mut last = 0u64;
    assert!(lost_print_check(&mut last, 0, false, 5));
    assert!(lost_print_check(&mut last, 0, false, 6));
    assert_eq!(last, 0, "an unthrottled warning does not charge the window");
}

#[test]
fn the_lost_warning_is_throttled_to_one_per_second_under_a_rate_limit() {
    let mut last = 0u64;
    assert!(lost_print_check(&mut last, 10, false, 1_500));
    assert_eq!(last, 1_500);
    assert!(!lost_print_check(&mut last, 10, false, 2_000));
    assert!(lost_print_check(&mut last, 10, false, 2_501));
}

/// A failure mode that must be noisy outranks the throttle.
#[test]
fn an_always_print_failure_mode_is_never_throttled() {
    let mut last = 5_000u64;
    assert!(lost_print_check(&mut last, 10, true, 5_001));
    assert!(lost_print_check(&mut last, 10, true, 5_002));
}
