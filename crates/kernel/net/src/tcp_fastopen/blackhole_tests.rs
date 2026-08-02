// The pause on active fast open: when it starts, how long it lasts, how it
// lengthens, and what ends it.

use super::*;

const SEC: u64 = 1_000_000_000;
const BASE: i64 = 3600;

#[test]
fn a_zero_timeout_turns_the_whole_mechanism_off() {
    let state = Blackhole::new();
    state.disable(0, SEC);
    assert_eq!(state.times(), 0, "nothing is recorded, so nothing has to be unwound");
    assert_eq!(state.pause(0, SEC), Pause::Off);
    assert_eq!(state.pause(BASE, SEC), Pause::Off);
}

#[test]
fn a_namespace_that_never_failed_is_not_paused() {
    assert_eq!(Blackhole::new().pause(BASE, 99 * SEC), Pause::Off);
}

#[test]
fn one_detection_pauses_for_the_configured_base() {
    let state = Blackhole::new();
    state.disable(BASE, SEC);
    assert_eq!(state.pause(BASE, SEC), Pause::Held);
    assert_eq!(state.pause(BASE, SEC + BASE as u64 * SEC - 1), Pause::Held);
    assert_eq!(state.pause(BASE, SEC + BASE as u64 * SEC), Pause::Expired);
}

#[test]
fn each_recurrence_doubles_the_pause() {
    for (times, multiplier) in [(1u32, 1u64), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32),
                                (7, 64)] {
        assert_eq!(pause_ns(BASE, times), multiplier * BASE as u64 * SEC);
    }
}

#[test]
fn the_pause_stops_doubling_at_sixty_four_times_the_base() {
    let ceiling = 64 * BASE as u64 * SEC;
    for times in [7u32, 8, 20, 1000, u32::MAX] {
        assert_eq!(pause_ns(BASE, times), ceiling,
            "an unbounded doubling would turn a transient failure into a permanent one");
    }
}

#[test]
fn a_success_clears_the_recurrence_count_and_ends_the_pause() {
    let state = Blackhole::new();
    state.disable(BASE, SEC);
    state.disable(BASE, SEC);
    assert_eq!(state.times(), 2);
    state.reset();
    assert_eq!(state.pause(BASE, SEC), Pause::Off);
}

#[test]
fn an_expired_pause_reads_apart_from_no_pause_at_all() {
    let state = Blackhole::new();
    state.disable(BASE, 0);
    assert_eq!(state.pause(BASE, 10 * BASE as u64 * SEC), Pause::Expired,
        "the count is only trustworthy while the next open is confirming it");
    assert_eq!(Blackhole::new().pause(BASE, 10 * BASE as u64 * SEC), Pause::Off);
}

#[test]
fn a_connection_that_never_fast_opened_is_no_evidence_about_the_path() {
    for timeouts in 0..4 {
        for expired in [false, true] {
            assert!(!detect(false, false, false, timeouts, expired));
        }
    }
}

#[test]
fn the_third_consecutive_timeout_names_the_path_a_blackhole() {
    assert!(!detect(true, false, false, 0, false));
    assert!(!detect(true, false, false, 1, false));
    assert!(detect(true, false, false, 2, false));
    assert!(!detect(true, false, false, 3, false),
        "one detection per connection: the count passed the trigger already");
}

#[test]
fn running_out_of_retransmit_budget_early_also_names_it() {
    assert!(detect(true, false, false, 0, true));
    assert!(detect(true, false, false, 1, true));
}

#[test]
fn each_of_the_three_fast_open_marks_alone_makes_the_connection_evidence() {
    assert!(detect(true, false, false, 2, false));
    assert!(detect(false, true, false, 2, false));
    assert!(detect(false, false, true, 2, false));
}

#[test]
fn a_recorded_detection_survives_a_timeout_an_administrator_later_turns_on() {
    let state = Blackhole::new();
    state.disable(BASE, SEC);
    // Read against a different base than it was recorded under: the stamp is
    // absolute, the base is read live, so the pause is whatever the current
    // configuration says it is.
    assert_eq!(state.pause(1, SEC + 2 * SEC), Pause::Expired);
    assert_eq!(state.pause(BASE, SEC + 2 * SEC), Pause::Held);
}
