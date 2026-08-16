use super::*;
use crate::limits::LATENCY_UNLIMITED_NS;
use crate::state::{Entry, IdleState};
use crate::usage::{new_usage, StateUsage};

fn state(latency_us: u64, residency_us: u64) -> IdleState {
    IdleState::from_us("C", "", latency_us, residency_us, Entry::Halt)
}

/// POLL, C1 (1/1 us), C2 (40/100 us), C3 (100/400 us).
fn ladder() -> alloc::vec::Vec<IdleState> {
    let mut states = alloc::vec![state(0, 0), state(1, 1), state(40, 100), state(100, 400)];
    states[0].flags |= crate::uapi::FLAG_POLLING;
    states
}

fn input<'a>(states: &'a [IdleState], usage: &'a [StateUsage], latency_ns: u64)
    -> SelectInput<'a>
{
    SelectInput {
        states, usage,
        sleep_length_ns: u64::MAX,
        tick_ns: 10_000_000,
        latency_req_ns: latency_ns,
        tick_stopped: false,
    }
}

#[test]
fn the_deepest_state_worth_a_given_sleep_is_chosen() {
    let states = ladder();
    let usage = new_usage(&states);
    let input = input(&states, &usage, LATENCY_UNLIMITED_NS);
    assert_eq!(deepest_fitting(&input, 0), Some(0));
    assert_eq!(deepest_fitting(&input, 50_000), Some(1));
    assert_eq!(deepest_fitting(&input, 100_000), Some(2));
    assert_eq!(deepest_fitting(&input, 399_999), Some(2));
    assert_eq!(deepest_fitting(&input, 400_000), Some(3));
    assert_eq!(deepest_fitting(&input, u64::MAX), Some(3));
}

#[test]
fn a_latency_requirement_stops_the_scan_at_the_first_state_too_costly_to_leave() {
    let states = ladder();
    let usage = new_usage(&states);
    let input = input(&states, &usage, 40_000);
    assert_eq!(deepest_fitting(&input, u64::MAX), Some(2),
               "C3 costs 100 us to leave and 40 us is all that is tolerated");
    assert_eq!(deepest_within_latency(&input), Some(2));

    let strict = self::input(&states, &usage, 500);
    assert_eq!(deepest_within_latency(&strict), Some(0));
}

#[test]
fn a_disabled_state_is_skipped_and_a_deeper_enabled_one_still_reachable() {
    let states = ladder();
    let mut usage = new_usage(&states);
    usage[2].set_user_disable(true);
    let input = input(&states, &usage, LATENCY_UNLIMITED_NS);
    assert_eq!(deepest_fitting(&input, 200_000), Some(1),
               "C2 is off, and 200 us does not pay for C3");
    assert_eq!(deepest_fitting(&input, u64::MAX), Some(3));
}

#[test]
fn the_shallowest_enabled_state_is_where_a_governor_with_no_answer_lands() {
    let states = ladder();
    let mut usage = new_usage(&states);
    assert_eq!(shallowest_enabled(&input(&states, &usage, LATENCY_UNLIMITED_NS)), 0);
    usage[0].set_user_disable(true);
    usage[1].set_user_disable(true);
    assert_eq!(shallowest_enabled(&input(&states, &usage, LATENCY_UNLIMITED_NS)), 2);
}

#[test]
fn a_correction_downward_finds_the_nearest_enabled_state_that_fits() {
    let states = ladder();
    let usage = new_usage(&states);
    let input = input(&states, &usage, LATENCY_UNLIMITED_NS);
    assert_eq!(shallower_fitting(&input, 3, 150_000), 2);
    assert_eq!(shallower_fitting(&input, 3, 50_000), 1);
    assert_eq!(shallower_fitting(&input, 3, 0), 0);
    assert_eq!(shallower_fitting(&input, 0, 0), 0);
}

#[test]
fn the_tick_may_not_be_stopped_for_a_spin_state_or_a_short_sleep() {
    let states = ladder();
    let usage = new_usage(&states);
    let input = input(&states, &usage, LATENCY_UNLIMITED_NS);
    assert!(!may_stop_tick(&input, 0, u64::MAX), "the CPU is not asleep in a spin state");
    assert!(!may_stop_tick(&input, 3, 1_000_000), "the tick would have fired inside it");
    assert!(may_stop_tick(&input, 3, 20_000_000));
}

#[test]
fn a_tick_already_stopped_stays_stopped() {
    let states = ladder();
    let usage = new_usage(&states);
    let mut input = input(&states, &usage, LATENCY_UNLIMITED_NS);
    input.tick_stopped = true;
    assert!(may_stop_tick(&input, 0, 0));
}
