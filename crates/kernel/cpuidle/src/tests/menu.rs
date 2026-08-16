use super::*;
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

fn input<'a>(states: &'a [IdleState], usage: &'a [StateUsage], sleep_ns: u64)
    -> SelectInput<'a>
{
    SelectInput {
        states, usage,
        sleep_length_ns: sleep_ns,
        tick_ns: 10_000_000,
        latency_req_ns: crate::limits::LATENCY_UNLIMITED_NS,
        tick_stopped: false,
    }
}

#[test]
fn the_bucket_boundaries_are_decades_of_microseconds() {
    assert_eq!(which_bucket(0), 0);
    assert_eq!(which_bucket(9_999), 0);
    assert_eq!(which_bucket(10_000), 1);
    assert_eq!(which_bucket(99_999_000), 4);
    assert_eq!(which_bucket(100_000_000), 5);
    assert_eq!(which_bucket(u64::MAX), 5);
}

#[test]
fn a_fresh_predictor_trusts_the_timer_and_picks_what_that_sleep_pays_for() {
    let states = ladder();
    let usage = new_usage(&states);
    let mut menu = MenuState::default();
    // 5 ms until the next timer: deep enough for C3 (400 us) but the tick at
    // 10 ms is still running, so C3's residency fits inside it.
    let chosen = select(&mut menu, &input(&states, &usage, 5_000_000), states.len());
    assert_eq!(chosen.index, 3);
    assert!(!chosen.stop_tick, "a sleep shorter than the tick cannot justify stopping it");
}

#[test]
fn a_very_short_time_to_the_next_timer_selects_the_shallowest_state() {
    let states = ladder();
    let usage = new_usage(&states);
    let mut menu = MenuState::default();
    let chosen = select(&mut menu, &input(&states, &usage, 500), states.len());
    assert_eq!(chosen.index, 0, "half a microsecond is not worth even C1");
}

#[test]
fn a_zero_latency_requirement_pins_the_shallowest_state() {
    let states = ladder();
    let usage = new_usage(&states);
    let mut menu = MenuState::default();
    let mut strict = input(&states, &usage, u64::MAX);
    strict.latency_req_ns = 0;
    let chosen = select(&mut menu, &strict, states.len());
    assert_eq!(chosen.index, 0);
    assert!(!chosen.stop_tick);
}

#[test]
fn a_latency_requirement_caps_the_depth_however_long_the_sleep() {
    let states = ladder();
    let usage = new_usage(&states);
    let mut menu = MenuState::default();
    let mut capped = input(&states, &usage, 1_000_000_000);
    capped.latency_req_ns = 50_000;
    let chosen = select(&mut menu, &capped, states.len());
    assert_eq!(chosen.index, 2, "C3 costs 100 us to leave; 50 us is the ceiling");
}

#[test]
fn a_repeating_short_interval_is_detected_and_overrides_a_distant_timer() {
    let states = ladder();
    let usage = new_usage(&states);
    let mut menu = MenuState::default();
    // Eight consecutive 20 us sleeps: an interrupt the timer knows nothing of.
    for _ in 0..INTERVALS { menu.intervals[menu.interval_ptr] = 20_000;
                            menu.interval_ptr = (menu.interval_ptr + 1) % INTERVALS; }
    assert_eq!(menu.typical_interval(), Some(20_000));
    let chosen = select(&mut menu, &input(&states, &usage, 1_000_000_000), states.len());
    assert_eq!(chosen.index, 1,
               "20 us pays for C1 but not for C2, however far away the next timer is");
}

#[test]
fn scattered_intervals_are_not_mistaken_for_a_repeat() {
    let mut menu = MenuState::default();
    let samples = [1_000u64, 900_000, 5_000, 400_000, 2_000, 1_000_000, 7_000, 250_000];
    for (slot, value) in samples.iter().enumerate() { menu.intervals[slot] = *value; }
    assert_eq!(menu.typical_interval(), None,
               "a series this scattered has no repeat to act on");
}

#[test]
fn an_empty_history_yields_no_prediction() {
    assert_eq!(MenuState::default().typical_interval(), None);
}

#[test]
fn the_correction_factor_learns_that_sleeps_end_early() {
    let states = ladder();
    let mut menu = MenuState::default();
    menu.bucket = which_bucket(1_000_000);
    menu.next_timer_ns = 1_000_000;
    let before = menu.correction[menu.bucket];
    // Ten sleeps that each ended after a tenth of the predicted time.
    for _ in 0..10 {
        menu.update(&states, &Reflection {
            entered: Some(2), measured_ns: 100_000, tick_wakeup: false, poll_time_limit: false,
        });
        menu.next_timer_ns = 1_000_000;
    }
    assert!(menu.correction[menu.bucket] < before,
            "a predictor that keeps overestimating must scale itself down");
}

#[test]
fn a_learned_correction_factor_shortens_the_prediction() {
    let states = ladder();
    let usage = new_usage(&states);
    // Untrained, a millisecond to the next timer pays for the deepest state.
    let mut fresh = MenuState::default();
    assert_eq!(select(&mut fresh, &input(&states, &usage, 1_000_000), states.len()).index, 3);

    // Trained to expect a tenth of the timer distance, the same input does not.
    let mut trained = MenuState::default();
    let bucket = which_bucket(1_000_000);
    trained.correction[bucket] = RESOLUTION * DECAY / 10;
    let chosen = select(&mut trained, &input(&states, &usage, 1_000_000), states.len());
    assert!(chosen.index < 3,
            "a predictor that has learned the sleeps end early must stop going deep");
}

#[test]
fn a_refused_entry_records_no_usable_sample_rather_than_a_zero() {
    let states = ladder();
    let mut menu = MenuState::default();
    reflect(&mut menu, &states, &Reflection {
        entered: None, measured_ns: 0, tick_wakeup: false, poll_time_limit: false,
    });
    assert_eq!(menu.intervals[0], u64::MAX);
    assert_eq!(menu.typical_interval(), None,
               "a zero here would drag every later prediction toward zero");
}

#[test]
fn a_disabled_deep_state_is_not_selected() {
    let states = ladder();
    let mut usage = new_usage(&states);
    usage[3].set_user_disable(true);
    let mut menu = MenuState::default();
    let chosen = select(&mut menu, &input(&states, &usage, 1_000_000_000), states.len());
    assert_eq!(chosen.index, 2);
}

#[test]
fn a_sleep_beyond_the_tick_period_permits_stopping_it() {
    let states = ladder();
    let usage = new_usage(&states);
    let mut menu = MenuState::default();
    let chosen = select(&mut menu, &input(&states, &usage, 100_000_000), states.len());
    assert_eq!(chosen.index, 3);
    assert!(chosen.stop_tick);
}
