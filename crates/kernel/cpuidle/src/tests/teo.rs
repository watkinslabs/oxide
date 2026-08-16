use super::*;
use crate::state::Entry;
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

const TICK_NS: u64 = 10_000_000;

#[test]
fn a_count_decays_by_an_eighth_and_then_to_nothing() {
    assert_eq!(decay(1024), 896);
    assert_eq!(decay(8), 7);
    assert_eq!(decay(7), 0, "the last of a count goes at once rather than never");
    assert_eq!(decay(0), 0);
}

#[test]
fn a_fresh_predictor_takes_the_deepest_state_the_sleep_length_allows() {
    let states = ladder();
    let usage = new_usage(&states);
    let mut teo = TeoState::default();
    let chosen = select(&mut teo, &input(&states, &usage, 100_000_000));
    assert_eq!(chosen.index, 3);
    assert!(chosen.stop_tick);
}

#[test]
fn a_sleep_length_short_of_a_state_pulls_the_choice_shallower() {
    let states = ladder();
    let usage = new_usage(&states);
    let mut teo = TeoState::default();
    let chosen = select(&mut teo, &input(&states, &usage, 200_000));
    assert_eq!(chosen.index, 2, "200 us pays for C2 but not for C3");
}

#[test]
fn a_run_of_sleeps_that_ran_to_the_timer_is_recorded_as_hits() {
    let states = ladder();
    let mut teo = TeoState::default();
    teo.sleep_length_ns = 1_000_000;
    for _ in 0..8 {
        // The sleep runs to the timer and a little past it, which is what a
        // real wakeup looks like once the handling is counted.
        teo.update(&states, &Reflection {
            entered: Some(3), measured_ns: 1_020_000, tick_wakeup: false,
            poll_time_limit: false,
        }, TICK_NS);
        teo.sleep_length_ns = 1_000_000;
    }
    assert!(teo.bins[3].hits > 0);
    assert_eq!(teo.bins[3].intercepts, 0);
}

#[test]
fn a_run_of_intercepted_sleeps_pulls_the_next_selection_shallower() {
    let states = ladder();
    let usage = new_usage(&states);
    let mut teo = TeoState::default();
    // The timer says a millisecond every time; something else wakes the CPU
    // after 5 us every time.
    for _ in 0..16 {
        teo.sleep_length_ns = 1_000_000;
        teo.update(&states, &Reflection {
            entered: Some(3), measured_ns: 5_000, tick_wakeup: false, poll_time_limit: false,
        }, TICK_NS);
    }
    assert!(teo.bins[0].intercepts + teo.bins[1].intercepts > 0,
            "a 5 us wakeup lands in one of the two shallowest bins");
    assert_eq!(teo.bins[3].hits, 0, "nothing ran to the timer");
    let chosen = select(&mut teo, &input(&states, &usage, 1_000_000));
    assert!(chosen.index < 3,
            "a CPU whose sleeps keep being cut short must stop trusting the timer");
}

#[test]
fn a_run_of_short_idles_keeps_the_tick_running() {
    let states = ladder();
    let usage = new_usage(&states);
    let mut teo = TeoState::default();
    for _ in 0..16 {
        teo.sleep_length_ns = 1_000;
        teo.update(&states, &Reflection {
            entered: Some(0), measured_ns: 1_000, tick_wakeup: false, poll_time_limit: false,
        }, TICK_NS);
    }
    assert!(2 * teo.short_idles >= teo.total);
    let chosen = select(&mut teo, &input(&states, &usage, 1_000));
    assert!(!chosen.stop_tick);
}

#[test]
fn a_latency_requirement_caps_the_choice() {
    let states = ladder();
    let usage = new_usage(&states);
    let mut teo = TeoState::default();
    let mut capped = input(&states, &usage, 100_000_000);
    capped.latency_req_ns = 40_000;
    assert_eq!(select(&mut teo, &capped).index, 2);
    capped.latency_req_ns = 0;
    assert_eq!(select(&mut teo, &capped).index, 0);
}

#[test]
fn every_state_disabled_but_the_shallowest_leaves_only_that_one() {
    let states = ladder();
    let mut usage = new_usage(&states);
    for slot in usage.iter_mut().skip(1) { slot.set_user_disable(true); }
    let mut teo = TeoState::default();
    assert_eq!(select(&mut teo, &input(&states, &usage, 100_000_000)).index, 0);
}

#[test]
fn a_refused_entry_teaches_the_predictor_nothing() {
    let states = ladder();
    let mut teo = TeoState::default();
    let before = teo.clone();
    reflect(&mut teo, &states, &Reflection {
        entered: None, measured_ns: 0, tick_wakeup: false, poll_time_limit: false,
    }, TICK_NS);
    assert_eq!(teo.bins, before.bins);
    assert_eq!(teo.total, before.total);
}

#[test]
fn a_tick_wakeup_on_a_cpu_that_mostly_wakes_on_ticks_credits_the_deepest_state() {
    let states = ladder();
    let mut teo = TeoState::default();
    for _ in 0..16 {
        teo.sleep_length_ns = 100_000_000;
        teo.update(&states, &Reflection {
            entered: Some(3), measured_ns: TICK_NS, tick_wakeup: true, poll_time_limit: false,
        }, TICK_NS);
    }
    assert!(teo.total_tick > 0);
    assert!(teo.bins[3].hits > 0);
}
