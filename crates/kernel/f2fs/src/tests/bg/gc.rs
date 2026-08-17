//! The cleaner's policy: the sleep walk, the modes, and one wake's decision.
//!
//! Every case here is one the thread would take minutes to reach and that no
//! boot could show: a device the policy calls busy, an urgent mode set while a
//! long sleep was running, a pass that found nothing. The walk is arithmetic
//! and the decision is a branch, so both are checked here rather than watched.

use super::*;
use crate::opts::BackgroundGc;

fn th() -> GcKthread { GcKthread::new() }

fn quiet() -> Conditions {
    Conditions { readonly: false, frozen: false, foreground: false, idle: true, boost: false,
                 can_lock: true }
}

#[test]
fn the_defaults_are_the_intervals_the_format_states() {
    let t = th();
    assert_eq!(t.urgent_sleep_time, 500);
    assert_eq!(t.min_sleep_time, 30_000);
    assert_eq!(t.max_sleep_time, 60_000);
    assert_eq!(t.no_gc_sleep_time, 300_000);
    assert_eq!(t.wait_ms, t.min_sleep_time, "a fresh cleaner starts at the floor");
    assert_eq!(t.mode, GcMode::Normal);
}

#[test]
fn the_walk_steps_up_by_one_step_and_stops_at_the_ceiling() {
    let t = th();
    assert_eq!(t.increase_sleep_time(30_000), 60_000);
    assert_eq!(t.increase_sleep_time(60_000), 60_000, "the ceiling holds");
    assert_eq!(t.increase_sleep_time(45_000), 60_000, "a step past it lands on it");
}

#[test]
fn the_walk_steps_down_by_one_step_and_stops_at_the_floor() {
    let t = th();
    assert_eq!(t.decrease_sleep_time(60_000), 30_000);
    assert_eq!(t.decrease_sleep_time(30_000), 30_000, "the floor holds");
}

#[test]
fn the_long_sleep_is_not_part_of_the_walk() {
    // Stepping up from it would carry the interval past its own ceiling, and
    // a volume that is doing nothing would sleep longer and longer forever.
    let t = th();
    assert_eq!(t.increase_sleep_time(300_000), 300_000);
    // Coming back re-enters the walk at its ceiling and takes one step down
    // from there, rather than staying out at five minutes.
    assert_eq!(t.decrease_sleep_time(300_000), 30_000);
}

#[test]
fn a_read_only_mount_does_nothing_and_the_interval_does_not_move() {
    let mut t = th();
    let before = t.wait_ms;
    let step = gc_round(&mut t, Conditions { readonly: true, ..quiet() }, BackgroundGc::On);
    assert_eq!(step, GcStep::Skip);
    assert_eq!(t.wait_ms, before);
}

#[test]
fn a_frozen_volume_backs_off() {
    let mut t = th();
    let step = gc_round(&mut t, Conditions { frozen: true, ..quiet() }, BackgroundGc::On);
    assert_eq!(step, GcStep::Sleep);
    assert_eq!(t.wait_ms, 60_000, "a writer-held volume is looked at less often");
}

#[test]
fn a_busy_device_backs_off_rather_than_cleaning() {
    let mut t = th();
    let step = gc_round(&mut t, Conditions { idle: false, ..quiet() }, BackgroundGc::On);
    assert_eq!(step, GcStep::Sleep);
    assert_eq!(t.wait_ms, 60_000);
}

#[test]
fn a_pass_already_cleaning_is_not_joined_by_a_second() {
    let mut t = th();
    let before = t.wait_ms;
    let step = gc_round(&mut t, Conditions { can_lock: false, ..quiet() }, BackgroundGc::On);
    assert_eq!(step, GcStep::Sleep);
    assert_eq!(t.wait_ms, before, "and the interval is left where it was");
}

#[test]
fn an_idle_volume_worth_cleaning_cleans_and_looks_again_sooner() {
    let mut t = th();
    t.wait_ms = 60_000;
    let step = gc_round(&mut t, Conditions { boost: true, ..quiet() }, BackgroundGc::On);
    assert_eq!(step, GcStep::Gc { sync: false, foreground: false });
    assert_eq!(t.wait_ms, 30_000);
}

#[test]
fn an_idle_volume_not_worth_cleaning_still_looks_but_less_often() {
    let mut t = th();
    let step = gc_round(&mut t, quiet(), BackgroundGc::On);
    assert_eq!(step, GcStep::Gc { sync: false, foreground: false });
    assert_eq!(t.wait_ms, 60_000);
}

#[test]
fn background_gc_sync_moves_blocks_the_way_the_foreground_does() {
    let mut t = th();
    let step = gc_round(&mut t, quiet(), BackgroundGc::Sync);
    assert_eq!(step, GcStep::Gc { sync: true, foreground: false });
}

#[test]
fn a_blocked_caller_is_never_served_by_the_slower_cost() {
    // The caller is waiting for space. Weighing age against liveness is for a
    // cleaner with time; this one wants the cheapest section there is.
    let mut t = th();
    let c = Conditions { foreground: true, idle: false, ..quiet() };
    let step = gc_round(&mut t, c, BackgroundGc::Sync);
    assert_eq!(step, GcStep::Gc { sync: false, foreground: true });
}

#[test]
fn a_blocked_caller_is_served_even_when_the_device_is_busy() {
    let mut t = th();
    let c = Conditions { foreground: true, idle: false, boost: false, ..quiet() };
    assert!(matches!(gc_round(&mut t, c, BackgroundGc::On), GcStep::Gc { .. }));
}

#[test]
fn an_urgent_mode_runs_at_the_urgent_interval_whatever_the_device_is_doing() {
    for mode in [GcMode::UrgentHigh, GcMode::UrgentMid] {
        let mut t = th();
        t.mode = mode;
        t.wait_ms = 300_000;
        let c = Conditions { idle: false, can_lock: true, ..quiet() };
        assert!(matches!(gc_round(&mut t, c, BackgroundGc::On), GcStep::Gc { .. }));
        assert_eq!(t.wait_ms, 500, "{mode:?} runs at the urgent interval");
    }
}

#[test]
fn the_low_urgency_mode_does_not_shorten_the_interval() {
    // It only claims the device is idle for background work; it is not a
    // request to clean harder.
    let mut t = th();
    t.mode = GcMode::UrgentLow;
    assert!(!t.mode.is_urgent());
    let c = Conditions { idle: false, ..quiet() };
    assert_eq!(gc_round(&mut t, c, BackgroundGc::On), GcStep::Sleep);
}

#[test]
fn a_request_for_a_pass_is_consumed_by_the_pass_it_asked_for() {
    let mut t = th();
    t.gc_wake = true;
    gc_round(&mut t, quiet(), BackgroundGc::On);
    assert!(!t.gc_wake, "or every later wake would think it was asked for");
}

#[test]
fn a_pass_that_found_nothing_sleeps_long() {
    let mut t = th();
    after_gc(&mut t, false, false);
    assert_eq!(t.wait_ms, 300_000);
}

#[test]
fn a_blocked_callers_pass_that_found_nothing_does_not_park_the_thread() {
    // The interval belongs to the background walk. A foreground pass borrowed
    // the thread and must not leave it asleep for five minutes.
    let mut t = th();
    after_gc(&mut t, false, true);
    assert_eq!(t.wait_ms, 30_000);
}

#[test]
fn a_pass_that_cleaned_re_enters_the_walk_at_its_floor() {
    let mut t = th();
    t.wait_ms = 300_000;
    after_gc(&mut t, true, false);
    assert_eq!(t.wait_ms, 30_000);
}

#[test]
fn a_pass_that_cleaned_leaves_an_ordinary_interval_alone() {
    let mut t = th();
    t.wait_ms = 45_000;
    after_gc(&mut t, true, false);
    assert_eq!(t.wait_ms, 45_000);
}

#[test]
fn an_urgent_mode_with_a_limit_lapses_back_to_normal() {
    let mut t = th();
    t.mode = GcMode::UrgentHigh;
    t.remaining_trials = 2;
    t.expire_trial();
    assert_eq!(t.mode, GcMode::UrgentHigh);
    assert_eq!(t.remaining_trials, 1);
    t.expire_trial();
    assert_eq!(t.mode, GcMode::Normal, "the last pass gives the mode back");
}

#[test]
fn an_urgent_mode_without_a_limit_does_not_lapse() {
    let mut t = th();
    t.mode = GcMode::UrgentHigh;
    for _ in 0..8 { t.expire_trial(); }
    assert_eq!(t.mode, GcMode::UrgentHigh);
}

#[test]
fn the_mode_numbers_are_the_ones_written_and_read_back() {
    for (n, m) in [(0, GcMode::Normal), (1, GcMode::IdleCb), (2, GcMode::IdleGreedy),
                   (3, GcMode::IdleAt), (4, GcMode::UrgentHigh), (5, GcMode::UrgentLow),
                   (6, GcMode::UrgentMid)] {
        assert_eq!(GcMode::from_u32(n), Some(m));
        assert_eq!(m.as_u32(), n);
    }
    assert_eq!(GcMode::from_u32(7), None);
}

#[test]
fn the_idle_modes_name_which_cost_a_pass_uses() {
    use crate::volume::gc::Policy;
    assert_eq!(GcMode::IdleGreedy.idle_policy(), Some(Policy::Greedy));
    assert_eq!(GcMode::IdleCb.idle_policy(), Some(Policy::CostBenefit));
    assert_eq!(GcMode::Normal.idle_policy(), None);
}

#[test]
fn only_the_high_mode_claims_the_device_is_idle_for_everything() {
    use crate::bg::gc::IdleKind;
    assert!(GcMode::UrgentHigh.claims_idle(IdleKind::Request));
    assert!(!GcMode::UrgentLow.claims_idle(IdleKind::Request));
    assert!(GcMode::UrgentLow.claims_idle(IdleKind::Gc));
    assert!(GcMode::UrgentLow.claims_idle(IdleKind::Discard));
    assert!(!GcMode::Normal.claims_idle(IdleKind::Gc));
}

#[test]
fn a_volume_touched_moments_ago_is_not_idle() {
    use crate::bg::gc::{is_idle, IdleKind, IDLE_INTERVAL_SECS};
    assert!(!is_idle(GcMode::Normal, IdleKind::Gc, 100, 100));
    assert!(!is_idle(GcMode::Normal, IdleKind::Gc, 100 + IDLE_INTERVAL_SECS, 100));
    assert!(is_idle(GcMode::Normal, IdleKind::Gc, 101 + IDLE_INTERVAL_SECS, 100));
    assert!(is_idle(GcMode::UrgentHigh, IdleKind::Gc, 100, 100), "urgent does not wait");
}

#[test]
fn cleaning_is_worth_it_only_when_dead_space_is_high_and_free_space_is_low() {
    use crate::bg::gc::has_enough_invalid_blocks;
    // Half the volume dead and almost nothing free: worth the writes.
    assert!(has_enough_invalid_blocks(1000, 500, 100, 0));
    // Half dead but a third of the volume free: the next write has somewhere
    // to go, and the blocks a pass would move may die on their own.
    assert!(!has_enough_invalid_blocks(1000, 500, 300, 0));
    // Barely anything dead: nothing to reclaim.
    assert!(!has_enough_invalid_blocks(1000, 900, 10, 0));
    // Overprovisioning is not free space and does not count as room.
    assert!(has_enough_invalid_blocks(1000, 500, 300, 250));
}
