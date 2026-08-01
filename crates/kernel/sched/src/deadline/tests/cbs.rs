// CBS throttle / replenish edges. These are the tests that make the class a
// real-time guarantee rather than a priority label: a task that overruns is
// thrown off here, in `cargo test`, not merely in theory.

use super::super::cbs::*;
use super::super::params::DlParams;

const MS: u64 = 1_000_000;

/// 2 ms every 10 ms, implicit deadline.
fn p2of10() -> DlParams { DlParams::from_request(2 * MS, 10 * MS, 10 * MS, 0) }

fn started(p: &DlParams, now: u64) -> DlSched {
    let mut s = DlSched::default();
    replenish_new_period(p, &mut s, now);
    s
}

#[test]
fn a_fresh_instance_grants_the_full_budget_and_a_relative_deadline() {
    let p = p2of10();
    let s = started(&p, 1_000);
    assert_eq!(s.runtime, 2 * MS as i64);
    assert_eq!(s.deadline, 1_000 + 10 * MS);
    assert!(!s.throttled);
}

#[test]
fn running_inside_the_budget_does_not_throttle() {
    let p = p2of10();
    let mut s = started(&p, 0);
    assert_eq!(charge(&p, &mut s, MS), Charged::Running);
    assert_eq!(s.runtime, MS as i64);
    assert!(!s.throttled);
}

#[test]
fn exhausting_the_budget_throttles_the_task() {
    let p = p2of10();
    let mut s = started(&p, 0);
    assert_eq!(charge(&p, &mut s, 2 * MS), Charged::Throttle);
    assert!(s.throttled);
    assert!(runtime_exceeded(&s));
}

#[test]
fn an_exactly_spent_budget_counts_as_exhausted() {
    // Zero remaining must throttle: letting the task back on the CPU would
    // spend the next interval's budget before it was granted.
    let p = p2of10();
    let mut s = started(&p, 0);
    charge(&p, &mut s, 2 * MS);
    assert_eq!(s.runtime, 0);
    assert!(s.throttled);
}

#[test]
fn an_overrun_is_recorded_as_debt_not_clamped_to_zero() {
    let p = p2of10();
    let mut s = started(&p, 0);
    charge(&p, &mut s, 5 * MS);
    assert_eq!(s.runtime, -(3 * MS as i64));
}

#[test]
fn overrun_debt_costs_proportionally_many_periods() {
    // Three budgets consumed in one instance means three postponed deadlines,
    // not one free reset — otherwise an overrunning task keeps its urgency.
    let p = p2of10();
    let mut s = started(&p, 0);
    let first_deadline = s.deadline;
    charge(&p, &mut s, 6 * MS);
    assert_eq!(s.runtime, -(4 * MS as i64));
    replenish(&p, &mut s, 6 * MS);
    assert_eq!(s.deadline, first_deadline + 3 * 10 * MS);
    assert_eq!(s.runtime, 2 * MS as i64);
    assert!(!s.throttled);
}

#[test]
fn replenishment_advances_exactly_one_period_for_a_plain_exhaustion() {
    let p = p2of10();
    let mut s = started(&p, 0);
    let d0 = s.deadline;
    charge(&p, &mut s, 2 * MS);
    replenish(&p, &mut s, 2 * MS);
    assert_eq!(s.deadline, d0 + 10 * MS);
    assert_eq!(s.runtime, 2 * MS as i64);
}

#[test]
fn the_overrun_signal_latch_is_raised_only_when_requested() {
    let plain = p2of10();
    let mut s = started(&plain, 0);
    charge(&plain, &mut s, 3 * MS);
    assert!(!s.overrun);

    let want = DlParams::from_request(2 * MS, 10 * MS, 10 * MS, super::super::params::FLAG_DL_OVERRUN);
    let mut s = started(&want, 0);
    charge(&want, &mut s, 3 * MS);
    assert!(s.overrun);
}

#[test]
fn a_yield_throttles_regardless_of_remaining_budget_and_without_elapsed_time() {
    let p = p2of10();
    let mut s = started(&p, 0);
    s.yielded = true;
    assert_eq!(charge(&p, &mut s, 0), Charged::Throttle);
    assert!(s.throttled);
    // A yield is not an overrun: no signal is owed.
    assert!(!s.overrun);
}

#[test]
fn a_yield_donates_the_rest_of_the_instance_and_costs_exactly_one_period() {
    let p = p2of10();
    let mut s = started(&p, 0);
    let d0 = s.deadline;
    s.yielded = true;
    charge(&p, &mut s, 0);
    replenish(&p, &mut s, MS);
    assert_eq!(s.deadline, d0 + 10 * MS);
    assert_eq!(s.runtime, 2 * MS as i64);
    assert!(!s.yielded);
    assert!(!s.throttled);
}

#[test]
fn a_governor_entity_never_consumes_budget() {
    let p = DlParams::from_request(0, 0, 0, super::super::params::FLAG_SUGOV);
    let mut s = DlSched::default();
    assert_eq!(charge(&p, &mut s, 1_000 * MS), Charged::Running);
    assert_eq!(s.runtime, 0);
    assert!(!s.throttled);
}

#[test]
fn deadline_comparison_is_strict_so_a_tie_never_wins() {
    assert!(dl_time_before(5, 6));
    assert!(!dl_time_before(6, 5));
    assert!(!dl_time_before(5, 5));
}

#[test]
fn deadline_comparison_survives_clock_wrap() {
    let late = u64::MAX - 10;
    let early_after_wrap = 10u64;
    assert!(dl_time_before(late, early_after_wrap));
    assert!(!dl_time_before(early_after_wrap, late));
}

#[test]
fn the_next_period_of_an_implicit_entity_is_its_deadline() {
    let p = p2of10();
    let s = started(&p, 0);
    assert_eq!(dl_next_period(&p, &s), s.deadline);
}

#[test]
fn the_next_period_of_a_constrained_entity_is_past_its_deadline() {
    // 2 ms budget, must finish 5 ms in, repeats every 20 ms.
    let p = DlParams::from_request(2 * MS, 5 * MS, 20 * MS, 0);
    let s = started(&p, 0);
    assert_eq!(s.deadline, 5 * MS);
    assert_eq!(dl_next_period(&p, &s), 20 * MS);
}

#[test]
fn a_wakeup_that_respects_the_reservation_keeps_its_instance() {
    // Ran 0.5 ms of its 2 ms budget in the first 2.5 ms of a 10 ms instance:
    // the remaining 1.5 ms over the remaining 7.5 ms is exactly the admitted
    // 2/10 density, so nothing is taken away.
    let p = p2of10();
    let mut s = started(&p, 0);
    charge(&p, &mut s, 500_000);
    let before = s;
    update_dl_entity(&p, &mut s, 2_500_000);
    assert_eq!(s, before);
}

#[test]
fn a_wakeup_that_banked_budget_across_a_sleep_loses_the_instance() {
    // Slept the first millisecond without running: keeping the full 2 ms budget
    // against 9 ms of laxity is a higher density than was admitted, so the
    // instance restarts rather than letting it run ahead of its reservation.
    let p = p2of10();
    let mut s = started(&p, 0);
    assert!(dl_entity_overflow(&p, &s, MS));
    update_dl_entity(&p, &mut s, MS);
    assert_eq!(s.deadline, MS + 10 * MS);
}

#[test]
fn a_wakeup_that_would_exceed_the_reservation_starts_a_new_instance() {
    // Nearly the whole instance elapsed but the budget is untouched — running
    // 2 ms in the remaining 0.5 ms would be four times the admitted density.
    let p = p2of10();
    let mut s = started(&p, 0);
    let now = 9 * MS + 500_000;
    assert!(dl_entity_overflow(&p, &s, now));
    update_dl_entity(&p, &mut s, now);
    assert_eq!(s.deadline, now + 10 * MS);
    assert_eq!(s.runtime, 2 * MS as i64);
}

#[test]
fn a_wakeup_after_the_deadline_passed_starts_a_new_instance() {
    let p = p2of10();
    let mut s = started(&p, 0);
    update_dl_entity(&p, &mut s, 50 * MS);
    assert_eq!(s.deadline, 60 * MS);
    assert_eq!(s.runtime, 2 * MS as i64);
}

#[test]
fn a_constrained_entity_waking_before_its_deadline_keeps_it_and_shrinks_the_budget() {
    // Density is 2/5ms; with 2 ms of laxity left it may have 0.8 ms, not 2 ms.
    let p = DlParams::from_request(2 * MS, 5 * MS, 20 * MS, 0);
    let mut s = started(&p, 0);
    update_dl_entity(&p, &mut s, 3 * MS);
    assert_eq!(s.deadline, 5 * MS, "the deadline must not move");
    let want = (p.density as u128 * (2 * MS) as u128) >> super::super::params::BW_SHIFT;
    assert_eq!(s.runtime, want as i64);
    assert!(s.runtime < 2 * MS as i64);
}

#[test]
fn a_constrained_entity_between_deadline_and_next_period_must_wait() {
    let p = DlParams::from_request(2 * MS, 5 * MS, 20 * MS, 0);
    let mut s = started(&p, 0);
    // 8 ms in: the deadline (5 ms) has passed, the next period (20 ms) has not.
    assert!(check_constrained(&p, &mut s, 8 * MS));
    assert!(s.throttled);
    assert_eq!(s.runtime, 0);
}

#[test]
fn an_implicit_entity_is_never_constrained_throttled() {
    let p = p2of10();
    let mut s = started(&p, 0);
    assert!(!check_constrained(&p, &mut s, 50 * MS));
    assert!(!s.throttled);
}

#[test]
fn replenishment_never_hands_back_a_deadline_already_in_the_past() {
    // Parked far beyond many periods: walking forward one period at a time
    // would still land behind `now`, handing the task an instantly-expired
    // instance that outranks every other deadline task on the machine.
    let p = p2of10();
    let mut s = started(&p, 0);
    charge(&p, &mut s, 2 * MS);
    replenish(&p, &mut s, 10_000 * MS);
    assert!(!dl_time_before(s.deadline, 10_000 * MS));
    assert_eq!(s.runtime, 2 * MS as i64);
}

#[test]
fn setup_of_a_stale_entity_restarts_the_period_but_leaves_a_throttled_one_alone() {
    let p = p2of10();
    let mut s = started(&p, 0);
    setup_new_entity(&p, &mut s, 100 * MS);
    assert_eq!(s.deadline, 110 * MS);

    let mut t = started(&p, 0);
    t.throttled = true;
    let before = t;
    setup_new_entity(&p, &mut t, 100 * MS);
    assert_eq!(t, before, "a throttled entity is owned by its replenishment");
}

#[test]
fn reclaim_charges_no_more_than_wall_time() {
    // The reclaimed share is bounded by the global cap, so a reclaiming task is
    // never charged MORE than a plain one for the same interval.
    let p = DlParams::from_request(2 * MS, 10 * MS, 10 * MS, super::super::params::FLAG_RECLAIM);
    let max_bw = super::super::params::BW_UNIT;
    let charged = grub_reclaim(MS, &p, p.bw, p.bw, max_bw, 0, 1 << super::super::params::RATIO_SHIFT);
    assert!(charged <= MS);
}

#[test]
fn reclaim_charges_less_when_admitted_bandwidth_sits_idle() {
    // Half the runqueue's assigned utilization is not contending, so the
    // running entity may use it and is charged slower than wall time.
    let p = DlParams::from_request(2 * MS, 10 * MS, 10 * MS, super::super::params::FLAG_RECLAIM);
    let max_bw = super::super::params::BW_UNIT;
    let this_bw = max_bw;
    let ratio = 1u64 << super::super::params::RATIO_SHIFT;
    let busy = grub_reclaim(MS, &p, this_bw, this_bw, max_bw, 0, ratio);
    let idle = grub_reclaim(MS, &p, this_bw, this_bw / 2, max_bw, 0, ratio);
    assert!(idle < busy, "idle deadline bandwidth must slow the charge");
}
