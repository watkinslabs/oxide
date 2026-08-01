// Admission arithmetic: what the scheduler will and will not promise.

use super::super::bw::*;
use super::super::params::{to_ratio, BW_UNIT};

const MS: u64 = 1_000_000;
const ONE_CPU: u64 = CAPACITY_SCALE;

fn u(runtime_ms: u64, period_ms: u64) -> u64 { to_ratio(period_ms * MS, runtime_ms * MS) }

#[test]
fn one_cpu_of_capacity_admits_exactly_one_cpu_of_bandwidth() {
    assert_eq!(cap_scale(BW_UNIT, ONE_CPU), BW_UNIT);
    assert_eq!(capacity_of(4), 4 * ONE_CPU);
}

#[test]
fn a_task_set_that_exactly_fills_the_cap_is_admissible() {
    // Strict comparison: 100% is schedulable by EDF, so refusing it would
    // reject a valid task set.
    assert!(!dl_overflow(BW_UNIT, ONE_CPU, 0, 0, BW_UNIT));
}

#[test]
fn one_unit_past_the_cap_is_refused() {
    assert!(dl_overflow(BW_UNIT, ONE_CPU, 0, 0, BW_UNIT + 1));
}

#[test]
fn the_admitted_total_is_summed_undivided_against_a_capacity_scaled_cap() {
    // Four CPUs admit four CPUs' worth. Mixing the conventions is what makes
    // an SMP machine admit N times too much or N times too little.
    let cap = capacity_of(4);
    assert!(!dl_overflow(BW_UNIT, cap, 0, 0, 4 * BW_UNIT));
    assert!(dl_overflow(BW_UNIT, cap, 0, 0, 4 * BW_UNIT + 1));
}

#[test]
fn a_disabled_cap_admits_everything() {
    assert!(!dl_overflow(BW_DISABLED, ONE_CPU, u64::MAX / 2, 0, u64::MAX / 2));
}

#[test]
fn replacing_a_reservation_only_charges_the_difference() {
    // A task already holding 50% asking for 60% needs 10% of headroom, not 60%
    // — judged as a fresh 60% on top of the existing 50% it would be refused.
    let half = u(5, 10);
    let sixty = u(6, 10);
    assert!(!dl_overflow(BW_UNIT, ONE_CPU, half, half, sixty));
    // Judged as a fresh reservation on top of its own, the same request fails.
    assert!(dl_overflow(BW_UNIT, ONE_CPU, half, 0, sixty));
    // A task holding 50% asking for 60% when another 50% is admitted elsewhere
    // genuinely does not fit.
    assert!(dl_overflow(BW_UNIT, ONE_CPU, BW_UNIT, half, sixty));
}

#[test]
fn entering_the_class_is_planned_as_an_add() {
    let want = u(2, 10);
    let plan = plan(BW_UNIT, ONE_CPU, 0, true, false, 0, want, false).expect("fits");
    assert_eq!(plan, BwChange::Add { new: want });
}

#[test]
fn entering_the_class_over_capacity_is_refused() {
    let want = u(6, 10);
    // 50% already admitted; another 60% does not fit in one CPU.
    assert!(plan(BW_UNIT, ONE_CPU, u(5, 10), true, false, 0, want, false).is_err());
}

#[test]
fn changing_parameters_is_planned_as_a_replace() {
    let old = u(2, 10);
    let new = u(3, 10);
    let plan = plan(BW_UNIT, ONE_CPU, old, true, true, old, new, false).expect("fits");
    assert_eq!(plan, BwChange::Replace { old, new });
}

#[test]
fn changing_parameters_is_judged_against_the_headroom_the_task_already_holds() {
    // The whole CPU is admitted and this task holds 60% of it; asking for 70%
    // needs only 10% more, so it must be judged as a replacement.
    let old = u(6, 10);
    let new = u(7, 10);
    assert!(plan(BW_UNIT, ONE_CPU, BW_UNIT, true, true, old, new, false).is_err());
    let total = old;
    assert!(plan(BW_UNIT, ONE_CPU, total, true, true, old, new, false).is_ok());
}

#[test]
fn re_requesting_the_identical_reservation_is_free() {
    let bw = u(2, 10);
    // Even at a completely full cap: nothing is being asked for.
    let plan = plan(BW_UNIT, ONE_CPU, BW_UNIT, true, true, bw, bw, false).expect("no-op");
    assert_eq!(plan, BwChange::None);
}

#[test]
fn leaving_the_class_does_not_release_the_reservation_at_the_request() {
    // The booking stands until the entity genuinely stops contending. Releasing
    // it here would let a leave-and-rejoin pair double-book the same CPU.
    let plan = plan(BW_UNIT, ONE_CPU, BW_UNIT, false, true, BW_UNIT, 0, false).expect("allowed");
    assert_eq!(plan, BwChange::Leaving);
}

#[test]
fn a_governor_entity_is_outside_the_ledger() {
    let plan = plan(BW_UNIT, ONE_CPU, BW_UNIT, true, false, 0, BW_UNIT, true).expect("bypasses");
    assert_eq!(plan, BwChange::None);
}

#[test]
fn a_non_deadline_request_from_a_non_deadline_task_touches_nothing() {
    assert_eq!(plan(BW_UNIT, ONE_CPU, 0, false, false, 0, 0, false).unwrap(), BwChange::None);
}

#[test]
fn the_ledger_sums_and_releases() {
    let b = DlBw::new();
    b.init(GLOBAL_RT_PERIOD_NS, GLOBAL_RT_RUNTIME_NS);
    assert_eq!(b.bw(), BW_UNIT);
    b.apply(BwChange::Add { new: u(2, 10) });
    assert_eq!(b.total_bw(), u(2, 10));
    b.apply(BwChange::Replace { old: u(2, 10), new: u(5, 10) });
    assert_eq!(b.total_bw(), u(5, 10));
    b.release(u(5, 10));
    assert_eq!(b.total_bw(), 0);
}

#[test]
fn a_release_never_underflows_the_ledger() {
    let b = DlBw::new();
    b.init(GLOBAL_RT_PERIOD_NS, GLOBAL_RT_RUNTIME_NS);
    b.release(u(5, 10));
    assert_eq!(b.total_bw(), 0);
}

#[test]
fn a_negative_global_runtime_disables_admission_control() {
    let b = DlBw::new();
    b.init(GLOBAL_RT_PERIOD_NS, u64::MAX);
    assert_eq!(b.bw(), BW_DISABLED);
    assert!(b.fits(0, 1));
}

#[test]
fn a_narrowed_cpu_set_is_refused_when_its_capacity_is_reserved() {
    let b = DlBw::new();
    b.init(GLOBAL_RT_PERIOD_NS, GLOBAL_RT_RUNTIME_NS);
    // 1.5 CPUs admitted across 2 CPUs.
    b.apply(BwChange::Add { new: BW_UNIT + BW_UNIT / 2 });
    assert!(!b.fits(capacity_of(1), 1));
}

#[test]
fn a_narrowed_cpu_set_is_allowed_when_the_rest_still_fits() {
    let b = DlBw::new();
    b.init(GLOBAL_RT_PERIOD_NS, GLOBAL_RT_RUNTIME_NS);
    b.apply(BwChange::Add { new: BW_UNIT / 2 });
    assert!(b.fits(capacity_of(1), 1));
}

#[test]
fn an_empty_cpu_set_never_serves_a_live_reservation() {
    let b = DlBw::new();
    b.init(GLOBAL_RT_PERIOD_NS, GLOBAL_RT_RUNTIME_NS);
    b.apply(BwChange::Add { new: 1 });
    assert!(!b.fits(capacity_of(0), 0));
}

#[test]
fn an_empty_ledger_fits_any_cpu_set() {
    let b = DlBw::new();
    b.init(GLOBAL_RT_PERIOD_NS, GLOBAL_RT_RUNTIME_NS);
    assert!(b.fits(capacity_of(0), 0));
}

#[test]
fn narrowing_the_cpu_set_below_the_admitted_total_does_not_fit() {
    let b = DlBw::new();
    b.init(GLOBAL_RT_PERIOD_NS, GLOBAL_RT_RUNTIME_NS);
    b.apply(BwChange::Add { new: 2 * BW_UNIT });
    assert!(b.fits(capacity_of(2), 2));
    assert!(!b.fits(capacity_of(1), 1));
}
