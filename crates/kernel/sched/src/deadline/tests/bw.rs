// Admission arithmetic: what the scheduler will and will not promise.

use super::super::bw::*;
use super::super::params::{to_ratio, BW_UNIT};
use std::sync::{Arc, Barrier};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::vec::Vec;

const MS: u64 = 1_000_000;
const ONE_CPU: u64 = CAPACITY_SCALE;

fn u(runtime_ms: u64, period_ms: u64) -> u64 { to_ratio(period_ms * MS, runtime_ms * MS) }

fn book(b: &DlBw, cap: u64, bw: u64) {
    b.admit(cap, true, false, 0, bw, false).expect("reservation fits");
}

static TEST_ONLINE: AtomicU64 = AtomicU64::new(0);
static OFFLINE_IN_MARK: AtomicBool = AtomicBool::new(false);
static ALLOW_OFFLINE_MARK: AtomicBool = AtomicBool::new(false);
static GATE_ONLINE: AtomicU64 = AtomicU64::new(0);

fn test_online_cpus() -> u64 { TEST_ONLINE.load(Ordering::Acquire) }
fn test_cpu_online(cpu: u32) -> bool { cpu < TEST_ONLINE.load(Ordering::Acquire) as u32 }

unsafe fn test_mark_offline(_cpu: u32) -> bool {
    OFFLINE_IN_MARK.store(true, Ordering::Release);
    while !ALLOW_OFFLINE_MARK.load(Ordering::Acquire) { std::thread::yield_now(); }
    TEST_ONLINE.fetch_update(Ordering::AcqRel, Ordering::Acquire,
        |n| if n == 0 { None } else { Some(n - 1) }).is_ok()
}

fn gate_online_cpus() -> u64 { GATE_ONLINE.load(Ordering::Acquire) }
fn gate_cpu_online(cpu: u32) -> bool { cpu < GATE_ONLINE.load(Ordering::Acquire) as u32 }

unsafe fn gate_mark_offline(_cpu: u32) -> bool {
    GATE_ONLINE.fetch_update(Ordering::AcqRel, Ordering::Acquire,
        |n| if n == 0 { None } else { Some(n - 1) }).is_ok()
}

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
fn special_to_ordinary_is_an_add_not_a_fake_replacement() {
    let fake = u(1, 10);
    let ordinary = u(3, 10);
    assert_eq!(plan_transition(BW_UNIT, ONE_CPU, 0, true, true,
        fake, ordinary, true, false).unwrap(), BwChange::Add { new: ordinary });
}

#[test]
fn ordinary_to_special_defers_the_old_booking_and_never_adds_the_fake_one() {
    let ordinary = u(3, 10);
    let fake = u(1, 10);
    assert_eq!(plan_transition(BW_UNIT, ONE_CPU, ordinary, true, true,
        ordinary, fake, false, true).unwrap(), BwChange::Leaving);
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
    book(&b, ONE_CPU, u(2, 10));
    assert_eq!(b.total_bw(), u(2, 10));
    b.admit(ONE_CPU, true, true, u(2, 10), u(5, 10), false).expect("replacement fits");
    assert_eq!(b.total_bw(), u(5, 10));
    b.release(u(5, 10));
    assert_eq!(b.total_bw(), 0);
}

#[test]
#[should_panic(expected = "deadline bandwidth double release")]
fn releasing_an_unbooked_reservation_is_an_invariant_failure() {
    let b = DlBw::new();
    b.init(GLOBAL_RT_PERIOD_NS, GLOBAL_RT_RUNTIME_NS);
    b.release(u(5, 10));
}

#[test]
fn exact_release_subtracts_once_and_preserves_other_bookings() {
    let b = DlBw::new();
    b.init(GLOBAL_RT_PERIOD_NS, GLOBAL_RT_RUNTIME_NS);
    let twenty = u(2, 10);
    let thirty = u(3, 10);
    book(&b, ONE_CPU, twenty);
    book(&b, ONE_CPU, thirty);
    b.release(twenty);
    assert_eq!(b.total_bw(), thirty);
}

#[test]
fn saturating_release_positive_control_hides_a_double_release() {
    let booked = u(2, 10);
    let impossible_second_release = booked.saturating_sub(booked).saturating_sub(booked);
    assert_eq!(impossible_second_release, 0,
        "control must show saturation converting corruption into an empty ledger");
}

#[test]
#[should_panic(expected = "deadline bandwidth replacement overflow")]
fn impossible_committed_replacement_is_an_invariant_failure() {
    let _ = changed_total(1, BwChange::Replace { old: 2, new: 1 });
}

#[test]
fn saturating_replace_positive_control_hides_a_missing_old_booking() {
    let hidden = 1u64.saturating_sub(2).saturating_add(1);
    assert_eq!(hidden, 1,
        "control must show saturation manufacturing a valid-looking total");
}

#[test]
#[should_panic(expected = "deadline bandwidth prospective total overflow")]
fn overflow_check_rejects_an_impossible_missing_old_booking() {
    let _ = dl_overflow(BW_UNIT, ONE_CPU, 1, 2, 1);
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
    book(&b, capacity_of(2), BW_UNIT + BW_UNIT / 2);
    assert!(!b.fits(capacity_of(1), 1));
}

#[test]
fn a_narrowed_cpu_set_is_allowed_when_the_rest_still_fits() {
    let b = DlBw::new();
    b.init(GLOBAL_RT_PERIOD_NS, GLOBAL_RT_RUNTIME_NS);
    book(&b, ONE_CPU, BW_UNIT / 2);
    assert!(b.fits(capacity_of(1), 1));
}

#[test]
fn an_empty_cpu_set_never_serves_a_live_reservation() {
    let b = DlBw::new();
    b.init(GLOBAL_RT_PERIOD_NS, GLOBAL_RT_RUNTIME_NS);
    book(&b, ONE_CPU, 1);
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
    book(&b, capacity_of(2), 2 * BW_UNIT);
    assert!(b.fits(capacity_of(2), 2));
    assert!(!b.fits(capacity_of(1), 1));
}

#[test]
fn split_check_then_commit_positive_control_overcommits() {
    let total = Arc::new(AtomicU64::new(0));
    let planned = Arc::new(Barrier::new(2));
    let sixty = u(6, 10);
    let mut workers = Vec::new();
    for _ in 0..2 {
        let total = Arc::clone(&total);
        let planned = Arc::clone(&planned);
        workers.push(std::thread::spawn(move || {
            let change = plan(BW_UNIT, ONE_CPU, total.load(Ordering::Acquire),
                              true, false, 0, sixty, false).expect("stale check fits");
            planned.wait();
            if let BwChange::Add { new } = change { total.fetch_add(new, Ordering::AcqRel); }
        }));
    }
    for worker in workers { worker.join().unwrap(); }
    assert_eq!(total.load(Ordering::Acquire), sixty * 2,
        "control must force both stale plans to commit");
    assert!(total.load(Ordering::Acquire) > BW_UNIT);
}

#[test]
fn concurrent_production_admission_never_overcommits() {
    let ledger = Arc::new(DlBw::new());
    ledger.init(GLOBAL_RT_PERIOD_NS, GLOBAL_RT_RUNTIME_NS);
    let start = Arc::new(Barrier::new(3));
    let sixty = u(6, 10);
    let mut workers = Vec::new();
    for _ in 0..2 {
        let ledger = Arc::clone(&ledger);
        let start = Arc::clone(&start);
        workers.push(std::thread::spawn(move || {
            start.wait();
            ledger.admit(ONE_CPU, true, false, 0, sixty, false)
        }));
    }
    start.wait();
    let accepted = workers.into_iter().map(|worker| worker.join().unwrap())
        .filter(Result::is_ok).count();
    assert_eq!(accepted, 1);
    assert_eq!(ledger.total_bw(), sixty);
}

fn no_online_cpus() -> u64 { 0 }
fn no_cpu_online(_cpu: u32) -> bool { false }
unsafe fn no_mark_offline(_cpu: u32) -> bool { false }

#[test]
fn topology_backed_admission_does_not_fabricate_boot_capacity() {
    let ledger = DlBw::with_topology(no_online_cpus, no_cpu_online, no_mark_offline);
    assert_eq!(ledger.capacity(), 0);
    assert!(ledger.admit(ONE_CPU, true, false, 0, 1, false).is_err(),
        "a stale caller hint cannot create capacity with no online CPU");
}

#[test]
fn cpu_offline_refuses_capacity_loss_that_strands_reservations() {
    GATE_ONLINE.store(2, Ordering::Release);
    let ledger = DlBw::with_topology(gate_online_cpus, gate_cpu_online, gate_mark_offline);
    book(&ledger, capacity_of(2), BW_UNIT + BW_UNIT / 2);
    // SAFETY: this test exclusively owns the synthetic topology transition.
    assert!(!unsafe { ledger.try_mark_offline(1) });
    assert_eq!(GATE_ONLINE.load(Ordering::Acquire), 2,
        "refusal must leave the canonical online set unchanged");
    assert_eq!(ledger.total_bw(), BW_UNIT + BW_UNIT / 2);
    // SAFETY: the test owns the synthetic topology; CPU 3 is absent.
    assert!(!unsafe { ledger.try_mark_offline(3) });
    assert_eq!(GATE_ONLINE.load(Ordering::Acquire), 2,
        "an absent target must not be charged as one online CPU");
}

#[test]
fn cpu_offline_and_admission_share_one_capacity_transaction() {
    TEST_ONLINE.store(2, Ordering::Release);
    OFFLINE_IN_MARK.store(false, Ordering::Release);
    ALLOW_OFFLINE_MARK.store(false, Ordering::Release);
    let ledger = Arc::new(DlBw::with_topology(
        test_online_cpus, test_cpu_online, test_mark_offline));
    let sixty = u(6, 10);
    book(&ledger, capacity_of(2), sixty);

    let down_ledger = Arc::clone(&ledger);
    let down = std::thread::spawn(move || {
        // SAFETY: the test thread exclusively owns the synthetic CPU-down
        // transition and its topology publisher.
        unsafe { down_ledger.try_mark_offline(1) }
    });
    while !OFFLINE_IN_MARK.load(Ordering::Acquire) { std::thread::yield_now(); }

    let admit_ledger = Arc::clone(&ledger);
    let started = Arc::new(AtomicBool::new(false));
    let admit_started = Arc::clone(&started);
    let admit = std::thread::spawn(move || {
        admit_started.store(true, Ordering::Release);
        admit_ledger.admit(capacity_of(2), true, false, 0, sixty, false)
    });
    while !started.load(Ordering::Acquire) { std::thread::yield_now(); }
    ALLOW_OFFLINE_MARK.store(true, Ordering::Release);

    assert!(down.join().unwrap(), "60% remains servable by one CPU");
    assert!(admit.join().unwrap().is_err(),
        "admission must observe the capacity published under the ledger lock");
    assert_eq!(TEST_ONLINE.load(Ordering::Acquire), 1);
    assert_eq!(ledger.total_bw(), sixty);
}

#[test]
fn split_capacity_check_positive_control_overcommits_after_offline() {
    let total = Arc::new(AtomicU64::new(u(6, 10)));
    let online = Arc::new(AtomicU64::new(2));
    let checked = Arc::new(Barrier::new(2));
    let sixty = u(6, 10);

    let down_total = Arc::clone(&total);
    let down_online = Arc::clone(&online);
    let down_checked = Arc::clone(&checked);
    let down = std::thread::spawn(move || {
        assert!(!dl_overflow(BW_UNIT, ONE_CPU,
            down_total.load(Ordering::Acquire), 0, 0));
        down_checked.wait();
        down_online.store(1, Ordering::Release);
    });
    let admit_total = Arc::clone(&total);
    let admit_online = Arc::clone(&online);
    let admit_checked = Arc::clone(&checked);
    let admit = std::thread::spawn(move || {
        let stale_cap = capacity_of(admit_online.load(Ordering::Acquire));
        assert!(!dl_overflow(BW_UNIT, stale_cap,
            admit_total.load(Ordering::Acquire), 0, sixty));
        admit_checked.wait();
        admit_total.fetch_add(sixty, Ordering::AcqRel);
    });
    down.join().unwrap();
    admit.join().unwrap();
    assert_eq!(online.load(Ordering::Acquire), 1);
    assert!(total.load(Ordering::Acquire) > BW_UNIT,
        "control must expose stale capacity admitting beyond the remaining CPU");
}
