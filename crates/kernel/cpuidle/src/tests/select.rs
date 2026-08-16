use super::*;
use crate::driver::{clear_for_tests, register, test_guard, IdleOps};
use crate::governor::{by_name, Kind};
use crate::state::{Entry, IdleState};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use vfs::{KResult, VfsError};

/// The clock the cycle reads, moved by hand.
static CLOCK_NS: AtomicU64 = AtomicU64::new(0);
/// How far the clock advances across one entry.
static SLEEP_NS: AtomicU64 = AtomicU64::new(0);
static TICK_WOKE: AtomicUsize = AtomicUsize::new(0);

fn clock() -> u64 { CLOCK_NS.load(Ordering::Relaxed) }
fn tick_wakeup() -> bool { TICK_WOKE.load(Ordering::Relaxed) != 0 }

struct Cpu { refuse: AtomicUsize, entered: AtomicUsize }

impl IdleOps for Cpu {
    fn enter(&self, index: usize, _state: &IdleState) -> KResult<usize> {
        if self.refuse.load(Ordering::Relaxed) != 0 { return Err(VfsError::Ebusy); }
        self.entered.store(index, Ordering::Relaxed);
        CLOCK_NS.fetch_add(SLEEP_NS.load(Ordering::Relaxed), Ordering::Relaxed);
        Ok(index)
    }
}

fn state(latency_us: u64, residency_us: u64) -> IdleState {
    IdleState::from_us("C", "", latency_us, residency_us, Entry::Halt)
}

fn setup(sleep_ns: u64) -> (std::sync::MutexGuard<'static, ()>, alloc::sync::Arc<Cpu>,
                            alloc::sync::Arc<crate::driver::Driver>)
{
    let guard = test_guard();
    CLOCK_NS.store(0, Ordering::Relaxed);
    SLEEP_NS.store(sleep_ns, Ordering::Relaxed);
    TICK_WOKE.store(0, Ordering::Relaxed);
    let ops = alloc::sync::Arc::new(Cpu {
        refuse: AtomicUsize::new(0), entered: AtomicUsize::new(usize::MAX),
    });
    let mut states = alloc::vec![state(0, 0), state(1, 1), state(40, 100), state(100, 400)];
    states[0].flags |= crate::uapi::FLAG_POLLING;
    let driver = register("oxide_idle", states, ops.clone(), 1).expect("register");
    (guard, ops, driver)
}

const TICK_NS: u64 = 10_000_000;

#[test]
fn one_cycle_selects_enters_measures_and_accounts() {
    let (_guard, ops, driver) = setup(500_000);
    let cycle = idle_cycle(&driver, &Conditions::new(0, 1_000_000, TICK_NS), clock, tick_wakeup)
        .expect("cycle");
    assert_eq!(cycle.entered, Some(cycle.selection.index));
    assert_eq!(cycle.measured_ns, 500_000);
    assert_eq!(ops.entered.load(Ordering::Relaxed), cycle.selection.index);

    let usage = driver.usage(0).expect("usage");
    assert_eq!(usage[cycle.selection.index].usage, 1);
    assert_eq!(usage[cycle.selection.index].time_ns, 500_000);
    clear_for_tests();
}

#[test]
fn the_residency_measured_is_the_sleep_and_not_the_decision_before_it() {
    let (_guard, _ops, driver) = setup(0);
    let cycle = idle_cycle(&driver, &Conditions::new(0, 1_000_000, TICK_NS), clock, tick_wakeup)
        .expect("cycle");
    assert_eq!(cycle.measured_ns, 0);
    clear_for_tests();
}

#[test]
fn a_refused_entry_counts_as_a_rejection_of_the_state_that_was_asked_for() {
    let (ops_guard, ops, driver) = setup(500_000);
    let requested = select(&driver, &Conditions::new(0, 1_000_000, TICK_NS))
        .expect("selection").index;
    ops.refuse.store(1, Ordering::Relaxed);
    let cycle = idle_cycle(&driver, &Conditions::new(0, 1_000_000, TICK_NS), clock, tick_wakeup)
        .expect("cycle");
    assert_eq!(cycle.entered, None);
    assert_eq!(cycle.measured_ns, 0);
    let usage = driver.usage(0).expect("usage");
    assert_eq!(usage[requested].rejected, 1);
    assert_eq!(usage[requested].usage, 0);
    drop(ops_guard);
    clear_for_tests();
}

#[test]
fn a_second_driver_registration_is_refused() {
    let (_guard, ops, _driver) = setup(0);
    let second = register("other", alloc::vec![state(1, 1)], ops, 1);
    assert_eq!(second.err(), Some(crate::state::TableError::AlreadyRegistered));
    clear_for_tests();
}

#[test]
fn selecting_a_governor_resets_every_predictor_but_keeps_the_counters() {
    let (_guard, _ops, driver) = setup(500_000);
    idle_cycle(&driver, &Conditions::new(0, 1_000_000, TICK_NS), clock, tick_wakeup);
    let before = driver.usage(0).expect("usage");
    assert!(before.iter().any(|slot| slot.usage > 0));

    driver.set_governor(by_name("menu").expect("menu"));
    assert_eq!(driver.governor().kind, Kind::Menu);
    let after = driver.usage(0).expect("usage");
    assert_eq!(before, after, "the counters belong to the reader, not the governor");
    clear_for_tests();
}

#[test]
fn a_run_of_long_sleeps_settles_on_the_deepest_state() {
    let (_guard, ops, driver) = setup(50_000_000);
    for _ in 0..20 {
        idle_cycle(&driver, &Conditions::new(0, 100_000_000, TICK_NS), clock, tick_wakeup);
    }
    assert_eq!(ops.entered.load(Ordering::Relaxed), 3);
    let usage = driver.usage(0).expect("usage");
    assert!(usage[3].usage > 10);
    assert_eq!(usage[3].below, 0, "the deepest state can never be too shallow");
    clear_for_tests();
}

#[test]
fn a_run_of_very_short_sleeps_is_visible_as_too_deep_and_pulls_the_choice_up() {
    let (_guard, ops, driver) = setup(2_000);
    for _ in 0..40 {
        idle_cycle(&driver, &Conditions::new(0, 100_000_000, TICK_NS), clock, tick_wakeup);
    }
    let usage = driver.usage(0).expect("usage");
    let too_deep: u64 = usage.iter().map(|slot| slot.above).sum();
    assert!(too_deep > 0, "a CPU woken after 2 us out of a deep state is over-committing");
    assert!(ops.entered.load(Ordering::Relaxed) < 3,
            "the governor must learn to stop choosing the deepest state");
    clear_for_tests();
}

#[test]
fn a_cpu_the_driver_was_not_built_for_selects_nothing() {
    let (_guard, _ops, driver) = setup(0);
    assert!(select(&driver, &Conditions::new(7, 1_000_000, TICK_NS)).is_none());
    assert!(idle_cycle(&driver, &Conditions::new(7, 1_000_000, TICK_NS), clock, tick_wakeup)
            .is_none());
    clear_for_tests();
}
