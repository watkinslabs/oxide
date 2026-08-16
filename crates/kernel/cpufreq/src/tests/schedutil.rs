use super::*;
use crate::policy::Limits;
use crate::uapi::Relation;

const TICK_NS: u64 = 10_000_000;

fn snapshot() -> Snapshot {
    Snapshot {
        limits: Limits { min: 800_000, max: 2_400_000 },
        hw: Limits { min: 800_000, max: 2_400_000 },
        cur: 800_000,
        setspeed: None,
    }
}

fn at(util: u64) -> Target {
    schedutil(&snapshot(), &Demand { util, capacity: CAPACITY_SCALE, ..Demand::default() })
        .expect("target")
}

#[test]
fn an_idle_cpu_asks_for_nothing_and_the_floor_is_applied_by_the_resolution() {
    let target = at(0);
    assert_eq!(target.freq_khz, 0);
    assert_eq!(target.relation, Relation::Lowest,
               "asking upward is what makes the policy floor the answer, not the ceiling");
}

#[test]
fn a_saturated_cpu_asks_for_the_full_hardware_ceiling() {
    assert_eq!(at(CAPACITY_SCALE).freq_khz, 2_400_000);
}

#[test]
fn an_eighty_percent_busy_cpu_already_asks_for_the_ceiling() {
    // Without the headroom this would ask for 1 920 000 — the speed the CPU is
    // already being measured at, so it could never climb.
    let freq = at(CAPACITY_SCALE * 4 / 5).freq_khz;
    assert!(freq > 2_390_000, "{freq}");
    assert_eq!(at(CAPACITY_SCALE * 4 / 5 + 11).freq_khz, 2_400_000);
}

#[test]
fn a_half_busy_cpu_asks_for_five_eighths_of_the_ceiling() {
    assert_eq!(at(CAPACITY_SCALE / 2).freq_khz, 1_500_000);
}

#[test]
fn a_wait_for_io_boost_raises_the_floor_of_an_otherwise_idle_cpu() {
    let plain = schedutil(&snapshot(), &Demand {
        util: 10, capacity: CAPACITY_SCALE, ..Demand::default()
    }).expect("target");
    let boosted = schedutil(&snapshot(), &Demand {
        util: 10, capacity: CAPACITY_SCALE, iowait_boost: CAPACITY_SCALE / 2,
        ..Demand::default()
    }).expect("target");
    assert!(boosted.freq_khz > plain.freq_khz,
            "a task blocked on a device shows no utilisation but still needs the speed");
    assert_eq!(boosted.freq_khz, 1_500_000);
}

#[test]
fn the_boost_starts_at_its_minimum_and_doubles_on_each_consecutive_wakeup() {
    let mut boost = IowaitBoost::default();
    boost.wakeup(true, 0, TICK_NS);
    assert_eq!(boost.value, IOWAIT_BOOST_MIN);
    assert_eq!(boost.apply(CAPACITY_SCALE), IOWAIT_BOOST_MIN);

    boost.wakeup(true, 0, TICK_NS);
    assert_eq!(boost.value, IOWAIT_BOOST_MIN * 2);
    boost.apply(CAPACITY_SCALE);
    boost.wakeup(true, 0, TICK_NS);
    assert_eq!(boost.value, IOWAIT_BOOST_MIN * 4);
}

#[test]
fn only_one_increase_is_taken_per_selection_cycle() {
    let mut boost = IowaitBoost::default();
    boost.wakeup(true, 0, TICK_NS);
    boost.wakeup(true, 0, TICK_NS);
    boost.wakeup(true, 0, TICK_NS);
    assert_eq!(boost.value, IOWAIT_BOOST_MIN,
               "repeated wakeups inside one cycle count once");
}

#[test]
fn the_boost_saturates_at_a_full_cpu() {
    let mut boost = IowaitBoost::default();
    for _ in 0..20 { boost.wakeup(true, 0, TICK_NS); boost.apply(CAPACITY_SCALE); }
    assert_eq!(boost.value, CAPACITY_SCALE);
}

#[test]
fn the_boost_halves_on_every_pass_that_brings_no_fresh_wakeup_and_then_goes() {
    let mut boost = IowaitBoost::default();
    for _ in 0..4 { boost.wakeup(true, 0, TICK_NS); boost.apply(CAPACITY_SCALE); }
    let peak = boost.value;
    assert!(peak > IOWAIT_BOOST_MIN);

    let mut previous = peak;
    loop {
        let applied = boost.apply(CAPACITY_SCALE);
        if applied == 0 { break; }
        assert!(boost.value < previous, "an unrefreshed boost must decay");
        previous = boost.value;
    }
    assert_eq!(boost.value, 0);
}

#[test]
fn a_boost_that_has_gone_cold_for_a_whole_tick_is_dropped() {
    let mut boost = IowaitBoost::default();
    for _ in 0..4 { boost.wakeup(true, 0, TICK_NS); boost.apply(CAPACITY_SCALE); }
    boost.wakeup(false, TICK_NS + 1, TICK_NS);
    assert_eq!(boost.value, 0);
    assert_eq!(boost.apply(CAPACITY_SCALE), 0);
}

#[test]
fn a_cold_cpu_woken_by_io_restarts_the_boost_at_its_minimum() {
    let mut boost = IowaitBoost::default();
    for _ in 0..4 { boost.wakeup(true, 0, TICK_NS); boost.apply(CAPACITY_SCALE); }
    boost.wakeup(true, TICK_NS + 1, TICK_NS);
    assert_eq!(boost.value, IOWAIT_BOOST_MIN, "it restarts rather than resuming at its peak");
}

#[test]
fn a_non_io_wakeup_neither_raises_nor_clears_a_live_boost() {
    let mut boost = IowaitBoost::default();
    boost.wakeup(true, 0, TICK_NS);
    boost.apply(CAPACITY_SCALE);
    let before = boost.value;
    boost.wakeup(false, 0, TICK_NS);
    assert_eq!(boost.value, before);
}

#[test]
fn the_rate_limit_follows_the_drivers_declared_latency() {
    assert_eq!(Tunables::from_latency(10_000).rate_limit_us, 15);
    assert_eq!(Tunables::from_latency(10_000).delay_ns(), 15_000);
    assert_eq!(Tunables::from_latency(0).rate_limit_us, crate::limits::USEC_PER_MSEC);
}

#[test]
fn a_selection_inside_the_rate_limit_is_refused_but_a_limits_change_is_not() {
    let tunables = Tunables::from_latency(1_000_000);   // 1500 us
    assert!(!may_update(&tunables, 1_000_000, 0, false));
    assert!(may_update(&tunables, 1_500_000, 0, false));
    assert!(may_update(&tunables, 1, 0, true),
            "a cap that has to wait out a rate limit is a cap that is not in force");
}
