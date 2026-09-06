use super::{update_value, UTIL_SCALE, PELT_PERIOD_NS, RUNNING_STEADY};

#[test]
fn short_running_burst_is_visible_before_a_tick() {
    let value = update_value(0, PELT_PERIOD_NS / 2, true);
    assert!(value > 0 && value < UTIL_SCALE as u32);
}

#[test]
fn idle_signal_decays() {
    let value = update_value(UTIL_SCALE, PELT_PERIOD_NS * 32, false);
    assert!(value < 600);
}

#[test]
fn one_period_running_adds_only_decayed_capacity() {
    let value = update_value(0, PELT_PERIOD_NS, true);
    assert!((20..=25).contains(&value), "one period: {value}");
}

#[test]
fn running_half_life_reaches_half_capacity() {
    let value = update_value(0, PELT_PERIOD_NS * 32, true);
    assert!((500..=530).contains(&value), "half life: {value}");
}

#[test]
fn crossing_period_boundary_has_no_capacity_jump() {
    let before = update_value(0, PELT_PERIOD_NS - 1, true);
    let after = update_value(0, PELT_PERIOD_NS, true);
    assert!(after.abs_diff(before) <= 2, "boundary: {before} -> {after}");
}

#[test]
fn running_and_idle_contributions_partition_capacity() {
    for periods in 1..=128 {
        let delta = periods * PELT_PERIOD_NS;
        let running = update_value(0, delta, true);
        let idle = update_value(RUNNING_STEADY, delta, false);
        assert!((running + idle).abs_diff(RUNNING_STEADY as u32) <= 1,
                "periods={periods}: running={running} idle={idle}");
    }
}

#[test]
fn accelerated_decay_stays_within_integer_recurrence_rounding_bound() {
    // Each old step discards less than one unit; the accumulated geometric
    // error is bounded by 1 / (1 - .978), plus final fixed-point rounding.
    for initial in [0, 22, 512, 1000, UTIL_SCALE] {
        for running in [false, true] {
            let mut old = initial;
            for periods in 0..=128 {
                let next = update_value(initial, periods * PELT_PERIOD_NS, running);
                assert!(u64::from(next).abs_diff(old) <= 47,
                    "initial={initial} running={running} periods={periods}: old={old} next={next}");
                old = old * 978 / 1000;
                if running { old += 22; }
            }
        }
    }
}
