use super::*;
use crate::policy::Limits;
use crate::uapi::Relation;

fn snapshot() -> Snapshot {
    Snapshot {
        limits: Limits { min: 800_000, max: 2_400_000 },
        hw: Limits { min: 800_000, max: 2_400_000 },
        cur: 800_000,
        setspeed: None,
    }
}

fn at(load: u32) -> Target {
    ondemand(&snapshot(), &Demand { load_percent: load, ..Demand::default() },
             &default_tunables()).expect("target")
}

#[test]
fn a_busy_window_is_the_fraction_of_it_that_was_not_idle() {
    assert_eq!(load_percent(1_000_000, 0), 100);
    assert_eq!(load_percent(1_000_000, 500_000), 50);
    assert_eq!(load_percent(1_000_000, 1_000_000), 0);
    assert_eq!(load_percent(1_000_000, 900_000), 10);
}

#[test]
fn a_window_in_which_no_time_passed_reports_no_load_rather_than_dividing_by_it() {
    assert_eq!(load_percent(0, 0), 0);
    assert_eq!(load_percent(1_000, 5_000), 0, "more idle than elapsed is a clock artefact");
}

#[test]
fn a_load_past_the_threshold_jumps_straight_to_the_ceiling() {
    let target = at(90);
    assert_eq!(target.freq_khz, 2_400_000);
    assert_eq!(target.relation, Relation::Highest);
    assert_eq!(at(81).freq_khz, 2_400_000);
}

#[test]
fn a_load_at_the_threshold_is_still_interpolated() {
    assert_ne!(at(UP_THRESHOLD_PERCENT).freq_khz, 2_400_000,
               "the jump is past the threshold, not at it");
}

#[test]
fn a_load_below_the_threshold_interpolates_across_the_hardware_range() {
    assert_eq!(at(0).freq_khz, 800_000);
    assert_eq!(at(50).freq_khz, 1_600_000);
    assert_eq!(at(25).freq_khz, 1_200_000);
    assert_eq!(at(50).relation, Relation::Closest);
}

#[test]
fn the_interpolation_is_against_the_hardware_range_not_a_narrowed_one() {
    // Same load, tighter policy ceiling: the target is unchanged and the
    // resolution is what holds it inside the limits.
    let mut capped = snapshot();
    capped.limits.max = 1_200_000;
    let target = ondemand(&capped, &Demand { load_percent: 50, ..Demand::default() },
                          &default_tunables()).expect("target");
    assert_eq!(target.freq_khz, 1_600_000,
               "the load is a property of the processor, not of the cap in force");
}

#[test]
fn the_threshold_can_be_retuned_only_within_the_usable_range() {
    let mut tunables = default_tunables();
    assert!(tunables.set_up_threshold(50));
    assert_eq!(tunables.up_threshold_percent, 50);
    assert!(!tunables.set_up_threshold(0));
    assert!(!tunables.set_up_threshold(101));
    assert_eq!(tunables.up_threshold_percent, 50, "a refused write must not take effect");

    let target = ondemand(&snapshot(), &Demand { load_percent: 60, ..Demand::default() },
                          &tunables).expect("target");
    assert_eq!(target.freq_khz, 2_400_000, "60% now passes the retuned threshold");
}

#[test]
fn the_sampling_interval_follows_the_drivers_declared_latency() {
    assert_eq!(Tunables::from_latency(10_000).sampling_rate_us, 15);
    assert_eq!(Tunables::from_latency(0).sampling_rate_us, crate::limits::USEC_PER_MSEC);
}
