use super::*;
use crate::trip::{Bucket, Trip, TripDesc};
use crate::uapi::TripType;
use crate::update::handle_trips;

fn trips(temp: i32) -> alloc::vec::Vec<TripDesc> {
    let mut trips = alloc::vec![
        TripDesc::new(Trip::with_hysteresis(TripType::Active, 60_000, 5_000)),
    ];
    handle_trips(temp, &mut trips);
    trips
}

fn view(cur: u64) -> InstanceView {
    InstanceView {
        trip: 0, cdev_max: 4, cdev_cur: cur, upper: 4, lower: 0,
        weight: 0, target: cur, initialized: true,
    }
}

fn decide(temp: i32, trend: Trend, instance: InstanceView) -> Option<u64> {
    let trips = trips(temp);
    let instances = alloc::vec![instance];
    let input = GovInput {
        temperature: temp, trend, trips: &trips, instances: &instances, crossings: &[],
    };
    step_wise(&input)[0]
}

#[test]
fn a_hot_zone_that_is_still_heating_deepens_one_state_per_sample() {
    assert_eq!(decide(65_000, Trend::Raising, view(0)), Some(1));
    assert_eq!(decide(65_000, Trend::Raising, view(1)), Some(2));
    assert_eq!(decide(65_000, Trend::Raising, view(3)), Some(4));
}

#[test]
fn the_deepest_state_is_the_bound_upper_limit_not_the_device_maximum() {
    let mut instance = view(3);
    instance.upper = 3;
    assert_eq!(decide(65_000, Trend::Raising, instance), Some(3));
}

#[test]
fn a_hot_zone_that_is_cooling_backs_off_one_state_but_never_switches_off() {
    assert_eq!(decide(65_000, Trend::Dropping, view(4)), Some(3));
    assert_eq!(decide(65_000, Trend::Dropping, view(2)), Some(1));
    assert_eq!(decide(65_000, Trend::Dropping, view(1)), Some(1),
               "a trip still above its threshold must keep some cooling");
    assert_eq!(decide(65_000, Trend::Dropping, view(0)), Some(1));
}

#[test]
fn a_hot_zone_holding_steady_is_left_where_it_is() {
    assert_eq!(decide(65_000, Trend::Stable, view(2)), None);
}

#[test]
fn a_zone_below_its_trip_releases_only_while_the_temperature_falls() {
    // The trip must first be reached, then left, for the binding to release.
    let mut trips = trips(65_000);
    handle_trips(50_000, &mut trips);
    assert_eq!(trips[0].bucket, Bucket::High);
    let instances = alloc::vec![view(3)];
    let input = GovInput {
        temperature: 50_000, trend: Trend::Dropping, trips: &trips,
        instances: &instances, crossings: &[],
    };
    assert_eq!(step_wise(&input)[0], Some(0), "released to the bound floor");

    let instances = alloc::vec![view(0)];
    let input = GovInput {
        temperature: 50_000, trend: Trend::Dropping, trips: &trips,
        instances: &instances, crossings: &[],
    };
    assert_eq!(step_wise(&input)[0], Some(NO_TARGET), "already at the floor: nothing requested");
}

#[test]
fn a_cool_zone_that_is_heating_is_not_touched_before_the_trip() {
    assert_eq!(decide(50_000, Trend::Raising, view(0)), None);
    assert_eq!(decide(50_000, Trend::Stable, view(0)), None);
}

#[test]
fn the_first_pass_engages_only_if_the_trip_is_already_asking() {
    let mut cold = view(0);
    cold.initialized = false;
    assert_eq!(decide(50_000, Trend::Raising, cold), Some(NO_TARGET));

    let mut hot = view(0);
    hot.initialized = false;
    assert_eq!(decide(65_000, Trend::Stable, hot), Some(1),
               "a first pass on an already-hot zone must engage without waiting for a trend");
}

#[test]
fn the_hysteresis_band_keeps_the_device_engaged_below_the_trip() {
    // Reached at 60 with a 5-degree band; at 57 the trip still throttles.
    let mut trips = trips(60_000);
    handle_trips(57_000, &mut trips);
    let instances = alloc::vec![view(2)];
    let input = GovInput {
        temperature: 57_000, trend: Trend::Dropping, trips: &trips,
        instances: &instances, crossings: &[],
    };
    assert_eq!(step_wise(&input)[0], Some(1),
               "inside the band the trip still throttles, so the floor is lower+1");
}

#[test]
fn a_terminal_trip_is_never_cooled_by_this_governor() {
    let mut trips = alloc::vec![TripDesc::new(Trip::new(TripType::Critical, 100_000))];
    handle_trips(105_000, &mut trips);
    let instances = alloc::vec![view(0)];
    let input = GovInput {
        temperature: 105_000, trend: Trend::Raising, trips: &trips,
        instances: &instances, crossings: &[],
    };
    assert_eq!(step_wise(&input)[0], None);
}
