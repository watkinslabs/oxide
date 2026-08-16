use super::*;
use crate::trip::{Trip, TripDesc};
use crate::uapi::{Trend, TripType, NO_TARGET};
use crate::update::{handle_trips, Crossing};
use super::super::input::InstanceView;

fn view(initialized: bool, target: u64) -> InstanceView {
    InstanceView {
        trip: 0, cdev_max: 1, cdev_cur: target, upper: 1, lower: 0,
        weight: 0, target, initialized,
    }
}

fn run(temp: i32, trips: &[TripDesc], crossings: &[Crossing], instance: InstanceView)
    -> Option<u64>
{
    let instances = alloc::vec![instance];
    let input = GovInput {
        temperature: temp, trend: Trend::Stable, trips, instances: &instances, crossings,
    };
    bang_bang(&input)[0]
}

fn zone() -> alloc::vec::Vec<TripDesc> {
    alloc::vec![TripDesc::new(Trip::with_hysteresis(TripType::Active, 60_000, 5_000))]
}

#[test]
fn the_fan_comes_on_at_the_trip_and_stays_on_through_the_band() {
    let mut trips = zone();
    let (crossings, _) = handle_trips(60_000, &mut trips);
    assert_eq!(run(60_000, &trips, &crossings, view(true, OFF)), Some(ON));

    // 57 is inside the band: no crossing, and the request does not move.
    let (crossings, _) = handle_trips(57_000, &mut trips);
    assert!(crossings.is_empty());
    assert_eq!(run(57_000, &trips, &crossings, view(true, ON)), None,
               "an unchanged trip must not re-drive the device every sample");
}

#[test]
fn the_fan_goes_off_only_once_the_whole_band_is_cleared() {
    let mut trips = zone();
    handle_trips(60_000, &mut trips);
    let (crossings, _) = handle_trips(54_999, &mut trips);
    assert_eq!(run(54_999, &trips, &crossings, view(true, ON)), Some(OFF));
}

#[test]
fn a_device_bound_to_an_already_hot_zone_is_synchronised_without_a_crossing() {
    let mut trips = zone();
    handle_trips(70_000, &mut trips);
    assert_eq!(run(70_000, &trips, &[], view(false, NO_TARGET)), Some(ON),
               "a fan bound after the zone got hot must not stay off");
}

#[test]
fn a_device_bound_to_a_cool_zone_is_synchronised_to_off() {
    let mut trips = zone();
    handle_trips(20_000, &mut trips);
    assert_eq!(run(20_000, &trips, &[], view(false, NO_TARGET)), Some(OFF));
}

#[test]
fn a_terminal_trip_is_never_driven_by_this_governor() {
    let mut trips = alloc::vec![TripDesc::new(Trip::new(TripType::Critical, 100_000))];
    let (crossings, _) = handle_trips(105_000, &mut trips);
    assert_eq!(run(105_000, &trips, &crossings, view(false, NO_TARGET)), None);
}

#[test]
fn the_governor_is_two_valued() {
    assert_eq!(OFF, 0);
    assert_eq!(ON, 1);
}
