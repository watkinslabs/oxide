use super::*;
use crate::trip::Trip;
use crate::uapi::TEMP_INVALID;

fn zone() -> alloc::vec::Vec<TripDesc> {
    alloc::vec![
        TripDesc::new(Trip::with_hysteresis(TripType::Active, 60_000, 5_000)),
        TripDesc::new(Trip::with_hysteresis(TripType::Passive, 80_000, 2_000)),
        TripDesc::new(Trip::new(TripType::Critical, 100_000)),
    ]
}

fn directions(crossings: &[Crossing]) -> alloc::vec::Vec<(usize, Direction)> {
    crossings.iter().map(|c| (c.index, c.direction)).collect()
}

#[test]
fn a_trip_is_crossed_upward_exactly_at_its_temperature() {
    let mut trips = zone();
    let (crossings, _) = handle_trips(59_999, &mut trips);
    assert!(crossings.is_empty(), "one millidegree short must not fire the trip");
    assert_eq!(trips[0].bucket, Bucket::High);

    let (crossings, _) = handle_trips(60_000, &mut trips);
    assert_eq!(directions(&crossings), alloc::vec![(0, Direction::Up)]);
    assert_eq!(trips[0].bucket, Bucket::Reached);
}

#[test]
fn a_reached_trip_holds_through_its_whole_hysteresis_band() {
    let mut trips = zone();
    handle_trips(60_000, &mut trips);
    for temp in [59_999, 57_000, 55_000] {
        let (crossings, _) = handle_trips(temp, &mut trips);
        assert!(crossings.is_empty(), "released at {temp} while inside the band");
        assert_eq!(trips[0].bucket, Bucket::Reached);
    }
    let (crossings, _) = handle_trips(54_999, &mut trips);
    assert_eq!(directions(&crossings), alloc::vec![(0, Direction::Down)]);
    assert_eq!(trips[0].bucket, Bucket::High);
}

#[test]
fn a_zone_that_jumps_past_several_trips_reports_each_of_them() {
    let mut trips = zone();
    let (crossings, _) = handle_trips(105_000, &mut trips);
    assert_eq!(directions(&crossings),
               alloc::vec![(0, Direction::Up), (1, Direction::Up), (2, Direction::Up)]);
}

#[test]
fn a_zone_that_falls_past_several_trips_releases_each_of_them() {
    let mut trips = zone();
    handle_trips(105_000, &mut trips);
    let (crossings, _) = handle_trips(20_000, &mut trips);
    assert_eq!(directions(&crossings),
               alloc::vec![(0, Direction::Down), (1, Direction::Down), (2, Direction::Down)]);
    assert!(trips.iter().all(|desc| desc.bucket == Bucket::High));
}

#[test]
fn a_trip_released_in_a_pass_is_not_re_engaged_by_the_same_pass() {
    // Reached at 60 with a 5-degree band, then a reading of 56: still inside
    // the band, so nothing moves. A pass that reclassified from the trip
    // temperature instead of the band bottom would release and immediately
    // re-take it.
    let mut trips = zone();
    handle_trips(60_000, &mut trips);
    let (crossings, _) = handle_trips(56_000, &mut trips);
    assert!(crossings.is_empty());
    assert_eq!(trips[0].bucket, Bucket::Reached);
}

#[test]
fn a_trip_with_no_declared_temperature_never_crosses() {
    let mut trips = alloc::vec![TripDesc::new(Trip::new(TripType::Active, TEMP_INVALID))];
    for temp in [-40_000, 0, 200_000] {
        let (crossings, win) = handle_trips(temp, &mut trips);
        assert!(crossings.is_empty());
        assert_eq!(win, WINDOW_UNBOUNDED);
    }
}

#[test]
fn the_window_brackets_the_temperature_between_the_nearest_edges() {
    let mut trips = zone();
    let (_, win) = handle_trips(70_000, &mut trips);
    // 60 is reached (band bottom 55), 80 and 100 are not.
    assert_eq!(win, Window { low: 54_999, high: 80_000 });

    let (_, win) = handle_trips(20_000, &mut trips);
    assert_eq!(win, Window { low: -i32::MAX, high: 60_000 },
               "with nothing reached there is no lower edge to watch");

    let (_, win) = handle_trips(200_000, &mut trips);
    assert_eq!(win, Window { low: 99_999, high: i32::MAX },
               "with everything reached there is no upper edge left");
}

#[test]
fn the_window_low_edge_is_the_highest_reached_band_bottom() {
    let mut trips = zone();
    handle_trips(85_000, &mut trips);
    let (_, win) = handle_trips(85_000, &mut trips);
    // Reached: trip 0 (band bottom 55_000) and trip 1 (band bottom 78_000).
    assert_eq!(win.low, 77_999, "the nearest edge below, not the furthest");
}

#[test]
fn the_passive_count_drives_the_faster_cadence_only_while_engaged() {
    let mut trips = zone();
    assert_eq!(passive_count(&trips), 0);
    handle_trips(85_000, &mut trips);
    assert_eq!(passive_count(&trips), 1);
    handle_trips(60_000, &mut trips);
    assert_eq!(passive_count(&trips), 0);
}

#[test]
fn the_trend_compares_the_two_most_recent_samples() {
    assert_eq!(trend_from_samples(50_000, 51_000), Trend::Raising);
    assert_eq!(trend_from_samples(50_000, 49_000), Trend::Dropping);
    assert_eq!(trend_from_samples(50_000, 50_000), Trend::Stable);
}

#[test]
fn a_zero_hysteresis_trip_releases_the_moment_it_is_left() {
    let mut trips = alloc::vec![TripDesc::new(Trip::new(TripType::Active, 60_000))];
    handle_trips(60_000, &mut trips);
    assert_eq!(trips[0].bucket, Bucket::Reached);
    let (crossings, _) = handle_trips(59_999, &mut trips);
    assert_eq!(directions(&crossings), alloc::vec![(0, Direction::Down)]);
}

#[test]
fn crossings_carry_the_category_so_a_terminal_trip_is_distinguishable() {
    let mut trips = zone();
    let (crossings, _) = handle_trips(105_000, &mut trips);
    let critical: alloc::vec::Vec<TripType> = crossings.iter()
        .filter(|c| !c.ty.governed()).map(|c| c.ty).collect();
    assert_eq!(critical, alloc::vec![TripType::Critical]);
}
