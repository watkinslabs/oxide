use super::*;
use super::super::decode::{KELVIN_OFFSET_DEFAULT_MC, MAX_ACTIVE_TRIPS};

fn raw() -> Raw {
    let mut active = [None; MAX_ACTIVE_TRIPS];
    active[0] = Some(3_432);   // 70.0 C
    active[1] = Some(3_332);   // 60.0 C
    Raw {
        critical: Some(3_732), // 100.0 C
        hot: Some(3_632),      // 90.0 C
        passive: Some(3_532),  // 80.0 C
        active,
    }
}

#[test]
fn the_ladder_is_terminal_then_throttling_then_the_reacting_levels() {
    let (trips, active) = assemble(&raw(), KELVIN_OFFSET_DEFAULT_MC);
    let kinds: alloc::vec::Vec<TripType> = trips.iter().map(|trip| trip.ty).collect();
    assert_eq!(kinds, alloc::vec![
        TripType::Critical, TripType::Hot, TripType::Passive,
        TripType::Active, TripType::Active,
    ]);
    assert_eq!(trips[0].temperature, 100_000);
    assert_eq!(trips[2].temperature, 80_000);
    assert_eq!(trips[3].temperature, 70_000);
    assert_eq!(active, alloc::vec![0, 1]);
}

#[test]
fn a_level_the_firmware_did_not_declare_leaves_no_placeholder() {
    let mut raw = raw();
    raw.hot = None;
    let (trips, _) = assemble(&raw, KELVIN_OFFSET_DEFAULT_MC);
    assert!(!trips.iter().any(|trip| trip.ty == TripType::Hot));
    assert_eq!(trips[1].ty, TripType::Passive, "the indexes stay contiguous");
}

#[test]
fn a_temperature_outside_the_plausible_range_is_left_out_of_the_ladder() {
    let mut raw = raw();
    raw.passive = Some(0);
    let (trips, _) = assemble(&raw, KELVIN_OFFSET_DEFAULT_MC);
    assert!(!trips.iter().any(|trip| trip.ty == TripType::Passive));
}

#[test]
fn a_zone_declaring_nothing_yields_no_ladder_at_all() {
    let (trips, active) = assemble(&Raw::default(), KELVIN_OFFSET_DEFAULT_MC);
    assert!(trips.is_empty());
    assert!(active.is_empty());
}

#[test]
fn the_reacting_levels_run_contiguously_from_zero() {
    let mut active = [None; MAX_ACTIVE_TRIPS];
    assert_eq!(active_run(&active), 0);
    active[0] = Some(3_432);
    active[1] = Some(3_332);
    assert_eq!(active_run(&active), 2);
    // A gap ends the run: firmware declares them without gaps, so a hole
    // means the rest are absent rather than that one is.
    active[3] = Some(3_232);
    assert_eq!(active_run(&active), 2);
}

#[test]
fn the_default_cadences_keep_an_undeclared_zone_being_read() {
    assert!(DEFAULT_POLLING_MS > 0, "a zone never re-read never fires its critical trip");
    assert!(DEFAULT_PASSIVE_MS > 0);
    assert!(DEFAULT_PASSIVE_MS < DEFAULT_POLLING_MS,
            "a throttled zone is the one whose temperature is moving");
}
