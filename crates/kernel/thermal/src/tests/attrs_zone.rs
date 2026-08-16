use super::*;
use crate::monitor::Cadence;
use crate::trip::Trip;
use crate::uapi::{TripType, TRIP_FLAG_RW_HYST, TRIP_FLAG_RW_TEMP};
use crate::zone::desc::ZoneDesc;
use core::sync::atomic::{AtomicI32, Ordering};
use vfs::KResult;

struct Sensor { temp: AtomicI32 }
impl crate::zone::ZoneOps for Sensor {
    fn get_temp(&self) -> KResult<i32> { Ok(self.temp.load(Ordering::Relaxed)) }
}

fn zone() -> Arc<crate::zone::ThermalZone> {
    let mut writable = Trip::with_hysteresis(TripType::Active, 60_000, 5_000);
    writable.flags = TRIP_FLAG_RW_TEMP | TRIP_FLAG_RW_HYST;
    let desc = ZoneDesc::new("acpitz", alloc::vec![
        writable,
        Trip::new(TripType::Critical, 100_000),
    ], Cadence::polled(4_000));
    Arc::new(crate::zone::ThermalZone::new(0, desc,
        Arc::new(Sensor { temp: AtomicI32::new(42_500) })))
}

fn body(zone: &Arc<crate::zone::ThermalZone>, attr: &str) -> String {
    String::from_utf8(show(zone, attr).expect(attr)).expect("utf8")
}

#[test]
fn the_temperature_reads_in_millidegrees_celsius() {
    let zone = zone();
    assert_eq!(body(&zone, "temp"), "42500\n",
               "a degree where a millidegree belongs is a 1000x wrong reading");
}

#[test]
fn a_negative_temperature_renders_with_its_sign() {
    let zone = zone();
    let desc = ZoneDesc::new("x11-sensor", alloc::vec![], Cadence::polled(0));
    let cold = Arc::new(crate::zone::ThermalZone::new(1, desc,
        Arc::new(Sensor { temp: AtomicI32::new(-12_000) })));
    assert_eq!(body(&cold, "temp"), "-12000\n");
    let _ = zone;
}

#[test]
fn a_sensor_reporting_the_invalid_sentinel_answers_enodata_not_a_number() {
    let desc = ZoneDesc::new("acpitz", alloc::vec![], Cadence::polled(0));
    let zone = Arc::new(crate::zone::ThermalZone::new(0, desc,
        Arc::new(Sensor { temp: AtomicI32::new(crate::uapi::TEMP_INVALID) })));
    assert_eq!(show(&zone, "temp"), Err(VfsError::Enodata));
}

#[test]
fn the_trip_attributes_render_their_category_temperature_and_band() {
    let zone = zone();
    assert_eq!(body(&zone, "trip_point_0_type"), "active\n");
    assert_eq!(body(&zone, "trip_point_0_temp"), "60000\n");
    assert_eq!(body(&zone, "trip_point_0_hyst"), "5000\n");
    assert_eq!(body(&zone, "trip_point_1_type"), "critical\n");
    assert_eq!(show(&zone, "trip_point_2_temp"), Err(VfsError::Enoent));
}

#[test]
fn only_a_provider_declared_writable_trip_gets_the_write_bit() {
    let zone = zone();
    let list = attrs(&zone);
    let mode = |name: &str| list.iter().find(|(attr, _)| attr == name).map(|(_, mode)| *mode);
    assert_eq!(mode("trip_point_0_temp"), Some(RW));
    assert_eq!(mode("trip_point_0_hyst"), Some(RW));
    assert_eq!(mode("trip_point_1_temp"), Some(RO));
    assert_eq!(mode("trip_point_1_hyst"), Some(RO));
    assert_eq!(mode("trip_point_0_type"), Some(RO));
    assert_eq!(mode("temp"), Some(RO));
    assert_eq!(mode("mode"), Some(RW));
    assert_eq!(mode("policy"), Some(RW));
}

#[test]
fn a_write_to_a_read_only_trip_is_refused_without_changing_it() {
    let zone = zone();
    assert_eq!(store(&zone, "trip_point_1_temp", b"90000"), Err(VfsError::Eacces));
    assert_eq!(body(&zone, "trip_point_1_temp"), "100000\n");
}

#[test]
fn a_writable_trip_moves_and_reads_back() {
    let zone = zone();
    assert_eq!(store(&zone, "trip_point_0_temp", b"70000\n"), Ok(6));
    assert_eq!(body(&zone, "trip_point_0_temp"), "70000\n");
    assert_eq!(store(&zone, "trip_point_0_hyst", b"1000"), Ok(4));
    assert_eq!(body(&zone, "trip_point_0_hyst"), "1000\n");
}

#[test]
fn a_negative_hysteresis_is_refused() {
    let zone = zone();
    assert_eq!(store(&zone, "trip_point_0_hyst", b"-1"), Err(VfsError::Einval));
    assert_eq!(body(&zone, "trip_point_0_hyst"), "5000\n");
}

#[test]
fn a_trip_whose_band_would_reach_below_the_sentinel_is_refused() {
    let zone = zone();
    assert_eq!(store(&zone, "trip_point_0_temp", b"-274000"), Ok(7),
               "the sentinel itself disables the trip and is allowed");
    let zone = self::zone();
    assert_eq!(store(&zone, "trip_point_0_temp", b"-280000"), Err(VfsError::Einval));
}

#[test]
fn the_mode_attribute_round_trips() {
    let zone = zone();
    assert_eq!(body(&zone, "mode"), "enabled\n");
    assert_eq!(store(&zone, "mode", b"disabled\n"), Ok(9));
    assert_eq!(body(&zone, "mode"), "disabled\n");
    assert_eq!(store(&zone, "mode", b"sideways"), Err(VfsError::Einval));
    assert_eq!(body(&zone, "mode"), "disabled\n");
}

#[test]
fn the_policy_attribute_only_accepts_a_governor_that_exists() {
    let zone = zone();
    assert_eq!(body(&zone, "policy"), "step_wise\n");
    assert_eq!(store(&zone, "policy", b"bang_bang\n"), Ok(10));
    assert_eq!(body(&zone, "policy"), "bang_bang\n");
    assert_eq!(store(&zone, "policy", b"ondemand"), Err(VfsError::Einval));
    assert_eq!(body(&zone, "policy"), "bang_bang\n");
}

#[test]
fn the_available_policies_list_contains_the_one_in_force() {
    let zone = zone();
    let list = body(&zone, "available_policies");
    assert!(list.contains("step_wise"));
    assert!(list.contains(zone.policy()));
    assert!(list.ends_with('\n'));
}

#[test]
fn the_uevent_names_the_zone_and_its_temperature() {
    let zone = zone();
    show(&zone, "temp").expect("prime the cached reading");
    let env = uevent_env(&zone);
    assert!(env.iter().any(|line| line == "DEVTYPE=thermal_zone"));
    assert!(env.iter().any(|line| line == "NAME=acpitz"));
}

#[test]
fn a_zone_with_no_bindings_publishes_no_links() {
    let zone = zone();
    assert!(links(&zone).is_empty());
    assert!(!attrs(&zone).iter().any(|(name, _)| name.starts_with("cdev")));
}
