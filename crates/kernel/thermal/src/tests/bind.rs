use super::*;
use crate::cdev::CoolingOps;
use crate::monitor::Cadence;
use crate::trip::Trip;
use crate::uapi::TripType;
use crate::zone::desc::ZoneDesc;
use core::sync::atomic::{AtomicU64, Ordering};

struct Fan { state: AtomicU64, max: u64 }
impl CoolingOps for Fan {
    fn max_state(&self) -> KResult<u64> { Ok(self.max) }
    fn cur_state(&self) -> KResult<u64> { Ok(self.state.load(Ordering::Relaxed)) }
    fn set_cur_state(&self, state: u64) -> KResult<()> {
        self.state.store(state, Ordering::Relaxed);
        Ok(())
    }
}

struct Sensor;
impl crate::zone::ZoneOps for Sensor {
    fn get_temp(&self) -> KResult<i32> { Ok(40_000) }
}

fn fan(max: u64) -> Arc<CoolingDevice> {
    Arc::new(CoolingDevice::new(0, "Fan", Arc::new(Fan { state: AtomicU64::new(0), max }), max, 0))
}

fn zone() -> ThermalZone {
    ThermalZone::new(0, ZoneDesc::new("acpitz", alloc::vec![
        Trip::new(TripType::Active, 60_000),
        Trip::new(TripType::Critical, 100_000),
    ], Cadence::polled(4_000)), Arc::new(Sensor))
}

#[test]
fn an_unbounded_bind_takes_the_whole_device_range() {
    let zone = zone();
    let cdev = fan(5);
    let id = bind(&zone, 0, &cdev, BindSpec::default()).expect("bind");
    let state = zone.state.lock();
    let inst = &state.instances[0];
    assert_eq!(id, 0);
    assert_eq!((inst.lower, inst.upper), (0, 5));
    assert!(inst.upper_no_limit);
    assert_eq!(inst.target, NO_TARGET);
    assert!(!inst.initialized);
}

#[test]
fn a_range_the_device_cannot_satisfy_is_refused_not_clamped() {
    let zone = zone();
    let cdev = fan(3);
    assert_eq!(bind(&zone, 0, &cdev, BindSpec { upper: 9, lower: 0, weight: 0 }),
               Err(VfsError::Einval));
    assert_eq!(bind(&zone, 0, &cdev, BindSpec { upper: 1, lower: 2, weight: 0 }),
               Err(VfsError::Einval));
    assert!(zone.state.lock().instances.is_empty());
}

#[test]
fn a_trip_the_zone_does_not_have_is_refused() {
    let zone = zone();
    let cdev = fan(3);
    assert_eq!(bind(&zone, 7, &cdev, BindSpec::default()), Err(VfsError::Einval));
}

#[test]
fn the_same_device_binds_once_per_trip_and_not_twice_to_one() {
    let zone = zone();
    let cdev = fan(3);
    assert_eq!(bind(&zone, 0, &cdev, BindSpec::default()), Ok(0));
    assert_eq!(bind(&zone, 0, &cdev, BindSpec::default()), Err(VfsError::Eexist));
    assert_eq!(bind(&zone, 1, &cdev, BindSpec::default()), Ok(1));
    assert_eq!(zone.state.lock().instances.len(), 2);
}

#[test]
fn unbinding_removes_every_binding_of_that_device() {
    let zone = zone();
    let cdev = fan(3);
    let other = Arc::new(CoolingDevice::new(
        1, "Processor", Arc::new(Fan { state: AtomicU64::new(0), max: 3 }), 3, 0));
    bind(&zone, 0, &cdev, BindSpec::default()).expect("bind");
    bind(&zone, 1, &cdev, BindSpec::default()).expect("bind");
    bind(&zone, 0, &other, BindSpec::default()).expect("bind");
    assert_eq!(unbind(&zone, &cdev), 2);
    assert_eq!(zone.state.lock().instances.len(), 1);
    assert_eq!(unbind(&zone, &cdev), 0);
}

#[test]
fn an_unbounded_binding_follows_the_device_when_it_gains_states() {
    let zone = zone();
    let ops = Arc::new(Fan { state: AtomicU64::new(0), max: 5 });
    let cdev = Arc::new(CoolingDevice::new(0, "Fan", ops, 2, 0));
    bind(&zone, 0, &cdev, BindSpec::default()).expect("bind");
    assert_eq!(zone.state.lock().instances[0].upper, 2);

    // The device now reports a deeper range than it was bound with.
    let deeper = Arc::new(CoolingDevice::new(
        0, "Fan", Arc::new(Fan { state: AtomicU64::new(0), max: 5 }), 5, 0));
    zone.state.lock().instances[0].cdev = Arc::clone(&deeper);
    refresh_range(&zone, &deeper);
    assert_eq!(zone.state.lock().instances[0].upper, 5);
}

#[test]
fn a_binding_with_an_explicit_ceiling_keeps_it_when_the_device_grows() {
    let zone = zone();
    let cdev = fan(5);
    bind(&zone, 0, &cdev, BindSpec { upper: 2, lower: 0, weight: 0 }).expect("bind");
    refresh_range(&zone, &cdev);
    assert_eq!(zone.state.lock().instances[0].upper, 2,
               "an explicit ceiling is the provider's choice, not a placeholder");
}

#[test]
fn a_shrinking_device_pulls_the_range_and_the_live_request_down_with_it() {
    let zone = zone();
    let cdev = fan(5);
    bind(&zone, 0, &cdev, BindSpec { upper: 5, lower: 4, weight: 0 }).expect("bind");
    { let mut state = zone.state.lock(); state.instances[0].target = 5; }

    let shrunk = Arc::new(CoolingDevice::new(
        0, "Fan", Arc::new(Fan { state: AtomicU64::new(0), max: 2 }), 2, 0));
    zone.state.lock().instances[0].cdev = Arc::clone(&shrunk);
    refresh_range(&zone, &shrunk);
    let state = zone.state.lock();
    let inst = &state.instances[0];
    assert_eq!((inst.lower, inst.upper), (2, 2));
    assert_eq!(inst.target, 2, "a request for a state the device lost would be refused forever");
}
