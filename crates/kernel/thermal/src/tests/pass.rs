use super::*;
use crate::cdev::CoolingOps;
use crate::monitor::Cadence;
use crate::trip::Trip;
use crate::uapi::{Mode, TripType};
use crate::zone::bind::bind;
use crate::zone::desc::{BindSpec, ZoneDesc};
use crate::zone::state::ThermalZone;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use vfs::{KResult, VfsError};

struct Sensor {
    temp: AtomicI32,
    fail: AtomicBool,
    pending: AtomicBool,
    window: sync::Spinlock<Option<(i32, i32)>, sync::Devices>,
    programmed: AtomicU64,
}

impl crate::zone::ZoneOps for Sensor {
    fn get_temp(&self) -> KResult<i32> {
        if self.fail.load(Ordering::Relaxed) { return Err(VfsError::Eio); }
        Ok(self.temp.load(Ordering::Relaxed))
    }
    fn read_pending(&self) -> bool { self.pending.load(Ordering::Relaxed) }
    fn set_trips(&self, low: i32, high: i32) {
        *self.window.lock() = Some((low, high));
        self.programmed.fetch_add(1, Ordering::Relaxed);
    }
}

fn sensor() -> Arc<Sensor> {
    Arc::new(Sensor {
        temp: AtomicI32::new(30_000),
        fail: AtomicBool::new(false),
        pending: AtomicBool::new(false),
        window: sync::Spinlock::new(None),
        programmed: AtomicU64::new(0),
    })
}

struct Fan { state: AtomicU64 }
impl CoolingOps for Fan {
    fn max_state(&self) -> KResult<u64> { Ok(1) }
    fn cur_state(&self) -> KResult<u64> { Ok(self.state.load(Ordering::Relaxed)) }
    fn set_cur_state(&self, state: u64) -> KResult<()> {
        self.state.store(state, Ordering::Relaxed);
        Ok(())
    }
}

fn zone(ops: Arc<Sensor>, governor: &str) -> Arc<ThermalZone> {
    let desc = ZoneDesc::new("acpitz", alloc::vec![
        Trip::with_hysteresis(TripType::Active, 60_000, 5_000),
        Trip::with_hysteresis(TripType::Passive, 80_000, 2_000),
        Trip::new(TripType::Critical, 100_000),
    ], Cadence { polling_ms: 4_000, passive_ms: 1_000 }).with_governor(governor);
    Arc::new(ThermalZone::new(0, desc, ops))
}

#[test]
fn a_pass_records_the_reading_and_arms_the_ordinary_cadence() {
    let ops = sensor();
    let zone = zone(ops.clone(), "step_wise");
    let outcome = update(&zone, 1_000_000_000);
    assert_eq!(outcome.temperature, Some(30_000));
    assert_eq!(zone.temperature(), 30_000);
    assert!(outcome.crossings.is_empty());
    assert_eq!(outcome.deadline_ns, Some(1_000_000_000 + 4_000 * 1_000_000));
}

#[test]
fn an_engaged_passive_trip_switches_the_zone_to_the_faster_cadence() {
    let ops = sensor();
    let zone = zone(ops.clone(), "step_wise");
    ops.temp.store(85_000, Ordering::Relaxed);
    let outcome = update(&zone, 0);
    assert_eq!(outcome.deadline_ns, Some(1_000 * 1_000_000));

    ops.temp.store(30_000, Ordering::Relaxed);
    let outcome = update(&zone, 0);
    assert_eq!(outcome.deadline_ns, Some(4_000 * 1_000_000));
}

#[test]
fn the_terminal_trip_is_reported_once_on_the_way_up() {
    let ops = sensor();
    let zone = zone(ops.clone(), "step_wise");
    ops.temp.store(105_000, Ordering::Relaxed);
    assert!(update(&zone, 0).critical);
    assert!(!update(&zone, 0).critical, "a trip already reached must not re-fire");
    ops.temp.store(30_000, Ordering::Relaxed);
    assert!(!update(&zone, 0).critical);
    ops.temp.store(105_000, Ordering::Relaxed);
    assert!(update(&zone, 0).critical, "re-crossing it must report again");
}

#[test]
fn a_disabled_zone_is_not_read_at_all() {
    let ops = sensor();
    let zone = zone(ops.clone(), "step_wise");
    zone.set_mode(Mode::Disabled);
    ops.temp.store(105_000, Ordering::Relaxed);
    let outcome = update(&zone, 0);
    assert_eq!(outcome.temperature, None);
    assert!(!outcome.critical);
    assert_eq!(outcome.deadline_ns, None);
}

#[test]
fn a_failing_sensor_backs_off_and_the_zone_is_eventually_disabled() {
    let ops = sensor();
    let zone = zone(ops.clone(), "step_wise");
    ops.fail.store(true, Ordering::Relaxed);
    let mut passes = 0;
    loop {
        let outcome = update(&zone, 0);
        assert_eq!(outcome.temperature, None);
        if outcome.broken { break; }
        passes += 1;
        assert!(passes < 100, "the backoff never terminated");
        assert!(outcome.deadline_ns.is_some());
    }
    assert_eq!(zone.mode(), Mode::Disabled);
    assert!(passes > 5, "a single failed read must not disable a zone");
}

#[test]
fn a_sensor_that_is_merely_slow_is_never_disabled() {
    let ops = sensor();
    let zone = zone(ops.clone(), "step_wise");
    ops.fail.store(true, Ordering::Relaxed);
    ops.pending.store(true, Ordering::Relaxed);
    for _ in 0..500 {
        assert!(!update(&zone, 0).broken);
    }
    assert_eq!(zone.mode(), Mode::Enabled);
}

#[test]
fn a_successful_read_resets_the_backoff() {
    let ops = sensor();
    let zone = zone(ops.clone(), "step_wise");
    ops.fail.store(true, Ordering::Relaxed);
    for _ in 0..5 { update(&zone, 0); }
    assert!(zone.state.lock().backoff_ms > crate::limits::RECHECK_DELAY_MS);
    ops.fail.store(false, Ordering::Relaxed);
    update(&zone, 0);
    assert_eq!(zone.state.lock().backoff_ms, crate::limits::RECHECK_DELAY_MS);
}

#[test]
fn the_sensor_window_is_programmed_once_and_only_when_it_moves() {
    let ops = sensor();
    let zone = zone(ops.clone(), "step_wise");
    update(&zone, 0);
    assert_eq!(*ops.window.lock(), Some((-i32::MAX, 60_000)));
    assert_eq!(ops.programmed.load(Ordering::Relaxed), 1);
    update(&zone, 0);
    assert_eq!(ops.programmed.load(Ordering::Relaxed), 1,
               "an unchanged window must not be reprogrammed every sample");

    ops.temp.store(65_000, Ordering::Relaxed);
    update(&zone, 0);
    assert_eq!(*ops.window.lock(), Some((54_999, 80_000)));
    assert_eq!(ops.programmed.load(Ordering::Relaxed), 2);
}

#[test]
fn a_bound_fan_is_engaged_when_the_zone_reaches_its_trip() {
    let ops = sensor();
    let zone = zone(ops.clone(), "bang_bang");
    let fan_ops = Arc::new(Fan { state: AtomicU64::new(0) });
    let cdev = Arc::new(crate::cdev::CoolingDevice::new(0, "Fan", fan_ops.clone(), 1, 0));
    bind(&zone, 0, &cdev, BindSpec::default()).expect("bind");

    ops.temp.store(65_000, Ordering::Relaxed);
    let outcome = update(&zone, 0);
    assert_eq!(outcome.touched.len(), 1);
    assert_eq!(zone.requests_for(&cdev), alloc::vec![1]);

    ops.temp.store(30_000, Ordering::Relaxed);
    let outcome = update(&zone, 0);
    assert_eq!(outcome.touched.len(), 1);
    assert_eq!(zone.requests_for(&cdev), alloc::vec![0]);
}

#[test]
fn a_reading_the_sensor_marks_invalid_is_neither_acted_on_nor_fatal() {
    let ops = sensor();
    let zone = zone(ops.clone(), "step_wise");
    ops.temp.store(crate::uapi::TEMP_INVALID, Ordering::Relaxed);
    let outcome = update(&zone, 0);
    assert_eq!(outcome.temperature, None);
    assert!(!outcome.broken);
    assert_eq!(outcome.deadline_ns, Some(4_000 * 1_000_000));
}
