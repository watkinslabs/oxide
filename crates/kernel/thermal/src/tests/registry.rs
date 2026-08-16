use super::*;
use crate::cdev::CoolingOps;
use crate::monitor::Cadence;
use crate::trip::Trip;
use crate::uapi::TripType;
use crate::zone::desc::BindSpec;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

/// One global class: serialise every test that registers into it.
static CLASS: Mutex<()> = Mutex::new(());
static CRITICALS: AtomicU32 = AtomicU32::new(0);
static PUBLISHED: AtomicU32 = AtomicU32::new(0);

fn count_critical(_zone: &str, _temp: i32) { CRITICALS.fetch_add(1, Ordering::Relaxed); }
fn count_published(_zone: &str, _temp: i32, _trip: usize, _dir: Direction) {
    PUBLISHED.fetch_add(1, Ordering::Relaxed);
}

struct Fan { state: AtomicU64, max: u64 }
impl CoolingOps for Fan {
    fn max_state(&self) -> KResult<u64> { Ok(self.max) }
    fn cur_state(&self) -> KResult<u64> { Ok(self.state.load(Ordering::Relaxed)) }
    fn set_cur_state(&self, state: u64) -> KResult<()> {
        self.state.store(state, Ordering::Relaxed);
        Ok(())
    }
}

struct Sensor { temp: AtomicI32, binds: bool }
impl ZoneOps for Sensor {
    fn get_temp(&self) -> KResult<i32> { Ok(self.temp.load(Ordering::Relaxed)) }
    fn should_bind(&self, trip: usize, _cdev: &CoolingDevice) -> Option<BindSpec> {
        if self.binds && trip == 0 { Some(BindSpec::default()) } else { None }
    }
}

fn desc(governor: &str) -> ZoneDesc {
    ZoneDesc::new("acpitz", alloc::vec![
        Trip::with_hysteresis(TripType::Active, 60_000, 5_000),
        Trip::new(TripType::Critical, 100_000),
    ], Cadence::polled(4_000)).with_governor(governor)
}

fn fresh() -> std::sync::MutexGuard<'static, ()> {
    let guard = CLASS.lock().unwrap_or_else(|err| err.into_inner());
    clear_for_tests();
    CRITICALS.store(0, Ordering::Relaxed);
    PUBLISHED.store(0, Ordering::Relaxed);
    guard
}

#[test]
fn zones_and_cooling_devices_share_one_class_directory() {
    let _guard = fresh();
    let sensor = Arc::new(Sensor { temp: AtomicI32::new(30_000), binds: false });
    let zone = register_zone(desc("step_wise"), sensor).expect("zone");
    let cdev = register_cdev("Fan", Arc::new(Fan { state: AtomicU64::new(0), max: 1 }), 0)
        .expect("cdev");
    let names = device_names();
    assert!(names.contains(&zone.name()));
    assert!(names.contains(&cdev.name()));
    assert!(zone_by_name(&zone.name()).is_some());
    assert!(cdev_by_name(&cdev.name()).is_some());
    assert!(zone_by_name(&cdev.name()).is_none(), "the two halves must not alias");
    clear_for_tests();
}

#[test]
fn a_device_registered_after_a_zone_is_bound_into_it() {
    let _guard = fresh();
    let sensor = Arc::new(Sensor { temp: AtomicI32::new(30_000), binds: true });
    let zone = register_zone(desc("bang_bang"), sensor).expect("zone");
    assert!(zone.bindings().is_empty());
    let cdev = register_cdev("Fan", Arc::new(Fan { state: AtomicU64::new(0), max: 1 }), 0)
        .expect("cdev");
    assert_eq!(zone.bindings().len(), 1);
    assert!(unregister_cdev(&cdev));
    assert!(zone.bindings().is_empty(), "a departed device must leave no binding behind");
    clear_for_tests();
}

#[test]
fn a_zone_registered_after_a_device_is_bound_to_it() {
    let _guard = fresh();
    register_cdev("Fan", Arc::new(Fan { state: AtomicU64::new(0), max: 1 }), 0).expect("cdev");
    let sensor = Arc::new(Sensor { temp: AtomicI32::new(30_000), binds: true });
    let zone = register_zone(desc("bang_bang"), sensor).expect("zone");
    assert_eq!(zone.bindings().len(), 1);
    clear_for_tests();
}

#[test]
fn a_device_shared_between_two_zones_is_driven_to_the_deepest_request() {
    let _guard = fresh();
    let hot = Arc::new(Sensor { temp: AtomicI32::new(65_000), binds: true });
    let cool = Arc::new(Sensor { temp: AtomicI32::new(20_000), binds: true });
    let zone_hot = register_zone(desc("bang_bang"), hot.clone()).expect("zone");
    let zone_cool = register_zone(desc("bang_bang"), cool.clone()).expect("zone");
    let fan = Arc::new(Fan { state: AtomicU64::new(0), max: 1 });
    let cdev = register_cdev("Fan", fan.clone(), 0).expect("cdev");

    update_zone(&zone_cool, 0);
    assert_eq!(fan.state.load(Ordering::Relaxed), 0);
    update_zone(&zone_hot, 0);
    assert_eq!(fan.state.load(Ordering::Relaxed), 1);

    // The cool zone asking for off must not undercut the hot one.
    update_zone(&zone_cool, 0);
    assert_eq!(fan.state.load(Ordering::Relaxed), 1,
               "a zone still hot must keep the shared device engaged");

    hot.temp.store(20_000, Ordering::Relaxed);
    update_zone(&zone_hot, 0);
    assert_eq!(fan.state.load(Ordering::Relaxed), 0);
    let _ = cdev;
    clear_for_tests();
}

#[test]
fn the_terminal_action_runs_once_per_crossing() {
    let _guard = fresh();
    set_critical_hook(count_critical);
    let sensor = Arc::new(Sensor { temp: AtomicI32::new(105_000), binds: false });
    let zone = register_zone(desc("step_wise"), sensor.clone()).expect("zone");
    update_zone(&zone, 0);
    assert_eq!(CRITICALS.load(Ordering::Relaxed), 1);
    update_zone(&zone, 0);
    assert_eq!(CRITICALS.load(Ordering::Relaxed), 1);
    clear_for_tests();
}

#[test]
fn only_the_userspace_governor_publishes_crossings() {
    let _guard = fresh();
    set_crossing_hook(count_published);
    let sensor = Arc::new(Sensor { temp: AtomicI32::new(65_000), binds: false });
    let zone = register_zone(desc("step_wise"), sensor.clone()).expect("zone");
    update_zone(&zone, 0);
    assert_eq!(PUBLISHED.load(Ordering::Relaxed), 0);

    assert!(zone.set_policy("user_space"));
    sensor.temp.store(20_000, Ordering::Relaxed);
    update_zone(&zone, 0);
    assert_eq!(PUBLISHED.load(Ordering::Relaxed), 1);
    clear_for_tests();
}

#[test]
fn only_a_zone_whose_deadline_has_arrived_is_read_by_the_tick() {
    let _guard = fresh();
    let sensor = Arc::new(Sensor { temp: AtomicI32::new(30_000), binds: false });
    let zone = register_zone(desc("step_wise"), sensor).expect("zone");
    assert_eq!(zone.deadline_ns(), None, "a fresh zone has no deadline until its first pass");
    assert_eq!(tick(0), 0);

    update_zone(&zone, 0);
    let deadline = zone.deadline_ns().expect("armed");
    assert_eq!(next_deadline_ns(), Some(deadline));
    assert_eq!(tick(deadline - 1), 0);
    assert_eq!(tick(deadline), 1);
    clear_for_tests();
}

#[test]
fn a_zone_with_an_over_long_type_is_refused() {
    let _guard = fresh();
    let sensor = Arc::new(Sensor { temp: AtomicI32::new(30_000), binds: false });
    let mut long = desc("step_wise");
    long.ty = alloc::string::String::from("a").repeat(crate::limits::NAME_LEN + 1);
    assert!(register_zone(long, sensor.clone()).is_err());
    let mut empty = desc("step_wise");
    empty.ty = alloc::string::String::new();
    assert!(register_zone(empty, sensor).is_err());
    clear_for_tests();
}

#[test]
fn an_unknown_governor_name_falls_back_rather_than_leaving_the_zone_ungoverned() {
    let _guard = fresh();
    let sensor = Arc::new(Sensor { temp: AtomicI32::new(30_000), binds: false });
    let zone = register_zone(desc("nonexistent"), sensor).expect("zone");
    assert_eq!(zone.policy(), crate::governor::default_governor().name);
    clear_for_tests();
}
