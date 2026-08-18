use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

struct Clock { name: &'static str, rate: AtomicU64, fail: AtomicBool, log: Arc<Mutex<Vec<&'static str>>> }
impl clk::ClockOps for Clock {
    fn rate_hz(&self) -> Option<u64> { Some(self.rate.load(Ordering::Acquire)) }
    fn set_rate_hz(&self, rate_hz: u64) -> KResult<()> {
        self.log.lock().expect("log").push(self.name);
        if self.fail.load(Ordering::Acquire) { return Err(VfsError::Eio); }
        self.rate.store(rate_hz, Ordering::Release);
        Ok(())
    }
}

struct Regulator { voltage: AtomicU64, fail: AtomicBool, log: Arc<Mutex<Vec<&'static str>>> }
impl regulator::RegulatorOps for Regulator {
    fn voltage_uv(&self) -> Option<u32> { u32::try_from(self.voltage.load(Ordering::Acquire)).ok() }
    fn set_voltage(&self, voltage: regulator::Voltage) -> KResult<()> {
        self.log.lock().expect("log").push("voltage");
        if self.fail.load(Ordering::Acquire) { return Err(VfsError::Eio); }
        self.voltage.store(u64::from(voltage.target_uv), Ordering::Release);
        Ok(())
    }
}

struct Performance { name: &'static str, state: AtomicU32, fail: AtomicBool, log: Arc<Mutex<Vec<&'static str>>> }
impl crate::PerformanceOps for Performance {
    fn set_performance_state(&self, state: u32) -> KResult<()> {
        self.log.lock().expect("log").push(self.name);
        if self.fail.load(Ordering::Acquire) { return Err(VfsError::Eio); }
        self.state.store(state, Ordering::Release);
        Ok(())
    }
}

static NEXT_PHANDLE: AtomicU32 = AtomicU32::new(100);

fn setup() -> (Domain, Arc<Clock>, Arc<Regulator>, Arc<Mutex<Vec<&'static str>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let clock = Arc::new(Clock { name: "clock", rate: AtomicU64::new(1_000_000), fail: AtomicBool::new(false), log: Arc::clone(&log) });
    let regulator = Arc::new(Regulator { voltage: AtomicU64::new(900_000), fail: AtomicBool::new(false), log: Arc::clone(&log) });
    let clock_spec = clk::ClockSpec::new(NEXT_PHANDLE.fetch_add(2, Ordering::Relaxed), alloc::vec![]).expect("spec");
    let clock_owner = clk::register(clock_spec, clock.clone()).expect("clock");
    let regulator_owner = regulator::register(NEXT_PHANDLE.fetch_add(2, Ordering::Relaxed), regulator.clone()).expect("regulator");
    let points = alloc::vec![
        OperatingPoint { rates_hz: alloc::vec![1_000_000], voltage: Some(regulator::Voltage { target_uv: 900_000, min_uv: 900_000, max_uv: 900_000 }), ..OperatingPoint::default() },
        OperatingPoint { rates_hz: alloc::vec![2_000_000], voltage: Some(regulator::Voltage { target_uv: 1_000_000, min_uv: 1_000_000, max_uv: 1_000_000 }), ..OperatingPoint::default() },
    ];
    (Domain::new(NEXT_PHANDLE.fetch_add(2, Ordering::Relaxed), alloc::vec![clock_owner], Some(regulator_owner), points).expect("domain"), clock, regulator, log)
}

#[test]
fn rate_increase_raises_voltage_before_programming_clock() {
    let (domain, clock, regulator, log) = setup();
    domain.transition(1).expect("raise");
    assert_eq!(*log.lock().expect("log"), ["voltage", "clock"]);
    assert_eq!(clock.rate.load(Ordering::Acquire), 2_000_000);
    assert_eq!(regulator.voltage.load(Ordering::Acquire), 1_000_000);
}

#[test]
fn rate_decrease_programs_clock_before_lowering_voltage() {
    let (domain, clock, regulator, log) = setup();
    domain.transition(1).expect("raise");
    log.lock().expect("log").clear();
    domain.transition(0).expect("lower");
    assert_eq!(*log.lock().expect("log"), ["clock", "voltage"]);
    assert_eq!(clock.rate.load(Ordering::Acquire), 1_000_000);
    assert_eq!(regulator.voltage.load(Ordering::Acquire), 900_000);
}

#[test]
fn second_step_failure_rolls_back_the_first_step() {
    let (domain, clock, regulator, log) = setup();
    clock.fail.store(true, Ordering::Release);
    assert_eq!(domain.transition(1), Err(VfsError::Eio));
    assert_eq!(*log.lock().expect("log"), ["voltage", "clock", "voltage"]);
    assert_eq!(regulator.voltage.load(Ordering::Acquire), 900_000);
}

#[test]
fn unknown_boot_rate_is_established_before_a_policy_can_cache_it() {
    let (domain, clock, regulator, log) = setup();
    clock.rate.store(1_500_000, Ordering::Release);
    domain.initialise(1).expect("initialise");
    assert_eq!(*log.lock().expect("log"), ["voltage", "clock"]);
    assert_eq!(clock.rate.load(Ordering::Acquire), 2_000_000);
    assert_eq!(regulator.voltage.load(Ordering::Acquire), 1_000_000);
}

fn setup_multi() -> (Domain, Arc<Clock>, Arc<Clock>, Arc<Regulator>, Arc<Mutex<Vec<&'static str>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let cpu = Arc::new(Clock { name: "cpu", rate: AtomicU64::new(1_000_000), fail: AtomicBool::new(false), log: Arc::clone(&log) });
    let bus = Arc::new(Clock { name: "bus", rate: AtomicU64::new(400_000_000), fail: AtomicBool::new(false), log: Arc::clone(&log) });
    let regulator = Arc::new(Regulator { voltage: AtomicU64::new(900_000), fail: AtomicBool::new(false), log: Arc::clone(&log) });
    let cpu_owner = clk::register(clk::ClockSpec::new(NEXT_PHANDLE.fetch_add(2, Ordering::Relaxed), alloc::vec![]).expect("cpu"), cpu.clone()).expect("cpu");
    let bus_owner = clk::register(clk::ClockSpec::new(NEXT_PHANDLE.fetch_add(2, Ordering::Relaxed), alloc::vec![1]).expect("bus"), bus.clone()).expect("bus");
    let regulator_owner = regulator::register(NEXT_PHANDLE.fetch_add(2, Ordering::Relaxed), regulator.clone()).expect("regulator");
    let points = alloc::vec![
        OperatingPoint { rates_hz: alloc::vec![1_000_000, 400_000_000], voltage: Some(regulator::Voltage { target_uv: 900_000, min_uv: 900_000, max_uv: 900_000 }), ..OperatingPoint::default() },
        OperatingPoint { rates_hz: alloc::vec![2_000_000, 600_000_000], voltage: Some(regulator::Voltage { target_uv: 1_000_000, min_uv: 1_000_000, max_uv: 1_000_000 }), ..OperatingPoint::default() },
    ];
    (Domain::new(NEXT_PHANDLE.fetch_add(2, Ordering::Relaxed), alloc::vec![cpu_owner, bus_owner], Some(regulator_owner), points).expect("domain"), cpu, bus, regulator, log)
}

#[test]
fn multi_clock_transitions_follow_declaration_order_up_and_reverse_down() {
    let (domain, cpu, bus, regulator, log) = setup_multi();
    domain.transition(1).expect("raise");
    assert_eq!(*log.lock().expect("log"), ["voltage", "cpu", "bus"]);
    assert_eq!(cpu.rate.load(Ordering::Acquire), 2_000_000);
    assert_eq!(bus.rate.load(Ordering::Acquire), 600_000_000);
    log.lock().expect("log").clear();
    domain.transition(0).expect("lower");
    assert_eq!(*log.lock().expect("log"), ["bus", "cpu", "voltage"]);
    assert_eq!(regulator.voltage.load(Ordering::Acquire), 900_000);
}

#[test]
fn multi_clock_failure_restores_completed_clocks_and_the_voltage() {
    let (domain, cpu, bus, regulator, log) = setup_multi();
    bus.fail.store(true, Ordering::Release);
    assert_eq!(domain.transition(1), Err(VfsError::Eio));
    assert_eq!(*log.lock().expect("log"), ["voltage", "cpu", "bus", "cpu", "voltage"]);
    assert_eq!(cpu.rate.load(Ordering::Acquire), 1_000_000);
    assert_eq!(regulator.voltage.load(Ordering::Acquire), 900_000);
}

#[test]
fn performance_dependencies_run_before_an_upclock_and_after_a_downclock() {
    let _guard = crate::binding::test_guard();
    let log = Arc::new(Mutex::new(Vec::new()));
    let table = NEXT_PHANDLE.fetch_add(8, Ordering::Relaxed);
    let first = table + 1;
    let second = table + 2;
    let clock = Arc::new(Clock { name: "clock", rate: AtomicU64::new(1_000_000), fail: AtomicBool::new(false), log: Arc::clone(&log) });
    let regulator = Arc::new(Regulator { voltage: AtomicU64::new(900_000), fail: AtomicBool::new(false), log: Arc::clone(&log) });
    let own = Arc::new(Performance { name: "self", state: AtomicU32::new(0), fail: AtomicBool::new(false), log: Arc::clone(&log) });
    let left = Arc::new(Performance { name: "left", state: AtomicU32::new(0), fail: AtomicBool::new(false), log: Arc::clone(&log) });
    let right = Arc::new(Performance { name: "right", state: AtomicU32::new(0), fail: AtomicBool::new(false), log: Arc::clone(&log) });
    let clock_owner = clk::register(clk::ClockSpec::new(table + 3, alloc::vec![]).expect("clock"), clock.clone()).expect("clock");
    let regulator_owner = regulator::register(table + 4, regulator).expect("regulator");
    crate::register_performance_domain(table, own.clone()).expect("self");
    crate::register_performance_domain(first, left.clone()).expect("left");
    crate::register_performance_domain(second, right.clone()).expect("right");
    let required = alloc::vec![
        RequiredState { table_phandle: first, performance_state: 71 },
        RequiredState { table_phandle: second, performance_state: 72 },
    ];
    let points = alloc::vec![
        OperatingPoint {
            rates_hz: alloc::vec![1_000_000], voltage: Some(regulator::Voltage { target_uv: 900_000, min_uv: 900_000, max_uv: 900_000 }),
            current_ua: Some(30_000), performance_state: Some(31), required_states: required.clone(),
        },
        OperatingPoint {
            rates_hz: alloc::vec![2_000_000], voltage: Some(regulator::Voltage { target_uv: 1_000_000, min_uv: 1_000_000, max_uv: 1_000_000 }),
            current_ua: Some(70_000), performance_state: Some(32), required_states: required,
        },
    ];
    let domain = Domain::new(table, alloc::vec![clock_owner], Some(regulator_owner), points).expect("domain");
    domain.transition(1).expect("up");
    assert_eq!(*log.lock().expect("log"), ["left", "right", "self", "voltage", "clock"]);
    assert_eq!(left.state.load(Ordering::Acquire), 71);
    assert_eq!(right.state.load(Ordering::Acquire), 72);
    assert_eq!(own.state.load(Ordering::Acquire), 32);
    assert_eq!(domain.points()[1].current_ua, Some(70_000));
    log.lock().expect("log").clear();
    domain.transition(0).expect("down");
    assert_eq!(*log.lock().expect("log"), ["clock", "voltage", "self", "right", "left"]);
    assert_eq!(own.state.load(Ordering::Acquire), 31);
    assert_eq!(right.state.load(Ordering::Acquire), 72);
    assert_eq!(left.state.load(Ordering::Acquire), 71);
}

#[test]
fn a_required_performance_failure_leaves_the_cpu_opp_untouched() {
    let _guard = crate::binding::test_guard();
    let log = Arc::new(Mutex::new(Vec::new()));
    let table = NEXT_PHANDLE.fetch_add(6, Ordering::Relaxed);
    let dependency = table + 1;
    let clock = Arc::new(Clock { name: "clock", rate: AtomicU64::new(1_000_000), fail: AtomicBool::new(false), log: Arc::clone(&log) });
    let regulator = Arc::new(Regulator { voltage: AtomicU64::new(900_000), fail: AtomicBool::new(false), log: Arc::clone(&log) });
    let required = Arc::new(Performance { name: "required", state: AtomicU32::new(0), fail: AtomicBool::new(true), log: Arc::clone(&log) });
    let clock_owner = clk::register(clk::ClockSpec::new(table + 2, alloc::vec![]).expect("clock"), clock.clone()).expect("clock");
    let regulator_owner = regulator::register(table + 3, regulator.clone()).expect("regulator");
    crate::register_performance_domain(dependency, required).expect("required");
    let needed = alloc::vec![RequiredState { table_phandle: dependency, performance_state: 7 }];
    let points = alloc::vec![
        OperatingPoint { rates_hz: alloc::vec![1_000_000], voltage: Some(regulator::Voltage { target_uv: 900_000, min_uv: 900_000, max_uv: 900_000 }), required_states: needed.clone(), ..OperatingPoint::default() },
        OperatingPoint { rates_hz: alloc::vec![2_000_000], voltage: Some(regulator::Voltage { target_uv: 1_000_000, min_uv: 1_000_000, max_uv: 1_000_000 }), required_states: needed, ..OperatingPoint::default() },
    ];
    let domain = Domain::new(table, alloc::vec![clock_owner], Some(regulator_owner), points).expect("domain");
    assert_eq!(domain.transition(1), Err(VfsError::Eio));
    assert_eq!(*log.lock().expect("log"), ["required"]);
    assert_eq!(clock.rate.load(Ordering::Acquire), 1_000_000);
    assert_eq!(regulator.voltage.load(Ordering::Acquire), 900_000);
}
