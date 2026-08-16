use super::*;
use crate::driver::{clear_for_tests, register, test_guard, IdleOps};
use crate::state::{Entry, IdleState};
struct Cpu;
impl IdleOps for Cpu {
    fn enter(&self, index: usize, _state: &IdleState) -> KResult<usize> { Ok(index) }
}

fn state(name: &str, latency_us: u64, residency_us: u64) -> IdleState {
    IdleState::from_us(name, "desc", latency_us, residency_us, Entry::Halt)
}

fn setup() -> (std::sync::MutexGuard<'static, ()>, Arc<Driver>) {
    let guard = test_guard();
    let mut states = alloc::vec![
        state("POLL", 0, 0), state("C1", 1, 1), state("C2", 40, 100), state("C3", 100, 400),
    ];
    states[0].flags |= crate::uapi::FLAG_POLLING;
    states[3].power_uw = 1_500;
    let driver = register("acpi_idle", states, Arc::new(Cpu), 1).expect("register");
    (guard, driver)
}

fn body(drv: &Arc<Driver>, index: usize, attr: &str) -> String {
    String::from_utf8(show_state(drv, 0, index, attr).expect(attr)).expect("utf8")
}

#[test]
fn latency_and_residency_report_the_microseconds_the_driver_declared() {
    let (_guard, drv) = setup();
    assert_eq!(body(&drv, 2, "latency"), "40\n");
    assert_eq!(body(&drv, 2, "residency"), "100\n");
    assert_eq!(body(&drv, 3, "latency"), "100\n");
    assert_eq!(body(&drv, 3, "residency"), "400\n",
               "a nanosecond figure here would read as 400000, a thousandfold error");
    clear_for_tests();
}

#[test]
fn time_reports_microseconds_converted_from_the_nanoseconds_it_accumulates() {
    let (_guard, drv) = setup();
    assert_eq!(body(&drv, 2, "time"), "0\n");
    drv.with_device(0, |device| {
        crate::usage::record_entry(drv.states(), &mut device.usage, 2, 250_000);
    });
    assert_eq!(body(&drv, 2, "time"), "250\n");
    assert_eq!(body(&drv, 2, "usage"), "1\n");
    clear_for_tests();
}

#[test]
fn the_state_identity_attributes_read_back() {
    let (_guard, drv) = setup();
    assert_eq!(body(&drv, 0, "name"), "POLL\n");
    assert_eq!(body(&drv, 1, "desc"), "desc\n");
    assert_eq!(body(&drv, 3, "power"), "1500\n");
    assert_eq!(body(&drv, 0, "power"), "0\n");
    clear_for_tests();
}

#[test]
fn an_undeclared_name_reads_as_the_explicit_null_marker() {
    let _guard = test_guard();
    let blank = IdleState::from_us("", "", 1, 1, Entry::Halt);
    let drv = register("x", alloc::vec![blank], Arc::new(Cpu), 1).expect("register");
    assert_eq!(body(&drv, 0, "name"), "<null>\n");
    assert_eq!(body(&drv, 0, "desc"), "<null>\n");
    clear_for_tests();
}

#[test]
fn the_mispredict_counters_are_published() {
    let (_guard, drv) = setup();
    drv.with_device(0, |device| {
        crate::usage::record_entry(drv.states(), &mut device.usage, 2, 10_000);
        crate::usage::record_entry(drv.states(), &mut device.usage, 2, 900_000);
        crate::usage::record_rejection(&mut device.usage, 3);
    });
    assert_eq!(body(&drv, 2, "above"), "1\n");
    assert_eq!(body(&drv, 2, "below"), "1\n");
    assert_eq!(body(&drv, 3, "rejected"), "1\n");
    clear_for_tests();
}

#[test]
fn the_disable_attribute_round_trips_and_takes_effect() {
    let (_guard, drv) = setup();
    assert_eq!(body(&drv, 3, "disable"), "0\n");
    assert_eq!(store_state(&drv, 0, 3, "disable", b"1\n"), Ok(2));
    assert_eq!(body(&drv, 3, "disable"), "1\n");
    assert!(!drv.usage(0).expect("usage")[3].enabled());
    assert_eq!(store_state(&drv, 0, 3, "disable", b"0"), Ok(1));
    assert!(drv.usage(0).expect("usage")[3].enabled());
    assert_eq!(store_state(&drv, 0, 3, "disable", b"nonsense"), Err(VfsError::Einval));
    clear_for_tests();
}

#[test]
fn a_driver_disabled_state_reports_its_default_status_and_cannot_be_enabled() {
    let _guard = test_guard();
    let mut off = state("C6", 200, 800);
    off.flags |= crate::uapi::FLAG_UNUSABLE | crate::uapi::FLAG_OFF;
    let drv = register("x", alloc::vec![state("C1", 1, 1), off], Arc::new(Cpu), 1)
        .expect("register");
    assert_eq!(body(&drv, 1, "default_status"), "disabled\n");
    assert_eq!(body(&drv, 0, "default_status"), "enabled\n");
    assert_eq!(store_state(&drv, 0, 1, "disable", b"0"), Ok(1));
    assert!(!drv.usage(0).expect("usage")[1].enabled(),
            "clearing the user bit must not unpin a state the driver called unusable");
    clear_for_tests();
}

#[test]
fn a_read_only_state_attribute_refuses_a_write() {
    let (_guard, drv) = setup();
    assert_eq!(store_state(&drv, 0, 2, "latency", b"1"), Err(VfsError::Eacces));
    assert_eq!(store_state(&drv, 0, 2, "usage", b"1"), Err(VfsError::Eacces));
    assert_eq!(show_state(&drv, 0, 2, "nonexistent"), Err(VfsError::Enoent));
    assert_eq!(show_state(&drv, 0, 9, "latency"), Err(VfsError::Enoent));
    clear_for_tests();
}

#[test]
fn the_directory_attributes_name_the_driver_and_the_governor() {
    let (_guard, drv) = setup();
    let text = |attr: &str| String::from_utf8(show_dir(&drv, attr).expect(attr)).expect("utf8");
    assert_eq!(text("current_driver"), "acpi_idle\n");
    assert_eq!(text("current_governor"), "teo\n");
    assert_eq!(text("current_governor_ro"), "teo\n");
    assert_eq!(text("available_governors"), "menu teo\n");
    clear_for_tests();
}

#[test]
fn the_governor_can_be_selected_but_only_through_the_writable_attribute() {
    let (_guard, drv) = setup();
    assert_eq!(store_dir(&drv, "current_governor", b"menu\n"), Ok(5));
    assert_eq!(drv.governor().name, "menu");
    assert_eq!(store_dir(&drv, "current_governor_ro", b"teo"), Err(VfsError::Eacces));
    assert_eq!(store_dir(&drv, "current_governor", b"ladder"), Err(VfsError::Einval));
    assert_eq!(drv.governor().name, "menu");
    clear_for_tests();
}

#[test]
fn a_state_directory_name_round_trips() {
    assert_eq!(state_dir(0), "state0");
    assert_eq!(state_dir(12), "state12");
    assert_eq!(parse_state_dir("state0"), Some(0));
    assert_eq!(parse_state_dir("state12"), Some(12));
    assert_eq!(parse_state_dir("statex"), None);
    assert_eq!(parse_state_dir("cpu0"), None);
}

#[test]
fn every_published_state_attribute_actually_renders() {
    let (_guard, drv) = setup();
    for (name, _) in STATE_ATTRS {
        assert!(show_state(&drv, 0, 1, name).is_ok(), "{name} is listed but does not render");
    }
    for (name, _) in DIR_ATTRS {
        assert!(show_dir(&drv, name).is_ok(), "{name} is listed but does not render");
    }
    assert_eq!(state_count(), 4);
    clear_for_tests();
}
