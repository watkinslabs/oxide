use super::*;
use crate::linux_device::types::{DEVICE_NAME_LEN, LinuxBusType, LinuxDeviceDriver};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

static RUNTIME_SUSPENDS: AtomicUsize = AtomicUsize::new(0);
static RUNTIME_RESUMES: AtomicUsize = AtomicUsize::new(0);
static SYSTEM_SUSPENDS: AtomicUsize = AtomicUsize::new(0);
static SYSTEM_RESUMES: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn runtime_suspend(_dev: *mut LinuxDevice) -> i32 {
    RUNTIME_SUSPENDS.fetch_add(1, Ordering::Relaxed);
    LINUX_OK
}

unsafe extern "C" fn runtime_resume(_dev: *mut LinuxDevice) -> i32 {
    RUNTIME_RESUMES.fetch_add(1, Ordering::Relaxed);
    LINUX_OK
}

unsafe extern "C" fn system_suspend(_dev: *mut LinuxDevice) -> i32 {
    SYSTEM_SUSPENDS.fetch_add(1, Ordering::Relaxed);
    LINUX_OK
}

unsafe extern "C" fn system_resume(_dev: *mut LinuxDevice) -> i32 {
    SYSTEM_RESUMES.fetch_add(1, Ordering::Relaxed);
    LINUX_OK
}

fn test_dev(ops: &LinuxDevPmOps, driver: &mut LinuxDeviceDriver) -> LinuxDevice {
    driver.pm = ops;
    LinuxDevice {
        dma_mask: null_mut(), coherent_dma_mask: 0, driver_data: null_mut(),
        parent: null_mut(), bus: null_mut::<LinuxBusType>(), class: null_mut(), driver,
        init_name: c"pm-dev".as_ptr(), name: [0; DEVICE_NAME_LEN], kobj: crate::linux_device::types::LinuxKobject::new(), release: None,
        of_node: null_mut(), acpi_node: null_mut(), power: LinuxDevPmInfo::new(),
    }
}

fn test_driver() -> LinuxDeviceDriver {
    LinuxDeviceDriver {
        name: c"pm-driver".as_ptr(), bus: null_mut(), owner: null_mut(), probe: None, remove: None,
        of_match_table: core::ptr::null(), acpi_match_table: core::ptr::null(), pm: core::ptr::null(),
    }
}

fn test_ops() -> LinuxDevPmOps {
    LinuxDevPmOps {
        prepare: None, complete: None, suspend: Some(system_suspend), resume: Some(system_resume),
        freeze: None, thaw: None, poweroff: None, restore: None, suspend_late: None, resume_early: None,
        runtime_suspend: Some(runtime_suspend), runtime_resume: Some(runtime_resume), runtime_idle: None,
    }
}

#[test]
fn runtime_pm_get_put_drives_callbacks_and_state() {
    let _modules = crate::test_serial::claim();
    RUNTIME_SUSPENDS.store(0, Ordering::Relaxed);
    RUNTIME_RESUMES.store(0, Ordering::Relaxed);
    let ops = test_ops();
    let mut driver = test_driver();
    let mut dev = test_dev(&ops, &mut driver);
    pm_runtime_set_suspended(&mut dev);
    pm_runtime_enable(&mut dev);
    assert_eq!(pm_runtime_get_sync(&mut dev), LINUX_OK);
    assert_eq!(RUNTIME_RESUMES.load(Ordering::Relaxed), 1);
    assert!(pm_runtime_active(&mut dev));
    assert_eq!(pm_runtime_put_sync(&mut dev), LINUX_OK);
    assert_eq!(RUNTIME_SUSPENDS.load(Ordering::Relaxed), 1);
    assert!(pm_runtime_suspended(&mut dev));
}

#[test]
fn system_pm_drives_sleep_callbacks() {
    let _modules = crate::test_serial::claim();
    SYSTEM_SUSPENDS.store(0, Ordering::Relaxed);
    SYSTEM_RESUMES.store(0, Ordering::Relaxed);
    let ops = test_ops();
    let mut driver = test_driver();
    let mut dev = test_dev(&ops, &mut driver);
    assert_eq!(dev_pm_suspend(&mut dev), LINUX_OK);
    assert_eq!(dev_pm_resume(&mut dev), LINUX_OK);
    assert_eq!(SYSTEM_SUSPENDS.load(Ordering::Relaxed), 1);
    assert_eq!(SYSTEM_RESUMES.load(Ordering::Relaxed), 1);
}

#[test]
fn wakeup_helpers_track_capability_and_enablement() {
    let _modules = crate::test_serial::claim();
    let ops = test_ops();
    let mut driver = test_driver();
    let mut dev = test_dev(&ops, &mut driver);
    assert_eq!(device_wakeup_enable(&mut dev), -LINUX_EINVAL);
    assert_eq!(device_init_wakeup(&mut dev, true), LINUX_OK);
    assert!(device_can_wakeup(&mut dev));
    assert!(device_may_wakeup(&mut dev));
    device_set_wakeup_capable(&mut dev, false);
    assert!(!device_may_wakeup(&mut dev));
}

#[test]
fn export_symbols_registers_pm_surface() {
    let _modules = crate::test_serial::claim();
    export_symbols();
    for name in [
        "pm_runtime_enable", "pm_runtime_get_sync", "pm_runtime_put_sync",
        "pm_runtime_set_suspended", "device_init_wakeup", "dev_pm_suspend",
    ] {
        assert!(crate::symtab::is_exported(name));
    }
}
