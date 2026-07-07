use super::*;
use core::ffi::{c_char, c_void};
use core::mem::size_of;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

static RELEASES: AtomicUsize = AtomicUsize::new(0);
static ACTIONS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn release(_dev: *mut LinuxDevice) {
    RELEASES.fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn action(_data: *mut c_void) {
    ACTIONS.fetch_add(1, Ordering::Relaxed);
}

fn cstr_eq(ptr: *const c_char, want: &[u8]) -> bool {
    if ptr.is_null() { return false; }
    for (i, b) in want.iter().enumerate() {
        // SAFETY: test strings are known-good NUL-terminated device names.
        if unsafe { *ptr.add(i) as u8 } != *b { return false; }
    }
    // SAFETY: caller-provided expected bytes stop before the required NUL.
    unsafe { *ptr.add(want.len()) == 0 }
}

#[test]
fn register_drvdata_name_and_release() {
    RELEASES.store(0, Ordering::Relaxed);
    let mut dev = LinuxDevice {
        dma_mask: null_mut(), coherent_dma_mask: 0, driver_data: null_mut(),
        parent: null_mut(), bus: null_mut(), class: null_mut(), driver: null_mut(),
        init_name: c"sample".as_ptr(), name: [0; DEVICE_NAME_LEN], release: Some(release),
        of_node: null_mut(), acpi_node: null_mut(), power: crate::linux_pm::types::LinuxDevPmInfo::new(),
    };
    let data = &mut dev as *mut _ as *mut c_void;
    assert_eq!(device_add(&mut dev), LINUX_OK);
    dev_set_drvdata(&mut dev, data);
    assert_eq!(dev_get_drvdata(&dev), data);
    assert!(cstr_eq(dev_name(&dev), b"sample"));
    device_unregister(&mut dev);
    assert_eq!(RELEASES.load(Ordering::Relaxed), 1);
}

#[test]
fn class_bus_driver_and_devres_round_trip() {
    ACTIONS.store(0, Ordering::Relaxed);
    let class = __class_create(null_mut(), c"sample-class".as_ptr());
    assert!(!class.is_null());
    let mut bus = LinuxBusType { name: c"sample-bus".as_ptr(), private: null_mut() };
    let mut driver = LinuxDeviceDriver {
        name: c"sample-driver".as_ptr(), bus: &mut bus, owner: null_mut(), probe: None, remove: None,
        of_match_table: core::ptr::null(), acpi_match_table: core::ptr::null(), pm: core::ptr::null(),
    };
    assert_eq!(bus_register(&mut bus), LINUX_OK);
    assert_eq!(driver_register(&mut driver), LINUX_OK);
    let mut dev = LinuxDevice {
        dma_mask: null_mut(), coherent_dma_mask: 0, driver_data: null_mut(),
        parent: null_mut(), bus: &mut bus, class, driver: &mut driver,
        init_name: c"sample-dev".as_ptr(), name: [0; DEVICE_NAME_LEN], release: None,
        of_node: null_mut(), acpi_node: null_mut(), power: crate::linux_pm::types::LinuxDevPmInfo::new(),
    };
    assert_eq!(device_add(&mut dev), LINUX_OK);
    let p = devm_kzalloc(&mut dev, size_of::<usize>(), 0);
    assert!(!p.is_null());
    assert_eq!(devm_add_action_or_reset(&mut dev, Some(action), null_mut()), LINUX_OK);
    device_del(&mut dev);
    assert_eq!(ACTIONS.load(Ordering::Relaxed), 1);
    driver_unregister(&mut driver);
    bus_unregister(&mut bus);
    class_destroy(class);
}

#[test]
fn export_symbols_registers_device_surface() {
    crate::symtab::_reset();
    export_symbols();
    for name in [
        "device_register", "device_unregister", "dev_set_drvdata",
        "dev_get_drvdata", "dev_name", "device_get_match_data", "devm_kmalloc", "devm_kfree",
        "__class_create", "bus_register", "driver_register", "_dev_info",
    ] {
        assert!(crate::symtab::is_exported(name));
    }
}
