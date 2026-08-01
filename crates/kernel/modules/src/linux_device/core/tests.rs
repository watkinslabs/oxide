use super::*;
use crate::linux_device::types::{LinuxAttribute, LinuxKobject, LINUX_EBUSY};
use core::ffi::{c_char, c_void};
use core::mem::size_of;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

static RELEASES: AtomicUsize = AtomicUsize::new(0);
static ACTIONS: AtomicUsize = AtomicUsize::new(0);
static PROBES: AtomicUsize = AtomicUsize::new(0);
static REMOVES: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn release(_dev: *mut LinuxDevice) {
    RELEASES.fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn action(_data: *mut c_void) {
    ACTIONS.fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn probe(dev: *mut LinuxDevice) -> i32 {
    assert!(!dev.is_null());
    PROBES.fetch_add(1, Ordering::Relaxed);
    LINUX_OK
}

unsafe extern "C" fn remove(dev: *mut LinuxDevice) -> i32 {
    assert!(!dev.is_null());
    REMOVES.fetch_add(1, Ordering::Relaxed);
    LINUX_OK
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
    let _modules = crate::test_serial::claim();
    RELEASES.store(0, Ordering::Relaxed);
    let mut dev = LinuxDevice {
        dma_mask: null_mut(), coherent_dma_mask: 0, driver_data: null_mut(),
        parent: null_mut(), bus: null_mut(), class: null_mut(), driver: null_mut(),
        init_name: c"sample".as_ptr(), name: [0; DEVICE_NAME_LEN], kobj: LinuxKobject::new(), release: Some(release),
        of_node: null_mut(), acpi_node: null_mut(), power: crate::linux_pm::types::LinuxDevPmInfo::new(),
    };
    let data = &mut dev as *mut _ as *mut c_void;
    assert_eq!(device_add(&mut dev), LINUX_OK);
    let snap = registry::snapshot(&mut dev as *mut _ as usize).unwrap();
    assert_eq!(snap.refs, 1);
    assert_eq!(get_device(&mut dev), &mut dev as *mut _);
    let snap = registry::snapshot(&mut dev as *mut _ as usize).unwrap();
    assert_eq!(snap.refs, 2);
    dev_set_drvdata(&mut dev, data);
    assert_eq!(dev_get_drvdata(&dev), data);
    assert!(cstr_eq(dev_name(&dev), b"sample"));
    device_unregister(&mut dev);
    assert_eq!(RELEASES.load(Ordering::Relaxed), 0);
    put_device(&mut dev);
    assert_eq!(RELEASES.load(Ordering::Relaxed), 1);
}

#[test]
fn class_bus_driver_and_devres_round_trip() {
    let _modules = crate::test_serial::claim();
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
        init_name: c"sample-dev".as_ptr(), name: [0; DEVICE_NAME_LEN], kobj: LinuxKobject::new(), release: None,
        of_node: null_mut(), acpi_node: null_mut(), power: crate::linux_pm::types::LinuxDevPmInfo::new(),
    };
    assert_eq!(device_add(&mut dev), LINUX_OK);
    let p = devm_kzalloc(&mut dev, size_of::<usize>(), 0);
    assert!(!p.is_null());
    assert_eq!(devm_add_action_or_reset(&mut dev, Some(action), null_mut()), LINUX_OK);
    device_del(&mut dev);
    assert_eq!(ACTIONS.load(Ordering::Relaxed), 0);
    put_device(&mut dev);
    assert_eq!(ACTIONS.load(Ordering::Relaxed), 1);
    driver_unregister(&mut driver);
    bus_unregister(&mut bus);
    class_destroy(class);
}

#[test]
fn sysfs_emit_formats_into_page_buffer() {
    let _modules = crate::test_serial::claim();
    let mut buf = [0u8; crate::linux_alloc::PAGE_SIZE];
    let n = unsafe { sysfs_emit(buf.as_mut_ptr() as *mut c_char, c"state=%u\n".as_ptr(), 7u32) };
    assert_eq!(n, 8);
    assert_eq!(&buf[..9], b"state=7\n\0");
    let n = unsafe { sysfs_emit_at(buf.as_mut_ptr() as *mut c_char, 8, c"tail=%d\n".as_ptr(), -3i32) };
    assert_eq!(n, 8);
    assert_eq!(&buf[8..17], b"tail=-3\n\0");
    let n = unsafe { sysfs_emit_at(buf.as_mut_ptr() as *mut c_char, crate::linux_alloc::PAGE_SIZE as i32, c"x".as_ptr()) };
    assert_eq!(n, 0);
}

#[test]
fn driver_register_binds_and_unbinds_bus_devices() {
    let _modules = crate::test_serial::claim();
    PROBES.store(0, Ordering::Relaxed);
    REMOVES.store(0, Ordering::Relaxed);
    let mut bus = LinuxBusType { name: c"bind-bus".as_ptr(), private: null_mut() };
    let mut dev = LinuxDevice {
        dma_mask: null_mut(), coherent_dma_mask: 0, driver_data: null_mut(),
        parent: null_mut(), bus: &mut bus, class: null_mut(), driver: null_mut(),
        init_name: c"bind-dev".as_ptr(), name: [0; DEVICE_NAME_LEN], kobj: LinuxKobject::new(), release: None,
        of_node: null_mut(), acpi_node: null_mut(), power: crate::linux_pm::types::LinuxDevPmInfo::new(),
    };
    let mut driver = LinuxDeviceDriver {
        name: c"bind-driver".as_ptr(), bus: &mut bus, owner: null_mut(), probe: Some(probe), remove: Some(remove),
        of_match_table: core::ptr::null(), acpi_match_table: core::ptr::null(), pm: core::ptr::null(),
    };
    assert_eq!(bus_register(&mut bus), LINUX_OK);
    assert_eq!(device_add(&mut dev), LINUX_OK);
    assert_eq!(driver_register(&mut driver), LINUX_OK);
    assert_eq!(PROBES.load(Ordering::Relaxed), 1);
    assert_eq!(dev.driver, &mut driver as *mut _);
    let snap = registry::snapshot(&mut dev as *mut _ as usize).unwrap();
    assert_eq!(snap.bound_driver, &mut driver as *mut _ as usize);
    driver_unregister(&mut driver);
    assert_eq!(REMOVES.load(Ordering::Relaxed), 1);
    assert!(dev.driver.is_null());
    device_unregister(&mut dev);
    bus_unregister(&mut bus);
}

#[test]
fn device_attrs_and_class_destroy_are_tracked() {
    let _modules = crate::test_serial::claim();
    let class = __class_create(null_mut(), c"tracked-class".as_ptr());
    assert!(!class.is_null());
    let dev = unsafe { device_create(class, null_mut(), 0x1234, null_mut(), c"tracked%d".as_ptr(), 7u32) };
    assert!(!dev.is_null());
    let attr = LinuxDeviceAttribute { attr: LinuxAttribute { name: c"state".as_ptr(), mode: 0o444 }, show: None, store: None };
    assert_eq!(device_create_file(dev, &attr), LINUX_OK);
    assert_eq!(device_create_file(dev, &attr), -LINUX_EBUSY);
    let snap = registry::snapshot(dev as usize).unwrap();
    assert_eq!(snap.class, class as usize);
    assert_eq!(snap.devt, 0x1234);
    assert_eq!(snap.attr_count, 1);
    assert!(snap.uevent_seq >= 2);
    device_remove_file(dev, &attr);
    let snap = registry::snapshot(dev as usize).unwrap();
    assert_eq!(snap.attr_count, 0);
    device_destroy(class, 0x1234);
    assert!(registry::snapshot(dev as usize).is_none());
    class_destroy(class);
}

#[test]
fn export_symbols_registers_device_surface() {
    let _modules = crate::test_serial::claim();
    export_symbols();
    for name in [
        "device_register", "device_unregister", "dev_set_drvdata",
        "dev_get_drvdata", "dev_name", "device_get_match_data", "devm_kmalloc", "devm_kfree",
        "__class_create", "bus_register", "driver_register", "sysfs_emit", "sysfs_emit_at", "_dev_info",
        "__dynamic_dev_dbg", "kobject_init", "kobject_put", "kobject_uevent", "sysfs_create_file",
    ] {
        assert!(crate::symtab::is_exported(name));
    }
}
