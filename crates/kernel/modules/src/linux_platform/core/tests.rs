use super::*;
use core::ffi::c_void;
use core::ptr::{null, null_mut};
use core::sync::atomic::{AtomicUsize, Ordering};

const TEST_MMIO_START: u64 = 0x1000_0000;
const TEST_MMIO_END: u64 = 0x1000_0fff;
const TEST_IRQ: u64 = 33;
const TEST_ACPI_DATA: usize = 0x55aa;
const TEST_OF_DATA: usize = 0xaa55;
const PLATFORM_DEVID_NONE: i32 = -1;

static PROBES: AtomicUsize = AtomicUsize::new(0);
static REMOVES: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn probe(dev: *mut PlatformDevice) -> i32 {
    PROBES.fetch_add(1, Ordering::Relaxed);
    platform_set(dev, TEST_OF_DATA as *mut c_void);
    LINUX_OK
}

unsafe extern "C" fn remove(_dev: *mut PlatformDevice) -> i32 {
    REMOVES.fetch_add(1, Ordering::Relaxed);
    LINUX_OK
}

fn reset() {
    DRIVERS.lock().clear();
    DEVICES.lock().clear();
    ALLOCATED.lock().clear();
    PROBES.store(0, Ordering::Relaxed);
    REMOVES.store(0, Ordering::Relaxed);
}

fn empty_device(name: *const c_char, res: &mut [LinuxResource]) -> PlatformDevice {
    PlatformDevice {
        name,
        id: PLATFORM_DEVID_NONE,
        dev: crate::linux_device::types::LinuxDevice {
            dma_mask: null_mut(),
            coherent_dma_mask: u64::MAX,
            driver_data: null_mut(),
            parent: null_mut(),
            bus: null_mut(),
            class: null_mut(),
            driver: null_mut(),
            init_name: name,
            name: [0; crate::linux_device::types::DEVICE_NAME_LEN],
            kobj: crate::linux_device::types::LinuxKobject::new(),
            release: None,
            of_node: null_mut(),
            acpi_node: null_mut(),
            power: crate::linux_pm::types::LinuxDevPmInfo::new(),
        },
        num_resources: res.len() as u32,
        resource: res.as_mut_ptr(),
        driver_data: null_mut(),
        driver: null_mut(),
        id_entry: null(),
        registered: 0,
    }
}

fn driver(ids: *const PlatformDeviceId) -> PlatformDriver {
    PlatformDriver {
        probe: Some(probe),
        remove: Some(remove),
        shutdown: None,
        driver: crate::linux_device::types::LinuxDeviceDriver {
            name: c"sample-platform".as_ptr(),
            bus: null_mut(),
            owner: null_mut(),
            probe: None,
            remove: None,
            of_match_table: null(),
            acpi_match_table: null(),
            pm: null(),
        },
        id_table: ids,
    }
}

fn platform_set(dev: *mut PlatformDevice, data: *mut c_void) {
    // SAFETY: test passes a valid platform device pointer.
    unsafe {
        (*dev).driver_data = data;
        (*dev).dev.driver_data = data;
    }
}

#[test]
fn driver_binds_by_platform_id_and_unbinds() {
    let _modules = crate::test_serial::claim();
    reset();
    let ids = [
        PlatformDeviceId { name: name20(*b"sample-platform\0\0\0\0\0"), driver_data: TEST_ACPI_DATA },
        PlatformDeviceId { name: [0; PLATFORM_NAME_SIZE], driver_data: 0 },
    ];
    let mut drv = driver(ids.as_ptr());
    let mut resources = [];
    let mut dev = empty_device(c"sample-platform".as_ptr(), &mut resources);

    assert_eq!(platform_device_add(&mut dev), LINUX_OK);
    assert_eq!(__platform_driver_register(&mut drv, null_mut()), LINUX_OK);
    assert_eq!(PROBES.load(Ordering::Relaxed), 1);
    assert_eq!(dev.driver, &mut drv as *mut PlatformDriver);
    assert_eq!(dev.id_entry, ids.as_ptr());
    assert_eq!(platform_get_drv(&mut dev), TEST_OF_DATA as *mut c_void);
    platform_driver_unregister(&mut drv);
    assert_eq!(REMOVES.load(Ordering::Relaxed), 1);
    assert!(dev.driver.is_null());
    platform_device_del(&mut dev);
}

#[test]
fn resources_irqs_and_iomap_translate_linux_resources() {
    let _modules = crate::test_serial::claim();
    reset();
    let mut resources = [
        LinuxResource { start: TEST_MMIO_START, end: TEST_MMIO_END, name: c"regs".as_ptr(), flags: IORESOURCE_MEM },
        LinuxResource { start: TEST_IRQ, end: TEST_IRQ, name: c"irq".as_ptr(), flags: IORESOURCE_IRQ },
    ];
    let mut dev = empty_device(c"resdev".as_ptr(), &mut resources);
    assert_eq!(platform_get_resource(&mut dev, IORESOURCE_MEM as u32, 0), &mut resources[0] as *mut LinuxResource);
    assert_eq!(platform_get_resource_byname(&mut dev, IORESOURCE_MEM as u32, c"regs".as_ptr()), &mut resources[0] as *mut LinuxResource);
    assert_eq!(platform_get_irq(&mut dev, 0), TEST_IRQ as i32);
    let mut out = null_mut();
    let ptr = devm_platform_get_and_ioremap_resource(&mut dev, 0, &mut out);
    assert_eq!(out, &mut resources[0] as *mut LinuxResource);
    assert_eq!(ptr as usize, TEST_MMIO_START as usize);
}

#[test]
fn firmware_match_tables_return_driver_data() {
    let _modules = crate::test_serial::claim();
    reset();
    let mut resources = [];
    let mut dev = empty_device(c"fwdev".as_ptr(), &mut resources);
    let node = DeviceNode {
        name: c"serial".as_ptr(),
        ty: c"serial".as_ptr(),
        compatible: c"ns16550a".as_ptr(),
        data: null_mut(),
    };
    let of_ids = [
        OfDeviceId { name: null(), ty: null(), compatible: c"ns16550a".as_ptr(), data: TEST_OF_DATA as *const c_void },
        OfDeviceId { name: null(), ty: null(), compatible: null(), data: null() },
    ];
    let acpi = AcpiDevice { hid: acpi9(*b"OXID0001\0"), uid: acpi9(*b"0\0\0\0\0\0\0\0\0"), driver_data: null_mut() };
    let acpi_ids = [
        AcpiDeviceId { id: *b"OXID0001\0", driver_data: TEST_ACPI_DATA },
        AcpiDeviceId { id: [0; ACPI_ID_LEN], driver_data: 0 },
    ];
    let mut drv = driver(null());
    drv.driver.of_match_table = of_ids.as_ptr() as *const c_void;
    drv.driver.acpi_match_table = acpi_ids.as_ptr() as *const c_void;
    dev.dev.of_node = &node as *const DeviceNode as *mut c_void;
    dev.dev.acpi_node = &acpi as *const AcpiDevice as *mut c_void;
    dev.dev.driver = &mut drv.driver;

    assert_eq!(of_match_device(of_ids.as_ptr(), &dev.dev), of_ids.as_ptr());
    assert_eq!(device_match_data(&mut dev.dev), TEST_OF_DATA as *const c_void);
    dev.dev.of_node = null_mut();
    assert_eq!(acpi_match_device(acpi_ids.as_ptr(), &dev.dev), acpi_ids.as_ptr());
    assert_eq!(device_match_data(&mut dev.dev), TEST_ACPI_DATA as *const c_void);
}

#[test]
fn export_symbols_registers_platform_surface() {
    let _modules = crate::test_serial::claim();
    export_symbols();
    for name in [
        "__platform_driver_register", "platform_device_register", "platform_get_resource",
        "platform_get_irq_optional", "devm_platform_ioremap_resource",
        "acpi_match_device", "of_match_device",
    ] {
        assert!(crate::symtab::is_exported(name));
    }
}

fn name20(bytes: [u8; PLATFORM_NAME_SIZE]) -> [c_char; PLATFORM_NAME_SIZE] {
    let mut out = [0 as c_char; PLATFORM_NAME_SIZE];
    for (i, b) in bytes.iter().enumerate() { out[i] = *b as c_char; }
    out
}

fn acpi9(bytes: [u8; ACPI_ID_LEN]) -> [c_char; ACPI_ID_LEN] {
    let mut out = [0 as c_char; ACPI_ID_LEN];
    for (i, b) in bytes.iter().enumerate() { out[i] = *b as c_char; }
    out
}

fn platform_get_drv(dev: *mut PlatformDevice) -> *mut c_void {
    if dev.is_null() { return null_mut(); }
    // SAFETY: test passes a valid platform device pointer.
    unsafe { (*dev).dev.driver_data }
}
