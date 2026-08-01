use super::*;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use core::ffi::{c_char, c_void};
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

const TEST_MMIO_START: u64 = 0x1000_0000;
const TEST_MMIO_END: u64 = 0x1000_0fff;
const TEST_IRQ: u32 = 32;
const TEST_BUS: u8 = 2;
const TEST_SLOT: u8 = 3;
const TEST_FUNC: u8 = 1;
const TEST_BAR: i32 = 0;
const TEST_BAR_IDX: usize = TEST_BAR as usize;
const TEST_MAXLEN_UNBOUNDED: usize = 0;
const TEST_VECTOR_COUNT: i32 = 1;
const TEST_MSI_VECTOR_COUNT: i32 = 2;
const TEST_VECTOR_NR: u32 = 0;
const TEST_VECTOR_NR_ONE: u32 = 1;
const TEST_VENDOR: u16 = 0x1af4;
const TEST_DEVICE: u16 = 0x1041;
const TEST_CFG_DWORD_OFF: i32 = 0;
const TEST_CFG_BYTE_OFF: i32 = 1;
const TEST_CFG_WORD_OFF: i32 = 2;
const TEST_CFG_DWORD: u32 = 0x1234_5678;
const TEST_CFG_LOW_BYTE: u8 = 0x78;
const TEST_CFG_HIGH_WORD: u16 = 0x1234;
const TEST_CFG_PATCH_BYTE: u8 = 0xab;
const TEST_CFG_PATCHED_DWORD: u32 = 0x1234_ab78;
const TEST_DEVFN: u8 = (TEST_SLOT << PCI_DEVFN_DEV_SHIFT) | TEST_FUNC;
const TEST_MODEL_CLASS: u32 = 0x010802;
const TEST_MODEL_DRIVER_DATA: usize = 0xfeed_beef;

static MODEL_PROBES: AtomicUsize = AtomicUsize::new(0);
static MODEL_REMOVES: AtomicUsize = AtomicUsize::new(0);
static MODEL_IDS: [LinuxPciDeviceId; 2] = [
    LinuxPciDeviceId {
        vendor: TEST_VENDOR as u32,
        device: TEST_DEVICE as u32,
        subvendor: u32::MAX,
        subdevice: u32::MAX,
        class: TEST_MODEL_CLASS,
        class_mask: 0x00ff_ffff,
        driver_data: TEST_MODEL_DRIVER_DATA,
    },
    LinuxPciDeviceId {
        vendor: 0,
        device: 0,
        subvendor: 0,
        subdevice: 0,
        class: 0,
        class_mask: 0,
        driver_data: 0,
    },
];

fn test_dev() -> LinuxPciDev {
    // SAFETY: repr(C) KPI structs are plain data and zero is a valid empty state for tests.
    let mut dev: LinuxPciDev = unsafe { MaybeUninit::zeroed().assume_init() };
    dev.bus = TEST_BUS;
    dev.devfn = TEST_DEVFN;
    dev.irq = TEST_IRQ;
    dev.vendor = TEST_VENDOR;
    dev.device = TEST_DEVICE;
    dev.resource[TEST_BAR_IDX] = LinuxResource {
        start: TEST_MMIO_START,
        end: TEST_MMIO_END,
        name: c"bar0".as_ptr(),
        flags: pci::IORESOURCE_MEM,
    };
    dev
}

fn cstr_eq(ptr: *const c_char, want: &[u8]) -> bool {
    if ptr.is_null() { return false; }
    for (i, b) in want.iter().enumerate() {
        // SAFETY: pci_name returns a NUL-terminated in-struct buffer.
        if unsafe { *ptr.add(i) as u8 } != *b { return false; }
    }
    // SAFETY: want stops before the expected NUL terminator.
    unsafe { *ptr.add(want.len()) == 0 }
}

unsafe extern "C" fn model_probe(dev: *mut LinuxPciDev, id: *const LinuxPciDeviceId) -> i32 {
    assert!(!dev.is_null());
    assert!(!id.is_null());
    // SAFETY: test probe receives live PCI ABI pointers from registry bridge.
    unsafe {
        assert_eq!((*dev).vendor, TEST_VENDOR);
        assert_eq!((*dev).device, TEST_DEVICE);
        assert_eq!((*dev).class, TEST_MODEL_CLASS);
        assert_eq!((*dev).resource[TEST_BAR_IDX].start, TEST_MMIO_START);
        assert!(pci_get_drvdata(dev).is_null());
        assert!(cstr_eq((*dev).name.as_ptr(), b"0000:02:03.1"));
        assert!(cstr_eq((*dev).dev.name.as_ptr(), b"0000:02:03.1"));
        assert!((*dev).dev.init_name.is_null());
        assert_eq!((*id).driver_data, TEST_MODEL_DRIVER_DATA);
    }
    MODEL_PROBES.fetch_add(1, Ordering::SeqCst);
    pci_set_drvdata(dev, TEST_MODEL_DRIVER_DATA as *mut c_void);
    LINUX_OK
}

unsafe extern "C" fn model_remove(dev: *mut LinuxPciDev) {
    assert!(!dev.is_null());
    assert_eq!(pci_get_drvdata(dev), TEST_MODEL_DRIVER_DATA as *mut c_void);
    MODEL_REMOVES.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn register_resources_iomap_and_irq_vectors() {
    let _modules = crate::test_serial::claim();
    let mut dev = test_dev();
    assert_eq!(pci_resource_start(&dev, TEST_BAR), TEST_MMIO_START);
    assert_eq!(pci_resource_len(&dev, TEST_BAR), TEST_MMIO_END - TEST_MMIO_START + 1);
    assert_eq!(pci_request_region(&mut dev, TEST_BAR, c"sample".as_ptr()), LINUX_OK);
    let ptr = pci_iomap(&mut dev, TEST_BAR, TEST_MAXLEN_UNBOUNDED);
    assert_eq!(ptr as usize, TEST_MMIO_START as usize);
    pci_iounmap(&mut dev, ptr);
    assert_eq!(pci_alloc_irq_vectors(&mut dev, TEST_VECTOR_COUNT, TEST_VECTOR_COUNT, PCI_IRQ_LEGACY), TEST_VECTOR_COUNT);
    assert_eq!(pci_irq_vector(&mut dev, TEST_VECTOR_NR), TEST_IRQ as i32);
    assert_eq!(dev.irq_vector_flags, PCI_IRQ_LEGACY);
    pci_free_irq_vectors(&mut dev);
    pci_release_region(&mut dev, TEST_BAR);
}

#[test]
fn msi_irq_vectors_allocate_and_free_arch_vectors() {
    let _modules = crate::test_serial::claim();
    let mut dev = test_dev();
    assert_eq!(
        pci_alloc_irq_vectors(&mut dev, TEST_MSI_VECTOR_COUNT, TEST_MSI_VECTOR_COUNT, PCI_IRQ_MSI),
        TEST_MSI_VECTOR_COUNT
    );
    let base = pci_irq_vector(&mut dev, TEST_VECTOR_NR);
    assert!(base > 0);
    assert_eq!(pci_irq_vector(&mut dev, TEST_VECTOR_NR_ONE), base + 1);
    assert_eq!(dev.irq_vector_flags, PCI_IRQ_MSI);
    pci_free_irq_vectors(&mut dev);
    assert_eq!(pci_irq_vector(&mut dev, TEST_VECTOR_NR), -LINUX_EINVAL);
    assert_eq!(
        pci_alloc_irq_vectors(&mut dev, TEST_MSI_VECTOR_COUNT, TEST_MSI_VECTOR_COUNT, PCI_IRQ_MSI),
        TEST_MSI_VECTOR_COUNT
    );
    pci_free_irq_vectors(&mut dev);
}

#[test]
fn config_helpers_update_fallback_config_space() {
    let _modules = crate::test_serial::claim();
    let mut dev = test_dev();
    let mut b = 0u8;
    let mut w = 0u16;
    let mut d = 0u32;
    assert_eq!(pci_write_config_dword(&mut dev, TEST_CFG_DWORD_OFF, TEST_CFG_DWORD), LINUX_OK);
    assert_eq!(pci_read_config_byte(&mut dev, TEST_CFG_DWORD_OFF, &mut b), LINUX_OK);
    assert_eq!(b, TEST_CFG_LOW_BYTE);
    assert_eq!(pci_read_config_word(&mut dev, TEST_CFG_WORD_OFF, &mut w), LINUX_OK);
    assert_eq!(w, TEST_CFG_HIGH_WORD);
    assert_eq!(pci_write_config_byte(&mut dev, TEST_CFG_BYTE_OFF, TEST_CFG_PATCH_BYTE), LINUX_OK);
    assert_eq!(pci_read_config_dword(&mut dev, TEST_CFG_DWORD_OFF, &mut d), LINUX_OK);
    assert_eq!(d, TEST_CFG_PATCHED_DWORD);
    assert!(cstr_eq(pci_name(&dev), b"0000:02:03.1"));
}

#[test]
fn driver_registration_and_drvdata_round_trip() {
    let _modules = crate::test_serial::claim();
    let mut dev = test_dev();
    // SAFETY: repr(C) KPI structs are plain data and zero is a valid empty state for tests.
    let mut driver: LinuxPciDriver = unsafe { MaybeUninit::zeroed().assume_init() };
    driver.name = c"sample-pci".as_ptr();
    assert_eq!(pci_register_driver(&mut driver), LINUX_OK);
    assert_eq!(pci_register_driver(&mut driver), -LINUX_EBUSY);
    let data = &mut driver as *mut _ as *mut c_void;
    pci_set_drvdata(&mut dev, data);
    assert_eq!(pci_get_drvdata(&dev), data);
    pci_unregister_driver(&mut driver);
}

#[test]
fn pci_driver_registration_binds_existing_model_device() {
    let _modules = crate::test_serial::claim();
    MODEL_PROBES.store(0, Ordering::SeqCst);
    MODEL_REMOVES.store(0, Ordering::SeqCst);
    let model = Arc::new(
        drv::Device::new("pci", String::from("0000:02:03.1"), TEST_VENDOR, TEST_DEVICE, TEST_MODEL_CLASS)
            .with_resources(vec![drv::Resource {
                bar: TEST_BAR as u8,
                start: TEST_MMIO_START,
                end: TEST_MMIO_END,
                flags: pci::IORESOURCE_MEM,
            }])
    );
    let model = drv::try_device_add(model).expect("model pci device added");
    // SAFETY: repr(C) KPI structs are plain data and zero is a valid empty state for tests.
    let mut driver: LinuxPciDriver = unsafe { MaybeUninit::zeroed().assume_init() };
    driver.name = c"linux-pci-model-test".as_ptr();
    driver.id_table = MODEL_IDS.as_ptr();
    driver.probe = Some(model_probe);
    driver.remove = Some(model_remove);
    assert_eq!(pci_register_driver(&mut driver), LINUX_OK);
    assert_eq!(model.bound(), Some("linux-pci-model-test"));
    assert_eq!(MODEL_PROBES.load(Ordering::SeqCst), 1);
    assert_eq!(super::super::registry::binding_count(), 1);
    assert_eq!(super::super::registry::bound_id_driver_data(&model), Some(TEST_MODEL_DRIVER_DATA));
    pci_unregister_driver(&mut driver);
    assert_eq!(model.bound(), None);
    assert_eq!(MODEL_REMOVES.load(Ordering::SeqCst), 1);
    assert_eq!(super::super::registry::binding_count(), 0);
    drv::device_del(&model);
}

#[test]
fn export_symbols_registers_pci_surface() {
    let _modules = crate::test_serial::claim();
    export_symbols();
    for name in [
        "__pci_register_driver", "pci_register_driver", "pci_enable_device", "pci_resource_start",
        "pci_request_region", "pci_iomap", "pci_alloc_irq_vectors",
        "pci_read_config_dword", "pci_write_config_dword",
    ] {
        assert!(crate::symtab::is_exported(name));
    }
}
