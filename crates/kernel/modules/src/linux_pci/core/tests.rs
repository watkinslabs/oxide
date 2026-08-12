use super::*;
use super::super::config::{pci_read_config_byte, pci_read_config_dword, pci_read_config_word, pci_write_config_byte, pci_write_config_dword, pci_write_config_word};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use core::ffi::{c_char, c_void};
use core::mem::{align_of, offset_of, size_of, MaybeUninit};
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
const TEST_PCI_STATUS_ERRORS: u16 = 0xf900;
const TEST_DEVFN: u8 = (TEST_SLOT << PCI_DEVFN_DEV_SHIFT) | TEST_FUNC;
const TEST_MODEL_CLASS: u32 = 0x010802;
const TEST_MODEL_DRIVER_DATA: usize = 0xfeed_beef;
const TEST_STREAMING_DMA_MASK: u64 = (1u64 << 48) - 1;
const TEST_COHERENT_DMA_MASK: u64 = (1u64 << 40) - 1;
const TEST_PCI_STATUS_CAP_LIST: u32 = 1 << 20;
const TEST_PCIE_CAP: usize = 0x40 / 4;
const TEST_PCIE_CAP_POINTER: usize = 0x34 / 4;
const TEST_PCIE_DEVCTL: usize = 0x48 / 4;
const TEST_PCIE_READRQ_512: u16 = 0x2000;
const TEST_MSIX_CAP: u8 = 0x50;
const TEST_MSIX_TABLE_SIZE_MINUS_ONE: u16 = 7;

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

#[test]
fn pci_kpi_structures_match_the_c_header_abi() {
    use crate::linux_device::types::{LinuxDevice, LinuxDeviceDriver, LinuxKobject};
    use crate::linux_pm::types::LinuxDevPmInfo;

    assert_eq!((size_of::<LinuxKobject>(), align_of::<LinuxKobject>()), (64, 8));
    assert_eq!((size_of::<LinuxDevPmInfo>(), align_of::<LinuxDevPmInfo>()), (320, 8));
    assert_eq!((size_of::<LinuxDevice>(), align_of::<LinuxDevice>()), (776, 8));
    assert_eq!(offset_of!(LinuxDevice, kobj), 0);
    assert_eq!(offset_of!(LinuxDevice, dma_mask), 600);
    assert_eq!(offset_of!(LinuxDevice, power), 232);
    assert_eq!((size_of::<LinuxDeviceDriver>(), align_of::<LinuxDeviceDriver>()), (152, 8));
    assert_eq!((size_of::<LinuxResource>(), align_of::<LinuxResource>()), (64, 8));
    assert_eq!((size_of::<LinuxPciDev>(), align_of::<LinuxPciDev>()), (2736, 8));
    assert_eq!(offset_of!(LinuxPciDev, vendor), 60);
    assert_eq!(offset_of!(LinuxPciDev, current_state), 160);
    assert_eq!(offset_of!(LinuxPciDev, dev), 200);
    assert_eq!(offset_of!(LinuxPciDev, resource), 984);
    assert_eq!(offset_of!(LinuxPciDev, saved_config_space), 2152);
    assert_eq!((size_of::<LinuxPciDriver>(), align_of::<LinuxPciDriver>()), (288, 8));
    assert_eq!(offset_of!(LinuxPciDriver, driver), 104);
}

#[test]
fn pci_bar_claim_conflicts_with_the_managed_memory_resource_tree() {
    let _modules = crate::test_serial::claim();
    let mut pci = test_dev();
    let mut other = crate::linux_device::types::LinuxDevice::new();
    assert_eq!(pci_request_region(&mut pci, TEST_BAR, c"pci".as_ptr()), LINUX_OK);
    assert!(crate::linux_resource::__devm_request_region(&mut other, crate::linux_resource::iomem_resource(), TEST_MMIO_START, TEST_MMIO_END - TEST_MMIO_START + 1, c"other".as_ptr()).is_null());
    pci_release_region(&mut pci, TEST_BAR);
    assert!(!crate::linux_resource::__devm_request_region(&mut other, crate::linux_resource::iomem_resource(), TEST_MMIO_START, TEST_MMIO_END - TEST_MMIO_START + 1, c"other".as_ptr()).is_null());
    crate::linux_device::devres::release_device(&mut other);
}

fn test_dev() -> LinuxPciDev {
    // SAFETY: repr(C) KPI structs are plain data and zero is a valid empty state for tests.
    let mut dev: LinuxPciDev = unsafe { MaybeUninit::zeroed().assume_init() };
    dev.devfn = TEST_DEVFN as u32;
    dev.irq = TEST_IRQ;
    dev.vendor = TEST_VENDOR;
    dev.device = TEST_DEVICE;
    dev.resource[TEST_BAR_IDX] = LinuxResource {
        start: TEST_MMIO_START,
        end: TEST_MMIO_END,
        name: c"bar0".as_ptr(),
        flags: pci::IORESOURCE_MEM,
        desc: 0,
        parent: core::ptr::null_mut(),
        sibling: core::ptr::null_mut(),
        child: core::ptr::null_mut(),
    };
    dev
}

fn cfg_set(dev: &mut LinuxPciDev, word: usize, value: u32) {
    assert_eq!(pci_write_config_dword(dev, (word * 4) as i32, value), LINUX_OK);
}

fn cfg_get(dev: &mut LinuxPciDev, word: usize) -> u32 {
    let mut value = 0;
    assert_eq!(pci_read_config_dword(dev, (word * 4) as i32, &mut value), LINUX_OK);
    value
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
        assert!(cstr_eq((*dev).dev.kobj.name, b"0000:02:03.1"));
        assert!(cstr_eq((*dev).dev.kobj.name, b"0000:02:03.1"));
        assert!((*dev).dev.init_name.is_null());
        assert_eq!((*id).driver_data, TEST_MODEL_DRIVER_DATA);
        assert_eq!(crate::linux_dma::dma_set_mask(&mut (*dev).dev, TEST_STREAMING_DMA_MASK), LINUX_OK);
        assert_eq!(crate::linux_dma::dma_set_coherent_mask(&mut (*dev).dev, TEST_COHERENT_DMA_MASK), LINUX_OK);
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
    pci_free_irq_vectors(&mut dev);
    pci_release_region(&mut dev, TEST_BAR);
}

#[test]
fn pcim_iomap_region_releases_mapping_and_claim_with_devres() {
    let _modules = crate::test_serial::claim();
    let mut dev = test_dev();
    let mut contender = test_dev();
    let ptr = pcim_iomap_region(&mut dev, TEST_BAR, c"test".as_ptr());
    assert!(!ptr.is_null());
    assert_eq!(pci_request_region(&mut contender, TEST_BAR, c"test".as_ptr()), -LINUX_EBUSY);
    crate::linux_device::devres::release_device(&mut dev.dev);
    assert_eq!(pci_request_region(&mut contender, TEST_BAR, c"test".as_ptr()), LINUX_OK);
    pci_release_region(&mut contender, TEST_BAR);
}

#[test]
fn selected_regions_use_the_linux_bar_mask_and_roll_back_on_conflict() {
    let _modules = crate::test_serial::claim();
    let mut first = test_dev();
    let mut second = test_dev();
    let mask = super::regions::pci_select_bars(&mut first, pci::IORESOURCE_MEM);
    assert_eq!(mask, 1 << TEST_BAR_IDX);
    assert_eq!(super::regions::pci_request_selected_regions(&mut first, mask, c"first".as_ptr()), LINUX_OK);
    assert_eq!(super::regions::pci_request_selected_regions(&mut second, mask, c"second".as_ptr()), -LINUX_EBUSY);
    super::regions::pci_release_selected_regions(&mut first, mask);
    assert_eq!(super::regions::pci_request_selected_regions(&mut second, mask, c"second".as_ptr()), LINUX_OK);
    super::regions::pci_release_selected_regions(&mut second, mask);
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
    pci_free_irq_vectors(&mut dev);
    assert_eq!(pci_irq_vector(&mut dev, TEST_VECTOR_NR), -LINUX_EINVAL);
    assert_eq!(
        pci_alloc_irq_vectors(&mut dev, TEST_MSI_VECTOR_COUNT, TEST_MSI_VECTOR_COUNT, PCI_IRQ_MSI),
        TEST_MSI_VECTOR_COUNT
    );
    pci_free_irq_vectors(&mut dev);
}

#[test]
fn msix_vector_count_reads_the_capability_table_size() {
    let _modules = crate::test_serial::claim();
    let mut dev = test_dev();
    assert_eq!(pci_msix_vec_count(&mut dev), -LINUX_EINVAL);
    dev.msix_cap = TEST_MSIX_CAP;
    assert_eq!(pci_write_config_word(&mut dev, (TEST_MSIX_CAP + 2) as i32, TEST_MSIX_TABLE_SIZE_MINUS_ONE), LINUX_OK);
    assert_eq!(pci_msix_vec_count(&mut dev), TEST_MSIX_TABLE_SIZE_MINUS_ONE as i32 + 1);
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
    assert!(pci_name(&dev).is_null());
}

#[test]
fn pci_status_returns_and_clears_only_error_bits() {
    let _modules = crate::test_serial::claim();
    let mut dev = test_dev();
    cfg_set(&mut dev, 1, (TEST_PCI_STATUS_ERRORS as u32) << 16 | TEST_PCI_STATUS_CAP_LIST);
    assert_eq!(super::super::status::pci_status_get_and_clear_errors(&mut dev), TEST_PCI_STATUS_ERRORS as i32);
    assert_eq!(cfg_get(&mut dev, 1) >> 16, TEST_PCI_STATUS_CAP_LIST >> 16);
}

#[test]
fn pci_presence_rejects_the_no_device_vendor_id() {
    let _modules = crate::test_serial::claim();
    let mut dev = test_dev();
    cfg_set(&mut dev, 0, u32::from(TEST_DEVICE) << 16 | u32::from(TEST_VENDOR));
    assert!(super::super::config::pci_device_is_present(&mut dev));
    cfg_set(&mut dev, 0, u32::MAX);
    assert!(!super::super::config::pci_device_is_present(&mut dev));
    assert!(!super::super::config::pci_device_is_present(core::ptr::null_mut()));
}

#[test]
fn pcie_readrq_updates_only_the_express_device_control_field() {
    let _modules = crate::test_serial::claim();
    let mut dev = test_dev();
    cfg_set(&mut dev, 1, TEST_PCI_STATUS_CAP_LIST);
    cfg_set(&mut dev, TEST_PCIE_CAP_POINTER, 0x40);
    cfg_set(&mut dev, TEST_PCIE_CAP, 0x10);
    cfg_set(&mut dev, TEST_PCIE_DEVCTL, 0x05aa);
    assert_eq!(super::super::pcie::pcie_set_readrq(&mut dev, 512), LINUX_OK);
    assert_eq!(cfg_get(&mut dev, TEST_PCIE_DEVCTL), 0x05aa | TEST_PCIE_READRQ_512 as u32);
    assert_eq!(super::super::pcie::pcie_set_readrq(&mut dev, 192), -LINUX_EINVAL);
    assert_eq!(cfg_get(&mut dev, TEST_PCIE_DEVCTL), 0x05aa | TEST_PCIE_READRQ_512 as u32);
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
    assert_eq!(model.dma_mask(), TEST_STREAMING_DMA_MASK);
    assert_eq!(model.coherent_dma_mask(), TEST_COHERENT_DMA_MASK);
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
    super::super::export_symbols();
    for name in [
        "__pci_register_driver", "pci_register_driver", "pci_enable_device", "pci_resource_start",
        "pci_request_region", "pci_iomap", "pcim_iomap_region", "pci_alloc_irq_vectors",
        "pci_read_config_dword", "pci_write_config_dword", "pci_device_is_present",
        "pci_status_get_and_clear_errors",
    ] {
        assert!(crate::symtab::is_exported(name));
    }
}
