use super::*;
use core::ffi::{c_char, c_void};
use core::mem::MaybeUninit;

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

#[test]
fn register_resources_iomap_and_irq_vectors() {
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
fn export_symbols_registers_pci_surface() {
    crate::symtab::_reset();
    export_symbols();
    for name in [
        "pci_register_driver", "pci_enable_device", "pci_resource_start",
        "pci_request_region", "pci_iomap", "pci_alloc_irq_vectors",
        "pci_read_config_dword", "pci_write_config_dword",
    ] {
        assert!(crate::symtab::is_exported(name));
    }
}
