use super::*;
use crate::linux_pm::types::PM_EVENT_SUSPEND;
use crate::linux_pci::config::{pci_read_config_dword, pci_write_config_dword};
use core::mem::MaybeUninit;

const TEST_CFG_DWORD_IDX: usize = 0;
const TEST_CFG_ORIGINAL: u32 = 0x1af4_1041;
const TEST_CFG_CHANGED: u32 = 0xffff_ffff;

fn test_dev() -> LinuxPciDev {
    // SAFETY: repr(C) KPI structs are plain data and zero is a valid empty state for tests.
    let mut dev: LinuxPciDev = unsafe { MaybeUninit::zeroed().assume_init() };
    dev.current_state = PCI_D0;
    dev
}

#[test]
fn save_restore_power_state_and_wake() {
    let _modules = crate::test_serial::claim();
    let mut dev = test_dev();
    assert_eq!(pci_write_config_dword(&mut dev, (TEST_CFG_DWORD_IDX * 4) as i32, TEST_CFG_ORIGINAL), LINUX_OK);
    assert_eq!(pci_save_state(&mut dev), LINUX_OK);
    assert_eq!(pci_write_config_dword(&mut dev, (TEST_CFG_DWORD_IDX * 4) as i32, TEST_CFG_CHANGED), LINUX_OK);
    assert_eq!(pci_restore_state(&mut dev), LINUX_OK);
    let mut restored = 0;
    assert_eq!(pci_read_config_dword(&mut dev, (TEST_CFG_DWORD_IDX * 4) as i32, &mut restored), LINUX_OK);
    assert_eq!(restored, TEST_CFG_ORIGINAL);
    assert_eq!(pci_set_power_state(&mut dev, PCI_D3HOT), LINUX_OK);
    assert_eq!(dev.current_state, PCI_D3HOT);
    assert_eq!(pci_enable_wake(&mut dev, PCI_D3HOT, true), LINUX_OK);
    assert!(crate::linux_pci::registry::test_wake_enabled(&dev));
}

#[test]
fn choose_state_maps_system_sleep_to_d3hot() {
    let _modules = crate::test_serial::claim();
    let mut dev = test_dev();
    let msg = LinuxPmMessage { event: PM_EVENT_SUSPEND };
    assert_eq!(pci_choose_state(&mut dev, msg), PCI_D3HOT);
}

#[test]
fn export_symbols_registers_pci_pm_surface() {
    let _modules = crate::test_serial::claim();
    export_symbols();
    for name in [
        "pci_save_state", "pci_restore_state", "pci_set_power_state",
        "pci_choose_state", "pci_enable_wake",
    ] {
        assert!(crate::symtab::is_exported(name));
    }
}
