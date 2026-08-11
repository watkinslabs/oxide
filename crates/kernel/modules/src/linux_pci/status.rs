use super::config::{clear16_w1c, read16};
use super::types::*;

const PCI_STATUS: u8 = 0x06;
const PCI_STATUS_ERROR_BITS: u16 = 0xf900;

/// Register PCI status KPI symbols. # C: O(1)
pub(super) fn export_symbols() {
    crate::symtab::export("pci_status_get_and_clear_errors", pci_status_get_and_clear_errors as *const () as usize, false);
}

pub(super) extern "C" fn pci_status_get_and_clear_errors(dev: *mut LinuxPciDev) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    let status = read16(dev, PCI_STATUS) & PCI_STATUS_ERROR_BITS;
    if status != 0 { clear16_w1c(dev, PCI_STATUS, status); }
    status as i32
}
