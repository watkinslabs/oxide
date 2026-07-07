use super::types::*;
use crate::linux_pm::types::{LinuxPmMessage, PM_EVENT_HIBERNATE, PM_EVENT_ON, PM_EVENT_SUSPEND};

/// Register Linux PCI PM KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("pci_save_state",       pci_save_state       as *const () as usize),
        ("pci_restore_state",    pci_restore_state    as *const () as usize),
        ("pci_set_power_state",  pci_set_power_state  as *const () as usize),
        ("pci_choose_state",     pci_choose_state     as *const () as usize),
        ("pci_enable_wake",      pci_enable_wake      as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn pci_save_state(dev: *mut LinuxPciDev) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    // SAFETY: dev points at a caller-owned Linux struct pci_dev.
    unsafe { (*dev).saved_config_space = (*dev).config_space; }
    LINUX_OK
}

extern "C" fn pci_restore_state(dev: *mut LinuxPciDev) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    // SAFETY: dev points at a caller-owned Linux struct pci_dev.
    unsafe { (*dev).config_space = (*dev).saved_config_space; }
    LINUX_OK
}

extern "C" fn pci_set_power_state(dev: *mut LinuxPciDev, state: i32) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    if !valid_power_state(state) { return PCI_POWER_ERROR; }
    // SAFETY: dev points at a caller-owned Linux struct pci_dev.
    unsafe { (*dev).current_state = state; }
    LINUX_OK
}

extern "C" fn pci_choose_state(_dev: *mut LinuxPciDev, state: LinuxPmMessage) -> i32 {
    match state.event {
        PM_EVENT_ON => PCI_D0,
        PM_EVENT_SUSPEND | PM_EVENT_HIBERNATE => PCI_D3HOT,
        _ => PCI_D3COLD,
    }
}

extern "C" fn pci_enable_wake(dev: *mut LinuxPciDev, state: i32, enable: bool) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    if !valid_power_state(state) { return PCI_POWER_ERROR; }
    // SAFETY: dev points at a caller-owned Linux struct pci_dev.
    unsafe { (*dev).wake_enabled = enable; }
    LINUX_OK
}

fn valid_power_state(state: i32) -> bool {
    (PCI_D0..=PCI_D3COLD).contains(&state)
}

#[cfg(test)]
mod tests;
