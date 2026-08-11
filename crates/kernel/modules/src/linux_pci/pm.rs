use super::types::*;
use crate::linux_pm::types::{LinuxPmMessage, PM_EVENT_HIBERNATE, PM_EVENT_ON, PM_EVENT_SUSPEND};
use crate::linux_device::devres;

const PCI_COMMAND_INVALIDATE: u32 = 1 << 4;
const PCI_COMMAND_OFFSET: u8 = 4;
const LINUX_EOPNOTSUPP: i32 = 95;

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
        ("pci_prepare_to_sleep", pci_prepare_to_sleep as *const () as usize),
        ("pci_dev_run_wake",     pci_dev_run_wake     as *const () as usize),
        ("pci_disable_link_state", pci_disable_link_state as *const () as usize),
        ("pci_reset_bus",        pci_reset_bus        as *const () as usize),
        ("pcim_set_mwi",         pcim_set_mwi         as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn pci_save_state(dev: *mut LinuxPciDev) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    let _ = super::registry::save_config(dev);
    LINUX_OK
}

extern "C" fn pci_restore_state(dev: *mut LinuxPciDev) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    let _ = super::registry::restore_config(dev);
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
    let _ = super::registry::set_wake_enabled(dev, enable);
    LINUX_OK
}

extern "C" fn pci_prepare_to_sleep(dev: *mut LinuxPciDev) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    // SAFETY: dev is non-null and its embedded PM state owns the wake decision.
    let wake = unsafe { (*dev).dev.power.can_wakeup() && (*dev).dev.power.wakeup_enabled() };
    let state = if wake { PCI_D3HOT } else { PCI_D3HOT };
    let rc = pci_enable_wake(dev, state, wake);
    if rc != LINUX_OK { return rc; }
    let rc = pci_set_power_state(dev, state);
    if rc != LINUX_OK { let _ = pci_enable_wake(dev, state, false); }
    rc
}

extern "C" fn pci_dev_run_wake(dev: *mut LinuxPciDev) -> bool {
    // SAFETY: a non-null dev contains its canonical wake capability state.
    !dev.is_null() && unsafe { (*dev).dev.power.can_wakeup() && (*dev).dev.power.wakeup_enabled() }
}

extern "C" fn pci_disable_link_state(dev: *mut LinuxPciDev, _state: i32) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    LINUX_OK
}

extern "C" fn pci_reset_bus(dev: *mut LinuxPciDev) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    /* There is no registered bridge/slot reset owner in the current PCI model.
     * Returning the documented unsupported result lets driver reset fallbacks run. */
    -LINUX_EOPNOTSUPP
}

extern "C" fn pcim_set_mwi(dev: *mut LinuxPciDev) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    // SAFETY: the embedded device is initialized with the PCI binding and owns its devres list.
    let base = unsafe { &mut (*dev).dev as *mut _ };
    if devres::add_action_or_reset(base, Some(pcim_clear_mwi), dev.cast()) != LINUX_OK { return -LINUX_ENOMEM; }
    update_mwi(dev, true);
    LINUX_OK
}

unsafe extern "C" fn pcim_clear_mwi(data: *mut core::ffi::c_void) {
    if data.is_null() { return; }
    // SAFETY: devres passes precisely the PCI device recorded by pcim_set_mwi.
    update_mwi(data.cast(), false);
}

fn update_mwi(dev: *mut LinuxPciDev, enabled: bool) {
    let old = super::config::read16(dev, PCI_COMMAND_OFFSET);
    let next = if enabled { old | PCI_COMMAND_INVALIDATE as u16 } else { old & !(PCI_COMMAND_INVALIDATE as u16) };
    super::config::write16(dev, PCI_COMMAND_OFFSET, next);
}

fn valid_power_state(state: i32) -> bool {
    (PCI_D0..=PCI_D3COLD).contains(&state)
}

#[cfg(test)]
mod tests;
