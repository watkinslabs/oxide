use super::config::{read32, write32};
use super::types::*;
use crate::linux_pm::types::{LinuxPmMessage, PM_EVENT_HIBERNATE, PM_EVENT_ON, PM_EVENT_SUSPEND};
use crate::linux_device::devres;

const PCI_COMMAND_INVALIDATE: u32 = 1 << 4;
const PCI_COMMAND_OFFSET: u8 = 4;
const LINUX_EOPNOTSUPP: i32 = 95;
const PCI_CONFIG_HEADER_DWORDS: usize = 16;
const PCI_HEADER_TYPE_NORMAL: u8 = 0;
const PCI_HEADER_TYPE_BRIDGE: u8 = 1;

/// Register Linux PCI PM KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("pci_save_state",       pci_save_state       as *const () as usize),
        ("pci_restore_state",    pci_restore_state    as *const () as usize),
        ("pci_load_saved_state", pci_load_saved_state as *const () as usize),
        ("pci_set_power_state",  pci_set_power_state  as *const () as usize),
        ("pci_choose_state",     pci_choose_state     as *const () as usize),
        ("pci_enable_wake",      pci_enable_wake      as *const () as usize),
        ("pci_wake_from_d3",     pci_wake_from_d3     as *const () as usize),
        ("pci_prepare_to_sleep", pci_prepare_to_sleep as *const () as usize),
        ("pci_dev_run_wake",     pci_dev_run_wake     as *const () as usize),
        ("pci_disable_link_state", pci_disable_link_state as *const () as usize),
        ("pci_reset_bus",        pci_reset_bus        as *const () as usize),
        ("pcim_set_mwi",         pcim_set_mwi         as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn pci_save_state(dev: *mut LinuxPciDev) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    let mut saved = [0; PCI_CONFIG_HEADER_DWORDS];
    for (index, value) in saved.iter_mut().enumerate() { *value = read32(dev, (index * core::mem::size_of::<u32>()) as u8); }
    // SAFETY: dev is non-null and saved_config_space is the ABI-visible PCI header snapshot.
    unsafe { (*dev).saved_config_space = saved; }
    let _ = super::registry::load_saved_config(dev);
    LINUX_OK
}

extern "C" fn pci_restore_state(dev: *mut LinuxPciDev) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    restore_config_space(dev);
    let _ = super::registry::discard_saved_config(dev);
    LINUX_OK
}

/// Discard a saved PCI state, or load its fixed configuration-space prefix. # C: O(N)
extern "C" fn pci_load_saved_state(dev: *mut LinuxPciDev, state: *const LinuxPciSavedState) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    if state.is_null() {
        let _ = super::registry::discard_saved_config(dev);
        return LINUX_OK;
    }
    // SAFETY: state follows the Linux PCI saved-state ABI, whose fixed prefix is 16 dwords.
    unsafe { (*dev).saved_config_space = (*state).config_space; }
    let _ = super::registry::load_saved_config(dev);
    LINUX_OK
}

fn restore_config_space(dev: *mut LinuxPciDev) {
    // SAFETY: callers reject null and this function only reads the fixed PCI header array.
    let saved = unsafe { (*dev).saved_config_space };
    // SAFETY: callers reject null and hdr_type is part of the caller-owned PCI device ABI.
    match unsafe { (*dev).hdr_type & 0x7f } {
        PCI_HEADER_TYPE_NORMAL => {
            restore_config_range(dev, &saved, 10, 15, false);
            restore_config_range(dev, &saved, 4, 9, false);
            restore_config_range(dev, &saved, 0, 3, false);
        }
        PCI_HEADER_TYPE_BRIDGE => {
            restore_config_range(dev, &saved, 12, 15, false);
            restore_config_range(dev, &saved, 9, 11, true);
            restore_config_range(dev, &saved, 0, 8, false);
        }
        _ => restore_config_range(dev, &saved, 0, 15, false),
    }
}

fn restore_config_range(dev: *mut LinuxPciDev, saved: &[u32; PCI_CONFIG_HEADER_DWORDS], start: usize, end: usize, force: bool) {
    for index in (start..=end).rev() {
        let offset = (index * core::mem::size_of::<u32>()) as u8;
        if force || read32(dev, offset) != saved[index] { write32(dev, offset, saved[index]); }
    }
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

/// Configure wake in the deepest D3 state from which this device can signal PME.
/// # C: O(1)
extern "C" fn pci_wake_from_d3(dev: *mut LinuxPciDev, enable: bool) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    // SAFETY: dev was checked non-null; the first PM bitfield byte stores the PCI PME state mask.
    let supports_d3cold = unsafe { (*dev).pm_cap != 0 && ((*dev)._pm_flags[0] & (1 << PCI_D3COLD)) != 0 };
    pci_enable_wake(dev, if supports_d3cold { PCI_D3COLD } else { PCI_D3HOT }, enable)
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
