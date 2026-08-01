// PCI-function identity carried by a model device, plus the config-space
// and rescan indirection sysfs uses.
//
// The arch config-space accessor lives in the boot PCI crate; this crate is
// bus-agnostic, so the accessor arrives as an installed hook (the SYSFS_HOOK
// pattern) instead of a dependency edge.

use sync::{Spinlock, TaskList as DriverListClass};

/// Identity a PCI function publishes beyond vendor/device/class, captured
/// from config space when the bus registers the device.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct PciIdent {
    /// 8-bit revision id.
    pub revision: u8,
    /// Raw header-type register, multifunction bit included.
    pub header_type: u8,
    /// Subsystem vendor id (0 when the header type carries none).
    pub subsystem_vendor: u16,
    /// Subsystem device id (0 when the header type carries none).
    pub subsystem_device: u16,
    /// Legacy INTx line, 0 when the function reports no INTx pin.
    pub interrupt_line: u32,
}

/// Read `buf.len()` config-space bytes of the function at `addr` starting at
/// `off`. False = no accessor, or no such function.
pub type PciConfigReadHook = fn(&str, usize, &mut [u8]) -> bool;
/// Write `buf` into the config space of the function at `addr` at `off`.
pub type PciConfigWriteHook = fn(&str, usize, &[u8]) -> bool;
/// Re-enumerate the PCI hierarchy, publishing functions not yet registered.
pub type PciRescanHook = fn();

static CONFIG_READ_HOOK:  Spinlock<Option<PciConfigReadHook>,  DriverListClass> = Spinlock::new(None);
static CONFIG_WRITE_HOOK: Spinlock<Option<PciConfigWriteHook>, DriverListClass> = Spinlock::new(None);
static RESCAN_HOOK:       Spinlock<Option<PciRescanHook>,      DriverListClass> = Spinlock::new(None);

/// Install the config-space accessors (the kernel wires the arch ECAM
/// reader). # C: O(1)
pub fn set_pci_config_hooks(read: PciConfigReadHook, write: PciConfigWriteHook) {
    *CONFIG_READ_HOOK.lock()  = Some(read);
    *CONFIG_WRITE_HOOK.lock() = Some(write);
}

/// Install the bus-rescan hook. # C: O(1)
pub fn set_pci_rescan_hook(f: PciRescanHook) { *RESCAN_HOOK.lock() = Some(f); }

/// Read config space of the function at `addr`. # C: O(n)
pub fn pci_config_read(addr: &str, off: usize, buf: &mut [u8]) -> bool {
    let hook = *CONFIG_READ_HOOK.lock();
    match hook { Some(h) => h(addr, off, buf), None => false }
}

/// Write config space of the function at `addr`. # C: O(n)
pub fn pci_config_write(addr: &str, off: usize, buf: &[u8]) -> bool {
    let hook = *CONFIG_WRITE_HOOK.lock();
    match hook { Some(h) => h(addr, off, buf), None => false }
}

/// Re-enumerate the PCI hierarchy. False = no accessor installed. # C: O(N_bdfs)
pub fn pci_rescan() -> bool {
    let hook = *RESCAN_HOOK.lock();
    match hook { Some(h) => { h(); true } None => false }
}
