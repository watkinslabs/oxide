// Arch ECAM accessor exported to the driver model as config-space hooks, so
// sysfs can serve `config` (and the identity attributes derived from it)
// without an arch dependency.

use pci::uapi::CFG_SPACE_SIZE;

/// Whether a `[off, off+len)` access stays inside the addressable space.
/// # C: O(1)
fn in_space(off: usize, len: usize) -> bool {
    off.checked_add(len).is_some_and(|end| end <= CFG_SPACE_SIZE)
}

/// Config-space read hook: `false` when the address is not a PCI function,
/// the access leaves config space, or no ECAM accessor is published.
/// # C: O(n)
fn config_read(addr: &str, off: usize, buf: &mut [u8]) -> bool {
    let bdf = match pci::parse_bdf_addr(addr) { Some(b) => b, None => return false };
    if !in_space(off, buf.len()) { return false; }
    #[cfg(target_arch = "x86_64")]
    {
        match hal_x86_64::pci::EcamPci::from_published() {
            Some(r) => { pci::read_bytes(&r, bdf, off, buf); true }
            None => false,
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        match hal_aarch64::pci::EcamPci::from_published() {
            Some(r) => { pci::read_bytes(&r, bdf, off, buf); true }
            None => false,
        }
    }
}

/// Config-space write hook, same failure contract as [`config_read`].
/// # C: O(n)
fn config_write(addr: &str, off: usize, buf: &[u8]) -> bool {
    let bdf = match pci::parse_bdf_addr(addr) { Some(b) => b, None => return false };
    if !in_space(off, buf.len()) { return false; }
    #[cfg(target_arch = "x86_64")]
    {
        match hal_x86_64::pci::EcamPci::from_published() {
            Some(r) => { pci::write_bytes(&r, bdf, off, buf); true }
            None => false,
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        match hal_aarch64::pci::EcamPci::from_published() {
            Some(r) => { pci::write_bytes(&r, bdf, off, buf); true }
            None => false,
        }
    }
}

/// PCI identity of `bdf` that only config space carries. # C: O(1)
pub(crate) fn pci_ident(d: &pci::PciDevice) -> drv::PciIdent {
    let mut ident = drv::PciIdent {
        revision: d.revision,
        header_type: d.header_type,
        ..drv::PciIdent::default()
    };
    #[cfg(target_arch = "x86_64")]
    let reader = hal_x86_64::pci::EcamPci::from_published();
    #[cfg(target_arch = "aarch64")]
    let reader = hal_aarch64::pci::EcamPci::from_published();
    if let Some(r) = reader {
        let (svid, sdid) = pci::subsystem_ids(&r, d.bdf, d.header_type);
        ident.subsystem_vendor = svid;
        ident.subsystem_device = sdid;
        ident.interrupt_line = pci::interrupt_line(&r, d.bdf);
        ident.serial_number = pci::device_serial_number(&r, d.bdf);
    }
    ident
}

/// Publish the config-space and rescan indirection to the driver model.
/// # C: O(1)
pub(crate) fn install_hooks() {
    drv::set_pci_config_hooks(config_read, config_write);
    drv::set_pci_rescan_hook(super::rescan);
}
