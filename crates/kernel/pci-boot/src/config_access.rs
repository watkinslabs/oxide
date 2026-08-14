// Arch ECAM accessor exported to the driver model as config-space hooks, so
// sysfs can serve `config` (and the identity attributes derived from it)
// without an arch dependency.

use pci::uapi::CFG_SPACE_SIZE;
use firmware::acpi::{AmlError, RegionAccess, RegionAccessDirection, RegionSpace};

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

/// Shut the generic PCI transport gates after the bound driver has released
/// its device state, before the driver model removes the function.
/// # C: O(N_caps)
fn quiesce_after_driver_remove(dev: &drv::Device) {
    let Some(bdf) = pci::parse_bdf_addr(&dev.addr) else { return; };
    if let Some(port) = pcie_port::find(bdf) { pcie_port::remove(&port); }
    #[cfg(target_arch = "x86_64")]
    if let Some(r) = hal_x86_64::pci::EcamPci::from_published() { pci::quiesce_function(&r, bdf); }
    #[cfg(target_arch = "aarch64")]
    if let Some(r) = hal_aarch64::pci::EcamPci::from_published() { pci::quiesce_function(&r, bdf); }
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
    drv::set_pci_remove_hook(Some(quiesce_after_driver_remove));
    drv::set_pci_rescan_hook(super::rescan);
}

/// Install the sole AML OperationRegion adapter after ECAM publication. # C: O(1)
pub(crate) fn install_aml_region_backend() {
    firmware::acpi::install_region_backend(operation_region_access);
}

fn operation_region_access(access: RegionAccess, value: u64) -> Result<u64, AmlError> {
    let write = (access.direction == RegionAccessDirection::Write).then_some(value);
    let value = match access.space {
        RegionSpace::SystemMemory => None,
        RegionSpace::SystemIo => system_io_access(access.base, access.offset, access.width, write),
        RegionSpace::PciConfig => pci_config_access(access, write),
        _ => None,
    };
    value.ok_or(AmlError::RegionAccessUnavailable)
}

fn system_io_access(base: u64, offset: u64, width: u64, write: Option<u64>) -> Option<u64> {
    let port = base.checked_add(offset)?;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::io::operation_region_access(port, width, write) }
    #[cfg(target_arch = "aarch64")]
    { let _ = (port, width, write); None }
}

fn pci_config_access(access: RegionAccess, write: Option<u64>) -> Option<u64> {
    let address = access.pci?;
    let offset = u16::try_from(access.base.checked_add(access.offset)?).ok()?;
    let bdf = pci::Bdf { segment: address.segment, bus: address.bus, device: address.device, function: address.function };
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::pci::EcamPci::from_published()?.operation_region_access(bdf, offset, access.width, write) }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::pci::EcamPci::from_published()?.operation_region_access(bdf, offset, access.width, write) }
}
