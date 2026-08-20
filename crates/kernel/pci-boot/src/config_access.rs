// Arch ECAM accessor exported to the driver model as config-space hooks, so
// sysfs can serve `config` (and the identity attributes derived from it)
// without an arch dependency.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};
use pci::uapi::CFG_SPACE_SIZE;
use firmware::acpi::{AmlError, RegionAccess, RegionAccessDirection, RegionSpace};
use sync::{Devices, Spinlock};

const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;

#[derive(Copy, Clone)]
struct MemoryPage { pa: u64, va: u64 }

struct MemoryPages { entries: Box<[MemoryPage]> }

static MEMORY_PAGES: AtomicPtr<MemoryPages> = AtomicPtr::new(core::ptr::null_mut());
static MEMORY_PAGE_WRITER: Spinlock<(), Devices> = Spinlock::new(());

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
        RegionSpace::SystemMemory => system_memory_access(access.base, access.offset,
                                                           access.width, write),
        RegionSpace::SystemIo => system_io_access(access.base, access.offset, access.width, write),
        RegionSpace::PciConfig => pci_config_access(access, write),
        _ => None,
    };
    value.ok_or(AmlError::RegionAccessUnavailable)
}

/// Access one naturally aligned firmware SystemMemory register through a
/// boot-lifetime device mapping. FADT event pages are touched during SCI init,
/// so the hard handler only traverses the immutable published page table and
/// never maps or allocates. # C: O(N_pages)
fn system_memory_access(base: u64, offset: u64, width: u64, write: Option<u64>) -> Option<u64> {
    let (page_pa, in_page) = firmware::acpi::system_memory_location(
        base, offset, width, PAGE_BYTES)?;
    let va = mapped_page(page_pa)?.checked_add(in_page)? as *mut u8;
    Some(match (width, write) {
        // SAFETY: mapped_page retains a device mapping for the boot lifetime;
        // system_memory_location checked width alignment and page extent.
        (8, None) => u64::from(unsafe { core::ptr::read_volatile(va.cast::<u8>()) }),
        (16, None) => u64::from(unsafe { core::ptr::read_volatile(va.cast::<u16>()) }),
        (32, None) => u64::from(unsafe { core::ptr::read_volatile(va.cast::<u32>()) }),
        (64, None) => unsafe { core::ptr::read_volatile(va.cast::<u64>()) },
        (8, Some(value)) => { unsafe { core::ptr::write_volatile(va.cast::<u8>(), value as u8) }; 0 }
        (16, Some(value)) => { unsafe { core::ptr::write_volatile(va.cast::<u16>(), value as u16) }; 0 }
        (32, Some(value)) => { unsafe { core::ptr::write_volatile(va.cast::<u32>(), value as u32) }; 0 }
        (64, Some(value)) => { unsafe { core::ptr::write_volatile(va.cast::<u64>(), value) }; 0 }
        _ => return None,
    })
}

fn published_memory_page(pa: u64) -> Option<u64> {
    let pointer = MEMORY_PAGES.load(Ordering::Acquire);
    if pointer.is_null() { return None; }
    // SAFETY: snapshots are leaked after publication and never mutated.
    let pages = unsafe { &*pointer };
    pages.entries.iter().find(|entry| entry.pa == pa).map(|entry| entry.va)
}

fn mapped_page(pa: u64) -> Option<u64> {
    if let Some(va) = published_memory_page(pa) { return Some(va); }
    let _writer = MEMORY_PAGE_WRITER.lock();
    if let Some(va) = published_memory_page(pa) { return Some(va); }
    // SAFETY: this is a firmware-declared SystemMemory register page. The
    // immutable page cache becomes its sole boot-lifetime MMIO owner.
    let mapping = unsafe { mmio_map::map_owned(pa, 1) };
    let va = mapping.base_va();
    let _mapping = Box::leak(Box::new(mapping));
    let mut entries = Vec::new();
    let previous = MEMORY_PAGES.load(Ordering::Acquire);
    if !previous.is_null() {
        // SAFETY: published snapshots are leaked and immutable.
        entries.extend_from_slice(unsafe { &(*previous).entries });
    }
    entries.push(MemoryPage { pa, va });
    let snapshot = Box::into_raw(Box::new(MemoryPages { entries: entries.into_boxed_slice() }));
    MEMORY_PAGES.store(snapshot, Ordering::Release);
    Some(va)
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
