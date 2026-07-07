use super::types::LinuxResource;
use core::ffi::c_void;
use core::ptr::null_mut;
use pci::{IORESOURCE_IO, IORESOURCE_MEM};
use sync::{Modules as ModulesLockClass, Spinlock};

const MAX_IOMAPS: usize = 64;
const PAGE_SHIFT: u64 = 12;
const PAGE_SIZE: u64 = 1u64 << PAGE_SHIFT;
const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

#[derive(Copy, Clone)]
pub(super) struct PciIomap {
    pub(super) ptr: usize,
    pub(super) base_va: u64,
    pub(super) n_pages: u64,
    pub(super) mem: bool,
}

static IOMAPS: Spinlock<[Option<PciIomap>; MAX_IOMAPS], ModulesLockClass> =
    Spinlock::new([None; MAX_IOMAPS]);

pub(super) fn iomap_resource(res: LinuxResource, len: u64) -> Option<*mut c_void> {
    if (res.flags & IORESOURCE_IO) != 0 { return Some(res.start as usize as *mut c_void); }
    if (res.flags & IORESOURCE_MEM) == 0 { return None; }
    let (ptr, base_va, n_pages) = map_resource(res.start, len);
    if ptr.is_null() { return None; }
    if insert_iomap(PciIomap { ptr: ptr as usize, base_va, n_pages, mem: true }).is_err() {
        unmap_resource(base_va, n_pages);
        return None;
    }
    Some(ptr)
}

pub(super) fn iounmap(addr: *mut c_void) {
    if addr.is_null() { return; }
    if let Some(rec) = remove_iomap(addr as usize) {
        if rec.mem { unmap_resource(rec.base_va, rec.n_pages); }
    }
}

fn insert_iomap(rec: PciIomap) -> Result<(), ()> {
    let mut g = IOMAPS.lock();
    if let Some(slot) = g.iter_mut().find(|r| r.is_none()) {
        *slot = Some(rec);
        Ok(())
    } else { Err(()) }
}

fn remove_iomap(ptr: usize) -> Option<PciIomap> {
    let mut g = IOMAPS.lock();
    for slot in g.iter_mut() {
        if slot.is_some_and(|r| r.ptr == ptr) { return slot.take(); }
    }
    None
}

fn map_resource(start: u64, len: u64) -> (*mut c_void, u64, u64) {
    let off = start & (PAGE_SIZE - 1);
    let base = start & PAGE_MASK;
    let total = match off.checked_add(len) { Some(v) => v, None => return (null_mut(), 0, 0) };
    let n_pages = (total + PAGE_SIZE - 1) >> PAGE_SHIFT;
    let base_va = map_mmio(base, n_pages);
    if base_va == 0 { return (null_mut(), 0, 0); }
    ((base_va + off) as usize as *mut c_void, base_va, n_pages)
}

#[cfg(target_os = "oxide-kernel")]
fn map_mmio(pa: u64, n_pages: u64) -> u64 {
    // SAFETY: pci_iomap maps a claimed PCI memory BAR for a trusted kernel module.
    unsafe { mmio_map::map_pages(pa, n_pages) }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn map_mmio(pa: u64, _n_pages: u64) -> u64 { pa }

#[cfg(target_os = "oxide-kernel")]
fn unmap_resource(base_va: u64, n_pages: u64) {
    // SAFETY: IOMAPS owns the VA range removed before this call.
    unsafe { mmio_map::unmap_pages(base_va, n_pages); }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn unmap_resource(_base_va: u64, _n_pages: u64) {}
