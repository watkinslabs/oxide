use super::types::{LinuxResource, IORESOURCE_MEM};
use core::ffi::c_void;
use core::ptr::null_mut;
use sync::{Modules as ModulesLockClass, Spinlock};

const MAX_IOMAPS: usize = 64;
const PAGE_SHIFT: u64 = 12;
const PAGE_SIZE: u64 = 1u64 << PAGE_SHIFT;
const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

#[derive(Copy, Clone)]
#[allow(dead_code)]
struct PlatformIomap {
    ptr: usize,
    base_va: u64,
    n_pages: u64,
}

static IOMAPS: Spinlock<[Option<PlatformIomap>; MAX_IOMAPS], ModulesLockClass> =
    Spinlock::new([None; MAX_IOMAPS]);

pub(super) fn iomap_resource(res: LinuxResource, len: u64) -> Option<*mut c_void> {
    if (res.flags & IORESOURCE_MEM) == 0 { return None; }
    let (ptr, base_va, n_pages) = map_resource(res.start, len);
    if ptr.is_null() { return None; }
    if insert_iomap(PlatformIomap { ptr: ptr as usize, base_va, n_pages }).is_err() {
        unmap_resource(base_va, n_pages);
        return None;
    }
    Some(ptr)
}

fn insert_iomap(rec: PlatformIomap) -> Result<(), ()> {
    let mut g = IOMAPS.lock();
    if let Some(slot) = g.iter_mut().find(|r| r.is_none()) {
        *slot = Some(rec);
        Ok(())
    } else { Err(()) }
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
    // SAFETY: platform devm ioremap maps a discovered platform MMIO resource.
    unsafe { mmio_map::map_pages(pa, n_pages) }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn map_mmio(pa: u64, _n_pages: u64) -> u64 { pa }

#[cfg(target_os = "oxide-kernel")]
fn unmap_resource(base_va: u64, n_pages: u64) {
    // SAFETY: failed insertion owns the temporary VA range being unwound.
    unsafe { mmio_map::unmap_pages(base_va, n_pages); }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn unmap_resource(_base_va: u64, _n_pages: u64) {}
