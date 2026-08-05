// Linux vmap KPI helpers owned by linux_alloc.rs.

use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(target_os = "oxide-kernel")]
use alloc::vec::Vec;
#[cfg(target_os = "oxide-kernel")]
use hal::PageFlags;
#[cfg(not(target_os = "oxide-kernel"))]
use super::{page_address, PAGE_SIZE};
use super::{linux_page_phys, LinuxPage};

const VMAP_SLOTS: usize = 64;
const VMAP_BUSY: usize = usize::MAX;

static VMAP_BASES: [AtomicUsize; VMAP_SLOTS] = [const { AtomicUsize::new(0) }; VMAP_SLOTS];
static VMAP_COUNTS: [AtomicUsize; VMAP_SLOTS] = [const { AtomicUsize::new(0) }; VMAP_SLOTS];

pub(super) unsafe extern "C" fn vmap(
    pages: *mut *mut LinuxPage,
    count: u32,
    _flags: usize,
    _prot: usize,
) -> *mut c_void {
    if pages.is_null() || count == 0 { return null_mut(); }
    let base = match map_page_array(pages, count as usize) {
        Some(v) => v,
        None => return null_mut(),
    };
    if base.is_null() { return null_mut(); }
    if !remember(base as usize, count as usize) {
        unmap_page_array(base as usize, count as usize);
        return null_mut();
    }
    base as *mut c_void
}

pub(super) extern "C" fn vunmap(addr: *const c_void) {
    if addr.is_null() { return; }
    if let Some(count) = forget(addr as usize) {
        unmap_page_array(addr as usize, count);
    }
}

fn map_page_array(pages: *mut *mut LinuxPage, count: usize) -> Option<*mut u8> {
    #[cfg(target_os = "oxide-kernel")]
    {
        let mut phys = Vec::new();
        phys.try_reserve_exact(count).ok()?;
        for i in 0..count {
            // SAFETY: vmap caller supplies an array of count struct page pointers.
            let page = unsafe { *pages.add(i) };
            // SAFETY: vmap's KPI requires each array entry to be a live struct page descriptor.
            phys.push(unsafe { linux_page_phys(page)? });
        }
        // SAFETY: vmap validated every struct page and keeps the alias tracked for vunmap.
        Some(unsafe {
            mmio_map::map_page_list(&phys, PageFlags::READ | PageFlags::WRITE) as *mut u8
        })
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
        // SAFETY: caller supplies at least one struct page pointer.
        let first = unsafe { *pages };
        // SAFETY: vmap's KPI requires the first array entry to be a live struct page descriptor.
        let first_pa = unsafe { linux_page_phys(first)? };
        for i in 0..count {
            // SAFETY: caller supplies an array of count struct page pointers.
            let page = unsafe { *pages.add(i) };
            // SAFETY: vmap's KPI requires each array entry to be a live struct page descriptor.
            let pa = unsafe { linux_page_phys(page)? };
            if pa != first_pa + (i * PAGE_SIZE) as u64 { return None; }
        }
        Some(page_address(first))
    }
}

fn unmap_page_array(addr: usize, count: usize) {
    #[cfg(target_os = "oxide-kernel")]
    {
        // SAFETY: addr/count came from map_page_array and was remembered once.
        unsafe { mmio_map::unmap_pages(addr as u64, count as u64); }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
        let _ = (addr, count);
    }
}

fn remember(base: usize, count: usize) -> bool {
    if base == 0 || base == VMAP_BUSY || count == 0 { return false; }
    for i in 0..VMAP_SLOTS {
        if VMAP_BASES[i].compare_exchange(0, VMAP_BUSY, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            VMAP_COUNTS[i].store(count, Ordering::Release);
            VMAP_BASES[i].store(base, Ordering::Release);
            return true;
        }
    }
    false
}

fn forget(base: usize) -> Option<usize> {
    for i in 0..VMAP_SLOTS {
        if VMAP_BASES[i].compare_exchange(base, VMAP_BUSY, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            let count = VMAP_COUNTS[i].swap(0, Ordering::AcqRel);
            VMAP_BASES[i].store(0, Ordering::Release);
            return Some(count);
        }
    }
    None
}
