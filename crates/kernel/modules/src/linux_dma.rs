// Linux DMA mapping KPI exports for loadable drivers.

use alloc::alloc::{alloc_zeroed, dealloc, Layout};
use core::cmp::min;
use core::ffi::c_void;
use core::mem::{align_of, size_of};
use core::ptr::{copy_nonoverlapping, null_mut, write_bytes};
use core::sync::atomic::{compiler_fence, fence, Ordering};

use crate::linux_alloc::{self, LinuxPage};

pub(crate) const DMA_MAPPING_ERROR: u64 = 0;
const LINUX_OK: i32 = 0;
const LINUX_EIO: i32 = 5;
pub(crate) const LINUX_EINVAL: i32 = 22;
const DMA_NONE: i32 = 0;
pub(crate) const DMA_TO_DEVICE: i32 = 1;
const DMA_FROM_DEVICE: i32 = 2;
pub(crate) const DMA_BIDIRECTIONAL: i32 = 3;
pub(crate) const DEFAULT_DMA_MASK: u64 = u64::MAX;
const DMA_ADDRESS_BITS: u32 = u64::BITS;
pub(crate) const SG_END: usize = 0x02;
// Only `linux_dma_tests` drives `sg_miter_start`; no in-tree module maps an SG
// list yet, so the direction flag has no production reader.
#[cfg(test)]
pub(crate) const SG_MITER_FROM_SG: u32 = 1 << 2;

#[repr(C)]
pub struct LinuxDevice {
    pub(crate) dma_mask: *mut u64,
    pub(crate) coherent_dma_mask: u64,
    pub(crate) driver_data: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ScatterList {
    pub(crate) page_link: usize,
    pub(crate) offset: u32,
    pub(crate) length: u32,
    pub(crate) dma_address: u64,
    pub(crate) dma_length: u32,
}

#[repr(C)]
pub struct SgTable {
    pub(crate) sgl: *mut ScatterList,
    pub(crate) nents: u32,
    pub(crate) orig_nents: u32,
}

#[repr(C)]
pub struct SgPageIter {
    pub(crate) sg: *mut ScatterList,
    pub(crate) sg_pgoffset: u32,
    pub(crate) nents: u32,
    pub(crate) pg_advance: i32,
}

#[repr(C)]
pub struct SgMappingIter {
    pub(crate) page: *mut LinuxPage,
    pub(crate) addr: *mut c_void,
    pub(crate) length: usize,
    pub(crate) consumed: usize,
    pub(crate) piter: SgPageIter,
    pub(crate) offset: u32,
    pub(crate) remaining: u32,
    pub(crate) flags: u32,
}

/// Register Linux DMA mapping KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("dma_alloc_coherent",        dma_alloc_coherent        as *const () as usize),
        ("dmam_alloc_coherent",       dma_alloc_coherent        as *const () as usize),
        ("dma_free_coherent",         dma_free_coherent         as *const () as usize),
        ("dmam_free_coherent",        dma_free_coherent         as *const () as usize),
        ("dma_map_single",            dma_map_single            as *const () as usize),
        ("dma_unmap_single",          dma_unmap_single          as *const () as usize),
        ("dma_map_page",              dma_map_page              as *const () as usize),
        ("dma_unmap_page",            dma_unmap_page            as *const () as usize),
        ("dma_map_sg",                dma_map_sg                as *const () as usize),
        ("dma_unmap_sg",              dma_unmap_sg              as *const () as usize),
        ("dma_mapping_error",         dma_mapping_error         as *const () as usize),
        ("dma_sync_single_for_cpu",    dma_sync_single_for_cpu    as *const () as usize),
        ("dma_sync_single_for_device", dma_sync_single_for_device as *const () as usize),
        ("dma_sync_sg_for_cpu",        dma_sync_sg_for_cpu        as *const () as usize),
        ("dma_sync_sg_for_device",     dma_sync_sg_for_device     as *const () as usize),
        ("dma_set_mask",              dma_set_mask              as *const () as usize),
        ("dma_set_coherent_mask",     dma_set_coherent_mask     as *const () as usize),
        ("dma_set_mask_and_coherent", dma_set_mask_and_coherent as *const () as usize),
        ("dma_supported",             dma_supported             as *const () as usize),
        ("dma_get_required_mask",     dma_get_required_mask     as *const () as usize),
        ("sg_init_table",             sg_init_table             as *const () as usize),
        ("sg_init_one",               sg_init_one               as *const () as usize),
        ("sg_set_buf",                sg_set_buf                as *const () as usize),
        ("sg_set_page",               sg_set_page               as *const () as usize),
        ("sg_next",                   sg_next                   as *const () as usize),
        ("sg_alloc_table",            sg_alloc_table            as *const () as usize),
        ("sg_free_table",             sg_free_table             as *const () as usize),
        ("sg_copy_to_buffer",         sg_copy_to_buffer         as *const () as usize),
        ("sg_miter_start",            sg_miter_start            as *const () as usize),
        ("sg_miter_next",             sg_miter_next             as *const () as usize),
        ("sg_miter_stop",             sg_miter_stop             as *const () as usize),
        ("sgl_alloc_order",           crate::linux_dma_sgl::sgl_alloc_order as *const () as usize),
        ("sgl_free_n_order",          crate::linux_dma_sgl::sgl_free_n_order as *const () as usize),
    ] { export(name, addr, false); }
}

pub(crate) extern "C" fn dma_alloc_coherent(dev: *mut LinuxDevice, size: usize, dma_handle: *mut u64, flags: u64) -> *mut c_void {
    let _ = flags;
    if size == 0 || dma_handle.is_null() { return null_mut(); }
    let order = match order_for_size(size) { Some(v) => v, None => return null_mut() };
    let (pa, va) = match linux_alloc::page_run_alloc(order, true) { Some(v) => v, None => return null_mut() };
    if !fits_mask(pa, size, device_dma_mask(dev, true)) {
        linux_alloc::page_run_free_pa(pa, order);
        return null_mut();
    }
    // SAFETY: dma_handle is a non-null out pointer supplied by the caller.
    unsafe { *dma_handle = pa; }
    va as *mut c_void
}

pub(crate) extern "C" fn dma_free_coherent(_dev: *mut LinuxDevice, size: usize, cpu_addr: *mut c_void, dma_handle: u64) {
    if size == 0 || cpu_addr.is_null() || dma_handle == DMA_MAPPING_ERROR { return; }
    if let Some(order) = order_for_size(size) { linux_alloc::page_run_free_pa(dma_handle, order); }
}

pub(crate) extern "C" fn dma_map_single(dev: *mut LinuxDevice, ptr: *mut c_void, size: usize, dir: i32) -> u64 {
    if ptr.is_null() || size == 0 || !valid_dir(dir) { return DMA_MAPPING_ERROR; }
    let pa = match linux_alloc::direct_pa_for_va(ptr as *const u8) { Some(v) => v, None => return DMA_MAPPING_ERROR };
    if !fits_mask(pa, size, device_dma_mask(dev, false)) { return DMA_MAPPING_ERROR; }
    sync_for_device(dir);
    pa
}

pub(crate) extern "C" fn dma_unmap_single(_dev: *mut LinuxDevice, dma_addr: u64, size: usize, dir: i32) {
    if dma_addr == DMA_MAPPING_ERROR || size == 0 || !valid_dir(dir) { return; }
    sync_for_cpu(dir);
}

pub(crate) extern "C" fn dma_map_page(dev: *mut LinuxDevice, page: *mut LinuxPage, offset: usize, size: usize, dir: i32) -> u64 {
    if size == 0 || !valid_dir(dir) { return DMA_MAPPING_ERROR; }
    // SAFETY: dma_map_page's KPI requires page to be a live descriptor while the mapping is installed.
    let base = match unsafe { linux_alloc::linux_page_phys(page) } { Some(v) => v, None => return DMA_MAPPING_ERROR };
    let pa = match base.checked_add(offset as u64) { Some(v) => v, None => return DMA_MAPPING_ERROR };
    if !fits_mask(pa, size, device_dma_mask(dev, false)) { return DMA_MAPPING_ERROR; }
    sync_for_device(dir);
    pa
}

extern "C" fn dma_unmap_page(dev: *mut LinuxDevice, dma_addr: u64, size: usize, dir: i32) {
    dma_unmap_single(dev, dma_addr, size, dir);
}

pub(crate) extern "C" fn dma_map_sg(dev: *mut LinuxDevice, sg: *mut ScatterList, nents: i32, dir: i32) -> i32 {
    if sg.is_null() || nents <= 0 || !valid_dir(dir) { return 0; }
    let mut mapped = 0i32;
    for i in 0..nents as usize {
        // SAFETY: caller supplied an array containing nents scatterlist entries.
        let ent = unsafe { &mut *sg.add(i) };
        let dma = map_sg_entry(dev, ent, dir);
        if dma == DMA_MAPPING_ERROR { break; }
        ent.dma_address = dma;
        ent.dma_length = ent.length;
        mapped += 1;
    }
    mapped
}

pub(crate) extern "C" fn dma_unmap_sg(_dev: *mut LinuxDevice, sg: *mut ScatterList, nents: i32, dir: i32) {
    if sg.is_null() || nents <= 0 || !valid_dir(dir) { return; }
    sync_for_cpu(dir);
    for i in 0..nents as usize {
        // SAFETY: caller supplied an array containing nents scatterlist entries.
        let ent = unsafe { &mut *sg.add(i) };
        ent.dma_address = DMA_MAPPING_ERROR;
        ent.dma_length = 0;
    }
}

pub(crate) extern "C" fn dma_mapping_error(_dev: *mut LinuxDevice, dma_addr: u64) -> i32 {
    if dma_addr == DMA_MAPPING_ERROR { 1 } else { 0 }
}

extern "C" fn dma_sync_single_for_cpu(_dev: *mut LinuxDevice, _dma_addr: u64, size: usize, dir: i32) {
    if size != 0 && valid_dir(dir) { sync_for_cpu(dir); }
}

extern "C" fn dma_sync_single_for_device(_dev: *mut LinuxDevice, _dma_addr: u64, size: usize, dir: i32) {
    if size != 0 && valid_dir(dir) { sync_for_device(dir); }
}

extern "C" fn dma_sync_sg_for_cpu(_dev: *mut LinuxDevice, _sg: *mut ScatterList, nents: i32, dir: i32) {
    if nents > 0 && valid_dir(dir) { sync_for_cpu(dir); }
}

extern "C" fn dma_sync_sg_for_device(_dev: *mut LinuxDevice, _sg: *mut ScatterList, nents: i32, dir: i32) {
    if nents > 0 && valid_dir(dir) { sync_for_device(dir); }
}

extern "C" fn dma_set_mask(dev: *mut LinuxDevice, mask: u64) -> i32 {
    if dev.is_null() || mask == 0 { return -LINUX_EINVAL; }
    if dma_supported(dev, mask) == 0 { return -LINUX_EIO; }
    // SAFETY: dev follows the KPI struct device prefix from linux/device.h.
    unsafe {
        if (*dev).dma_mask.is_null() { return -LINUX_EIO; }
        *(*dev).dma_mask = mask;
    }
    LINUX_OK
}

extern "C" fn dma_set_coherent_mask(dev: *mut LinuxDevice, mask: u64) -> i32 {
    if dev.is_null() || mask == 0 { return -LINUX_EINVAL; }
    if dma_supported(dev, mask) == 0 { return -LINUX_EIO; }
    // SAFETY: dev follows the KPI struct device prefix from linux/device.h.
    unsafe { (*dev).coherent_dma_mask = mask; }
    LINUX_OK
}

extern "C" fn dma_set_mask_and_coherent(dev: *mut LinuxDevice, mask: u64) -> i32 {
    let r = dma_set_mask(dev, mask);
    if r != LINUX_OK { return r; }
    dma_set_coherent_mask(dev, mask)
}

extern "C" fn dma_supported(_dev: *mut LinuxDevice, mask: u64) -> i32 {
    if mask == 0 { 0 } else { 1 }
}

extern "C" fn dma_get_required_mask(_dev: *mut LinuxDevice) -> u64 {
    dma_bit_mask(DMA_ADDRESS_BITS)
}

pub(crate) unsafe extern "C" fn sg_init_table(sg: *mut ScatterList, nents: u32) {
    if sg.is_null() { return; }
    // SAFETY: caller supplied an array containing nents scatterlist entries.
    unsafe { write_bytes(sg, 0, nents as usize); }
    if nents > 0 {
        // SAFETY: caller supplied at least nents entries; mark the final entry as list end.
        unsafe { (*sg.add(nents as usize - 1)).page_link |= SG_END; }
    }
}

pub(crate) unsafe extern "C" fn sg_init_one(sg: *mut ScatterList, buf: *const c_void, buflen: u32) {
    // SAFETY: sg is the single entry supplied by the caller.
    unsafe { sg_init_table(sg, 1); }
    sg_set_buf(sg, buf, buflen);
}

pub(crate) extern "C" fn sg_set_buf(sg: *mut ScatterList, buf: *const c_void, buflen: u32) {
    if sg.is_null() { return; }
    // SAFETY: sg points at a caller-owned scatterlist entry.
    unsafe {
        (*sg).page_link &= SG_END;
        (*sg).offset = 0;
        (*sg).length = buflen;
        (*sg).dma_address = buf as u64;
        (*sg).dma_length = 0;
    }
}

pub(crate) extern "C" fn sg_set_page(sg: *mut ScatterList, page: *mut LinuxPage, len: u32, offset: u32) {
    if sg.is_null() { return; }
    // SAFETY: sg points at a caller-owned scatterlist entry.
    unsafe {
        (*sg).page_link = (page as usize) | ((*sg).page_link & SG_END);
        (*sg).offset = offset;
        (*sg).length = len;
        (*sg).dma_address = DMA_MAPPING_ERROR;
        (*sg).dma_length = 0;
    }
}

pub(crate) extern "C" fn sg_next(sg: *mut ScatterList) -> *mut ScatterList {
    if sg.is_null() { null_mut() } else {
        // SAFETY: sg points to a valid entry and page_link holds Linux end marker bits.
        unsafe { if (*sg).page_link & SG_END != 0 { null_mut() } else { sg.add(1) } }
    }
}

pub(crate) extern "C" fn sg_alloc_table(t: *mut SgTable, nents: u32, _flags: u32) -> i32 {
    if t.is_null() || nents == 0 { return -LINUX_EINVAL; }
    let layout = match sg_layout(nents) { Some(v) => v, None => return -LINUX_EINVAL };
    // SAFETY: layout has non-zero size and scatterlist alignment.
    let p = unsafe { alloc_zeroed(layout) as *mut ScatterList };
    if p.is_null() { return -LINUX_EIO; }
    // SAFETY: p points to nents scatterlist entries allocated above.
    unsafe { sg_init_table(p, nents); (*t).sgl = p; (*t).nents = nents; (*t).orig_nents = nents; }
    LINUX_OK
}

pub(crate) extern "C" fn sg_free_table(t: *mut SgTable) {
    if t.is_null() { return; }
    // SAFETY: table pointer is caller-owned and sgl/orig_nents follow sg_alloc_table contract.
    unsafe {
        if !(*t).sgl.is_null() && (*t).orig_nents != 0 {
            if let Some(layout) = sg_layout((*t).orig_nents) { dealloc((*t).sgl as *mut u8, layout); }
        }
        (*t).sgl = null_mut(); (*t).nents = 0; (*t).orig_nents = 0;
    }
}

pub(crate) extern "C" fn sg_copy_to_buffer(sg: *mut ScatterList, nents: u32, buf: *mut c_void, buflen: usize) -> usize {
    if sg.is_null() || buf.is_null() || nents == 0 || buflen == 0 { return 0; }
    let mut copied = 0usize;
    let mut cur = sg;
    for _ in 0..nents {
        if cur.is_null() || copied == buflen { break; }
        if let Some((src, len)) = sg_cpu_ptr_len(cur) {
            let n = min(len, buflen - copied);
            // SAFETY: src names readable sg bytes; buf has buflen caller-owned writable bytes.
            unsafe { copy_nonoverlapping(src, (buf as *mut u8).add(copied), n); }
            copied += n;
        }
        cur = sg_next(cur);
    }
    copied
}

pub(crate) extern "C" fn sg_miter_start(m: *mut SgMappingIter, sg: *mut ScatterList, nents: u32, flags: u32) {
    if m.is_null() { return; }
    // SAFETY: m points at Linux sg_mapping_iter storage supplied by the module.
    unsafe {
        (*m).page = null_mut(); (*m).addr = null_mut(); (*m).length = 0; (*m).consumed = 0;
        (*m).piter.sg = sg; (*m).piter.sg_pgoffset = 0; (*m).piter.nents = nents; (*m).piter.pg_advance = 0;
        (*m).offset = 0; (*m).remaining = 0; (*m).flags = flags;
    }
}

pub(crate) extern "C" fn sg_miter_next(m: *mut SgMappingIter) -> bool {
    if m.is_null() { return false; }
    // SAFETY: m points at Linux sg_mapping_iter storage initialized by sg_miter_start.
    unsafe {
        if !(*m).addr.is_null() {
            let used = min((*m).consumed, (*m).length);
            (*m).offset = (*m).offset.saturating_add(used as u32);
            (*m).remaining = (*m).remaining.saturating_sub(used as u32);
        }
        while (*m).piter.nents != 0 && !(*m).piter.sg.is_null() {
            let sg = (*m).piter.sg;
            if (*m).remaining == 0 {
                (*m).offset = 0;
                (*m).remaining = (*sg).length;
            }
            if (*m).remaining != 0 {
                if let Some((addr, len)) = sg_cpu_ptr_len_with_offset(sg, (*m).offset as usize) {
                    (*m).page = ((*sg).page_link & !SG_END) as *mut LinuxPage;
                    (*m).addr = addr as *mut c_void;
                    (*m).length = min(len, (*m).remaining as usize);
                    (*m).consumed = (*m).length;
                    return true;
                }
                (*m).remaining = 0;
            }
            (*m).piter.nents -= 1;
            (*m).piter.sg = sg_next(sg);
        }
        (*m).page = null_mut(); (*m).addr = null_mut(); (*m).length = 0; (*m).consumed = 0;
    }
    false
}

pub(crate) extern "C" fn sg_miter_stop(m: *mut SgMappingIter) {
    if m.is_null() { return; }
    // SAFETY: m points at Linux sg_mapping_iter storage supplied by the module.
    unsafe { (*m).page = null_mut(); (*m).addr = null_mut(); (*m).length = 0; (*m).consumed = 0; }
}

fn map_sg_entry(dev: *mut LinuxDevice, ent: &ScatterList, dir: i32) -> u64 {
    if ent.length == 0 { return DMA_MAPPING_ERROR; }
    let page = ent.page_link & !SG_END;
    let pa = if page != 0 {
        // SAFETY: a nonzero scatterlist page link names a live struct page descriptor for the map operation.
        let base = match unsafe { linux_alloc::linux_page_phys(page as *const LinuxPage) } { Some(v) => v, None => return DMA_MAPPING_ERROR };
        match base.checked_add(ent.offset as u64) { Some(v) => v, None => return DMA_MAPPING_ERROR }
    } else {
        match linux_alloc::direct_pa_for_va(ent.dma_address as *const u8) { Some(v) => v, None => return DMA_MAPPING_ERROR }
    };
    if !fits_mask(pa, ent.length as usize, device_dma_mask(dev, false)) { return DMA_MAPPING_ERROR; }
    sync_for_device(dir);
    pa
}

fn sg_layout(nents: u32) -> Option<Layout> {
    Layout::from_size_align(size_of::<ScatterList>().checked_mul(nents as usize)?, align_of::<ScatterList>()).ok()
}

fn sg_cpu_ptr_len(sg: *mut ScatterList) -> Option<(*const u8, usize)> {
    sg_cpu_ptr_len_with_offset(sg, 0)
}

fn sg_cpu_ptr_len_with_offset(sg: *mut ScatterList, extra: usize) -> Option<(*const u8, usize)> {
    if sg.is_null() { return None; }
    // SAFETY: sg points at a caller-owned scatterlist entry.
    let ent = unsafe { &*sg };
    if extra >= ent.length as usize { return None; }
    let base = if ent.page_link & !SG_END != 0 {
        let page = (ent.page_link & !SG_END) as *mut LinuxPage;
        let p = linux_alloc::page_address(page);
        if p.is_null() { return None; }
        p
    } else { ent.dma_address as *mut u8 };
    if base.is_null() { return None; }
    let off = ent.offset as usize + extra;
    Some((base.wrapping_add(off), ent.length as usize - extra))
}

fn order_for_size(size: usize) -> Option<u32> {
    let pages = size.checked_add(linux_alloc::PAGE_SIZE - 1)? / linux_alloc::PAGE_SIZE;
    let mut order = 0u32;
    let mut capacity = 1usize;
    while capacity < pages {
        capacity = capacity.checked_shl(1)?;
        order += 1;
    }
    Some(order)
}

fn fits_mask(addr: u64, size: usize, mask: u64) -> bool {
    if size == 0 || mask == 0 { return false; }
    let end = match addr.checked_add(size as u64 - 1) { Some(v) => v, None => return false };
    end <= mask
}

fn valid_dir(dir: i32) -> bool {
    matches!(dir, DMA_NONE | DMA_TO_DEVICE | DMA_FROM_DEVICE | DMA_BIDIRECTIONAL)
}

fn device_dma_mask(dev: *mut LinuxDevice, coherent: bool) -> u64 {
    if dev.is_null() { return DEFAULT_DMA_MASK; }
    // SAFETY: dev follows the KPI struct device prefix from linux/device.h.
    unsafe {
        if coherent && (*dev).coherent_dma_mask != 0 { return (*dev).coherent_dma_mask; }
        if !(*dev).dma_mask.is_null() { *(*dev).dma_mask } else { DEFAULT_DMA_MASK }
    }
}

fn dma_bit_mask(bits: u32) -> u64 {
    if bits >= DMA_ADDRESS_BITS { u64::MAX }
    else if bits == 0 { 0 }
    else { (1u64 << bits) - 1 }
}

fn sync_for_cpu(dir: i32) {
    if dir == DMA_FROM_DEVICE || dir == DMA_BIDIRECTIONAL { fence(Ordering::SeqCst); }
}

fn sync_for_device(dir: i32) {
    if dir == DMA_TO_DEVICE || dir == DMA_BIDIRECTIONAL {
        compiler_fence(Ordering::SeqCst);
        fence(Ordering::SeqCst);
    }
}
