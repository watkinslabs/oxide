// Linux DMA mapping KPI exports for loadable drivers.

use core::ffi::c_void;
use core::ptr::{null_mut, write_bytes};
use core::sync::atomic::{compiler_fence, fence, Ordering};

use crate::linux_alloc::{self, LinuxPage};

const DMA_MAPPING_ERROR: u64 = 0;
const LINUX_OK: i32 = 0;
const LINUX_EIO: i32 = 5;
const LINUX_EINVAL: i32 = 22;
const DMA_NONE: i32 = 0;
const DMA_TO_DEVICE: i32 = 1;
const DMA_FROM_DEVICE: i32 = 2;
const DMA_BIDIRECTIONAL: i32 = 3;
const DEFAULT_DMA_MASK: u64 = u64::MAX;
const DMA_ADDRESS_BITS: u32 = u64::BITS;
#[cfg(test)]
const TEST_DMA_BUF_SIZE: usize = 32;

#[repr(C)]
pub struct LinuxDevice {
    dma_mask: *mut u64,
    coherent_dma_mask: u64,
    driver_data: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ScatterList {
    page_link: usize,
    offset: u32,
    length: u32,
    dma_address: u64,
    dma_length: u32,
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
    ] { export(name, addr, false); }
}

extern "C" fn dma_alloc_coherent(dev: *mut LinuxDevice, size: usize, dma_handle: *mut u64, flags: u64) -> *mut c_void {
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

extern "C" fn dma_free_coherent(_dev: *mut LinuxDevice, size: usize, cpu_addr: *mut c_void, dma_handle: u64) {
    if size == 0 || cpu_addr.is_null() || dma_handle == DMA_MAPPING_ERROR { return; }
    if let Some(order) = order_for_size(size) { linux_alloc::page_run_free_pa(dma_handle, order); }
}

extern "C" fn dma_map_single(dev: *mut LinuxDevice, ptr: *mut c_void, size: usize, dir: i32) -> u64 {
    if ptr.is_null() || size == 0 || !valid_dir(dir) { return DMA_MAPPING_ERROR; }
    let pa = match linux_alloc::direct_pa_for_va(ptr as *const u8) { Some(v) => v, None => return DMA_MAPPING_ERROR };
    if !fits_mask(pa, size, device_dma_mask(dev, false)) { return DMA_MAPPING_ERROR; }
    sync_for_device(dir);
    pa
}

extern "C" fn dma_unmap_single(_dev: *mut LinuxDevice, dma_addr: u64, size: usize, dir: i32) {
    if dma_addr == DMA_MAPPING_ERROR || size == 0 || !valid_dir(dir) { return; }
    sync_for_cpu(dir);
}

extern "C" fn dma_map_page(dev: *mut LinuxDevice, page: *mut LinuxPage, offset: usize, size: usize, dir: i32) -> u64 {
    if size == 0 || !valid_dir(dir) { return DMA_MAPPING_ERROR; }
    let base = match linux_alloc::linux_page_phys(page) { Some(v) => v, None => return DMA_MAPPING_ERROR };
    let pa = match base.checked_add(offset as u64) { Some(v) => v, None => return DMA_MAPPING_ERROR };
    if !fits_mask(pa, size, device_dma_mask(dev, false)) { return DMA_MAPPING_ERROR; }
    sync_for_device(dir);
    pa
}

extern "C" fn dma_unmap_page(dev: *mut LinuxDevice, dma_addr: u64, size: usize, dir: i32) {
    dma_unmap_single(dev, dma_addr, size, dir);
}

extern "C" fn dma_map_sg(dev: *mut LinuxDevice, sg: *mut ScatterList, nents: i32, dir: i32) -> i32 {
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

extern "C" fn dma_unmap_sg(_dev: *mut LinuxDevice, sg: *mut ScatterList, nents: i32, dir: i32) {
    if sg.is_null() || nents <= 0 || !valid_dir(dir) { return; }
    sync_for_cpu(dir);
    for i in 0..nents as usize {
        // SAFETY: caller supplied an array containing nents scatterlist entries.
        let ent = unsafe { &mut *sg.add(i) };
        ent.dma_address = DMA_MAPPING_ERROR;
        ent.dma_length = 0;
    }
}

extern "C" fn dma_mapping_error(_dev: *mut LinuxDevice, dma_addr: u64) -> i32 {
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

unsafe extern "C" fn sg_init_table(sg: *mut ScatterList, nents: u32) {
    if sg.is_null() { return; }
    // SAFETY: caller supplied an array containing nents scatterlist entries.
    unsafe { write_bytes(sg, 0, nents as usize); }
}

unsafe extern "C" fn sg_init_one(sg: *mut ScatterList, buf: *const c_void, buflen: u32) {
    // SAFETY: sg is the single entry supplied by the caller.
    unsafe { sg_init_table(sg, 1); }
    sg_set_buf(sg, buf, buflen);
}

extern "C" fn sg_set_buf(sg: *mut ScatterList, buf: *const c_void, buflen: u32) {
    if sg.is_null() { return; }
    // SAFETY: sg points at a caller-owned scatterlist entry.
    unsafe {
        (*sg).page_link = 0;
        (*sg).offset = 0;
        (*sg).length = buflen;
        (*sg).dma_address = buf as u64;
        (*sg).dma_length = 0;
    }
}

extern "C" fn sg_set_page(sg: *mut ScatterList, page: *mut LinuxPage, len: u32, offset: u32) {
    if sg.is_null() { return; }
    // SAFETY: sg points at a caller-owned scatterlist entry.
    unsafe {
        (*sg).page_link = page as usize;
        (*sg).offset = offset;
        (*sg).length = len;
        (*sg).dma_address = DMA_MAPPING_ERROR;
        (*sg).dma_length = 0;
    }
}

extern "C" fn sg_next(sg: *mut ScatterList) -> *mut ScatterList {
    if sg.is_null() { null_mut() } else {
        // SAFETY: Linux sg_next advances within a caller-managed scatterlist chain.
        unsafe { sg.add(1) }
    }
}

fn map_sg_entry(dev: *mut LinuxDevice, ent: &ScatterList, dir: i32) -> u64 {
    if ent.length == 0 { return DMA_MAPPING_ERROR; }
    let pa = if ent.page_link != 0 {
        let base = match linux_alloc::linux_page_phys(ent.page_link as *const LinuxPage) { Some(v) => v, None => return DMA_MAPPING_ERROR };
        match base.checked_add(ent.offset as u64) { Some(v) => v, None => return DMA_MAPPING_ERROR }
    } else {
        match linux_alloc::direct_pa_for_va(ent.dma_address as *const u8) { Some(v) => v, None => return DMA_MAPPING_ERROR }
    };
    if !fits_mask(pa, ent.length as usize, device_dma_mask(dev, false)) { return DMA_MAPPING_ERROR; }
    sync_for_device(dir);
    pa
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coherent_alloc_returns_dma_address_and_zeroed_memory() {
        let mut dma = DMA_MAPPING_ERROR;
        let p = dma_alloc_coherent(null_mut(), linux_alloc::PAGE_SIZE, &mut dma, 0);
        assert!(!p.is_null());
        assert_ne!(dma, DMA_MAPPING_ERROR);
        unsafe { assert_eq!(core::slice::from_raw_parts(p as *const u8, linux_alloc::PAGE_SIZE), &[0; linux_alloc::PAGE_SIZE]); }
        dma_free_coherent(null_mut(), linux_alloc::PAGE_SIZE, p, dma);
    }

    #[test]
    fn streaming_map_checks_masks_and_directions() {
        let mut buf = [0u8; TEST_DMA_BUF_SIZE];
        let mut mask = DEFAULT_DMA_MASK;
        let mut dev = LinuxDevice { dma_mask: &mut mask, coherent_dma_mask: DEFAULT_DMA_MASK, driver_data: null_mut() };
        let dma = dma_map_single(&mut dev, buf.as_mut_ptr() as *mut c_void, buf.len(), DMA_TO_DEVICE);
        assert_eq!(dma_mapping_error(&mut dev, dma), 0);
        dma_unmap_single(&mut dev, dma, buf.len(), DMA_TO_DEVICE);
        mask = dma - 1;
        assert_eq!(mask, dma - 1);
        assert_eq!(dma_map_single(&mut dev, buf.as_mut_ptr() as *mut c_void, buf.len(), DMA_TO_DEVICE), DMA_MAPPING_ERROR);
        assert_eq!(dma_map_single(&mut dev, buf.as_mut_ptr() as *mut c_void, buf.len(), LINUX_EINVAL), DMA_MAPPING_ERROR);
    }

    #[test]
    fn scatterlist_maps_buffer_and_page_entries() {
        let buf = [0u8; 16];
        let mut sg = [ScatterList { page_link: 0, offset: 0, length: 0, dma_address: 0, dma_length: 0 }; 2];
        unsafe { sg_init_table(sg.as_mut_ptr(), sg.len() as u32); }
        sg_set_buf(&mut sg[0], buf.as_ptr() as *const c_void, buf.len() as u32);
        let page = crate::linux_alloc::alloc_pages(0, 0);
        sg_set_page(&mut sg[1], page, linux_alloc::PAGE_SIZE as u32, 0);
        assert_eq!(dma_map_sg(null_mut(), sg.as_mut_ptr(), sg.len() as i32, DMA_BIDIRECTIONAL), sg.len() as i32);
        assert_ne!(sg[0].dma_address, DMA_MAPPING_ERROR);
        assert_ne!(sg[1].dma_address, DMA_MAPPING_ERROR);
        dma_unmap_sg(null_mut(), sg.as_mut_ptr(), sg.len() as i32, DMA_BIDIRECTIONAL);
        crate::linux_alloc::__free_pages(page, 0);
    }

    #[test]
    fn export_symbols_registers_dma_surface() {
        crate::symtab::_reset();
        export_symbols();
        for name in [
            "dma_alloc_coherent", "dma_free_coherent", "dma_map_single",
            "dma_unmap_single", "dma_map_page", "dma_map_sg", "dma_unmap_sg",
            "dma_mapping_error", "dma_set_mask", "dma_set_coherent_mask",
            "dma_set_mask_and_coherent", "sg_init_table", "sg_set_buf", "sg_set_page",
        ] {
            assert!(crate::symtab::is_exported(name));
        }
    }
}
