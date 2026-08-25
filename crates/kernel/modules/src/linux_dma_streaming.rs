use super::*;
pub(crate) extern "C" fn dma_map_single(dev: *mut LinuxDevice, ptr: *mut c_void, size: usize, dir: i32) -> u64 {
    if ptr.is_null() || size == 0 || !valid_dir(dir) { return DMA_MAPPING_ERROR; }
    let pa = match linux_alloc::direct_pa_for_va(ptr as *const u8) { Some(v) => v, None => return DMA_MAPPING_ERROR };
    let Some(dma) = map_for_device(dev, pa, size, device_dma_mask(dev, false)) else { return DMA_MAPPING_ERROR; };
    if !fits_mask(dma, size, device_dma_mask(dev, false)) { unmap_for_device(dev, dma, size); return DMA_MAPPING_ERROR; }
    sync_for_device(dir);
    dma
}

pub(crate) extern "C" fn dma_unmap_single(dev: *mut LinuxDevice, dma_addr: u64, size: usize, dir: i32) {
    if dma_addr == DMA_MAPPING_ERROR || size == 0 || !valid_dir(dir) { return; }
    if !unmap_for_device(dev, dma_addr, size) { return; }
    sync_for_cpu(dir);
}

pub(crate) extern "C" fn dma_map_page(dev: *mut LinuxDevice, page: *mut LinuxPage, offset: usize, size: usize, dir: i32) -> u64 {
    dma_map_page_attrs(dev, page, offset, size, dir, 0)
}

pub(crate) extern "C" fn dma_map_page_attrs(dev: *mut LinuxDevice, page: *mut LinuxPage, offset: usize, size: usize, dir: i32, attrs: u64) -> u64 {
    if size == 0 || !valid_dir(dir) { return DMA_MAPPING_ERROR; }
    // SAFETY: dma_map_page's KPI requires page to be a live descriptor while the mapping is installed.
    let base = match unsafe { linux_alloc::linux_page_phys(page) } { Some(v) => v, None => return DMA_MAPPING_ERROR };
    if !page_range_valid(page, offset, size) { return DMA_MAPPING_ERROR; }
    let pa = match base.checked_add(offset as u64) { Some(v) => v, None => return DMA_MAPPING_ERROR };
    let Some(dma) = map_for_device(dev, pa, size, device_dma_mask(dev, false)) else { return DMA_MAPPING_ERROR; };
    if !fits_mask(dma, size, device_dma_mask(dev, false)) { unmap_for_device(dev, dma, size); return DMA_MAPPING_ERROR; }
    if attrs & DMA_ATTR_SKIP_CPU_SYNC == 0 { sync_for_device(dir); }
    dma
}

pub(crate) extern "C" fn dma_unmap_page(dev: *mut LinuxDevice, dma_addr: u64, size: usize, dir: i32) {
    dma_unmap_page_attrs(dev, dma_addr, size, dir, 0);
}

pub(crate) extern "C" fn dma_unmap_page_attrs(dev: *mut LinuxDevice, dma_addr: u64, size: usize, dir: i32, attrs: u64) {
    if dma_addr == DMA_MAPPING_ERROR || size == 0 || !valid_dir(dir) { return; }
    if !unmap_for_device(dev, dma_addr, size) { return; }
    if attrs & DMA_ATTR_SKIP_CPU_SYNC == 0 { sync_for_cpu(dir); }
}

/// Map a caller-owned physical range through the device's DMA translation.
/// This is the Linux `dma_map_phys` KPI: unlike `dma_map_page`, it deliberately
/// accepts a physical range not represented by a `struct page`.
pub(crate) extern "C" fn dma_map_phys(dev: *mut LinuxDevice, phys: u64, size: usize,
    dir: i32, attrs: u64) -> u64 {
    if size == 0 || !valid_dir(dir) || phys.checked_add(size as u64 - 1).is_none() {
        return DMA_MAPPING_ERROR;
    }
    let Some(dma) = map_for_device(dev, phys, size, device_dma_mask(dev, false)) else {
        return DMA_MAPPING_ERROR;
    };
    if !fits_mask(dma, size, device_dma_mask(dev, false)) {
        let _ = unmap_for_device(dev, dma, size);
        return DMA_MAPPING_ERROR;
    }
    if attrs & DMA_ATTR_SKIP_CPU_SYNC == 0 { sync_for_device(dir); }
    dma
}

pub(crate) extern "C" fn dma_unmap_phys(dev: *mut LinuxDevice, dma_addr: u64,
    size: usize, dir: i32, attrs: u64) {
    if dma_addr == DMA_MAPPING_ERROR || size == 0 || !valid_dir(dir) { return; }
    if !unmap_for_device(dev, dma_addr, size) { return; }
    if attrs & DMA_ATTR_SKIP_CPU_SYNC == 0 { sync_for_cpu(dir); }
}

/// Map a DMA-able device resource. Linux routes this through `dma_map_phys`
/// with the MMIO attribute; MMIO never receives CPU-cache synchronization.
pub(crate) extern "C" fn dma_map_resource(dev: *mut LinuxDevice, phys: u64,
    size: usize, dir: i32, attrs: u64) -> u64 {
    dma_map_phys(dev, phys, size, dir, attrs | DMA_ATTR_SKIP_CPU_SYNC)
}

pub(crate) extern "C" fn dma_unmap_resource(dev: *mut LinuxDevice, dma_addr: u64,
    size: usize, dir: i32, attrs: u64) {
    dma_unmap_phys(dev, dma_addr, size, dir, attrs | DMA_ATTR_SKIP_CPU_SYNC);
}

