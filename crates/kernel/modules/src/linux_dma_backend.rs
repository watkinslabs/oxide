use super::*;
pub(crate) fn map_sg_entry(dev: *mut LinuxDevice, ent: &ScatterList, dir: i32, attrs: u64) -> u64 {
    if ent.length == 0 { return DMA_MAPPING_ERROR; }
    let page = ent.page_link & !SG_END;
    let pa = if page != 0 {
        // SAFETY: a nonzero scatterlist page link names a live struct page descriptor for the map operation.
        let page = page as *mut LinuxPage;
        // SAFETY: per the Linux DMA scatterlist contract, a nonzero page_link names a struct page the caller obtained from the page allocator (alloc_pages/kmalloc's backing pages), the same trust boundary every other page-taking KPI in this module relies on; linux_page_phys's valid_page check rejects a foreign magic before reading further fields.
        let base = match unsafe { linux_alloc::linux_page_phys(page) } { Some(v) => v, None => return DMA_MAPPING_ERROR };
        if !page_range_valid(page, ent.offset as usize, ent.length as usize) { return DMA_MAPPING_ERROR; }
        match base.checked_add(ent.offset as u64) { Some(v) => v, None => return DMA_MAPPING_ERROR }
    } else {
        match linux_alloc::direct_pa_for_va(ent.dma_address as *const u8) { Some(v) => v, None => return DMA_MAPPING_ERROR }
    };
    let Some(dma) = map_for_device(dev, pa, ent.length as usize, device_dma_mask(dev, false)) else { return DMA_MAPPING_ERROR; };
    if !fits_mask(dma, ent.length as usize, device_dma_mask(dev, false)) {
        unmap_for_device(dev, dma, ent.length as usize);
        return DMA_MAPPING_ERROR;
    }
    if attrs & DMA_ATTR_SKIP_CPU_SYNC == 0 { sync_for_device(dir); }
    dma
}

/// Validate that an external `struct page` owns the whole byte interval a DMA
/// request wants to expose. Compound allocations are valid; crossing the end
/// of their recorded run is not. # C: O(1)
pub(crate) fn page_range_valid(page: *mut LinuxPage, offset: usize, len: usize) -> bool {
    let Some(run) = linux_alloc::page_run_len(page) else { return false; };
    offset.checked_add(len).is_some_and(|end| end <= run)
}

pub(crate) fn map_for_device(dev: *mut LinuxDevice, pa: u64, len: usize, mask: u64) -> Option<u64> {
    match crate::linux_pci::bdf_for_device(dev) {
        Some(bdf) => iommu::map_dma_below(bdf, pa, len, mask),
        None => fits_mask(pa, len, mask).then_some(pa),
    }
}

pub(crate) fn unmap_for_device(dev: *mut LinuxDevice, dma: u64, len: usize) -> bool {
    match crate::linux_pci::bdf_for_device(dev) {
        Some(bdf) => iommu::unmap_dma(bdf, dma, len),
        None => true,
    }
}

pub(crate) fn sg_layout(nents: u32) -> Option<Layout> {
    Layout::from_size_align(size_of::<ScatterList>().checked_mul(nents as usize)?, align_of::<ScatterList>()).ok()
}

pub(crate) fn sg_cpu_ptr_len(sg: *mut ScatterList) -> Option<(*const u8, usize)> {
    sg_cpu_ptr_len_with_offset(sg, 0)
}

pub(crate) fn sg_cpu_ptr_len_with_offset(sg: *mut ScatterList, extra: usize) -> Option<(*const u8, usize)> {
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

pub(crate) fn order_for_size(size: usize) -> Option<u32> {
    let pages = size.checked_add(linux_alloc::PAGE_SIZE - 1)? / linux_alloc::PAGE_SIZE;
    let mut order = 0u32;
    let mut capacity = 1usize;
    while capacity < pages {
        capacity = capacity.checked_shl(1)?;
        order += 1;
    }
    Some(order)
}

pub(crate) fn fits_mask(addr: u64, size: usize, mask: u64) -> bool {
    if size == 0 || mask == 0 { return false; }
    let end = match addr.checked_add(size as u64 - 1) { Some(v) => v, None => return false };
    end <= mask
}

pub(crate) fn valid_dir(dir: i32) -> bool {
    matches!(dir, DMA_NONE | DMA_TO_DEVICE | DMA_FROM_DEVICE | DMA_BIDIRECTIONAL)
}

pub(crate) fn device_dma_mask(dev: *mut LinuxDevice, coherent: bool) -> u64 {
    if dev.is_null() { return DEFAULT_DMA_MASK; }
    // SAFETY: dev follows the KPI struct device prefix from linux/device.h.
    unsafe {
        if coherent && (*dev).coherent_dma_mask != 0 { return (*dev).coherent_dma_mask; }
        if !(*dev).dma_mask.is_null() { *(*dev).dma_mask } else { DEFAULT_DMA_MASK }
    }
}

pub(crate) fn dma_bit_mask(bits: u32) -> u64 {
    if bits >= DMA_ADDRESS_BITS { u64::MAX }
    else if bits == 0 { 0 }
    else { (1u64 << bits) - 1 }
}

pub(crate) fn sync_for_cpu(dir: i32) {
    if dir == DMA_FROM_DEVICE || dir == DMA_BIDIRECTIONAL { fence(Ordering::SeqCst); }
}

pub(crate) fn sync_for_device(dir: i32) {
    if dir == DMA_TO_DEVICE || dir == DMA_BIDIRECTIONAL {
        compiler_fence(Ordering::SeqCst);
        fence(Ordering::SeqCst);
    }
}
