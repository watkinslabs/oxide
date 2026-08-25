use super::*;

pub(crate) extern "C" fn dma_mapping_error(_dev: *mut LinuxDevice, dma_addr: u64) -> i32 {
    if dma_addr == DMA_MAPPING_ERROR { -LINUX_ENOMEM } else { 0 }
}

pub(crate) extern "C" fn dma_sync_single_for_cpu(_dev: *mut LinuxDevice, _dma_addr: u64, size: usize, dir: i32) {
    if size != 0 && valid_dir(dir) { sync_for_cpu(dir); }
}

pub(crate) extern "C" fn dma_sync_single_for_device(_dev: *mut LinuxDevice, _dma_addr: u64, size: usize, dir: i32) {
    if size != 0 && valid_dir(dir) { sync_for_device(dir); }
}

pub(crate) extern "C" fn dma_sync_sg_for_cpu(_dev: *mut LinuxDevice, _sg: *mut ScatterList, nents: i32, dir: i32) {
    if nents > 0 && valid_dir(dir) { sync_for_cpu(dir); }
}

pub(crate) extern "C" fn dma_sync_sg_for_device(_dev: *mut LinuxDevice, _sg: *mut ScatterList, nents: i32, dir: i32) {
    if nents > 0 && valid_dir(dir) { sync_for_device(dir); }
}

pub(crate) extern "C" fn dma_set_mask(dev: *mut LinuxDevice, mask: u64) -> i32 {
    if dev.is_null() || mask == 0 { return -LINUX_EINVAL; }
    if dma_supported(dev, mask) == 0 { return -LINUX_EIO; }
    // SAFETY: dev follows the KPI struct device prefix from linux/device.h.
    unsafe {
        if (*dev).dma_mask.is_null() { return -LINUX_EIO; }
        *(*dev).dma_mask = mask;
    }
    crate::linux_pci::sync_dma_masks(dev, Some(mask), None);
    LINUX_OK
}

pub(crate) extern "C" fn dma_set_coherent_mask(dev: *mut LinuxDevice, mask: u64) -> i32 {
    if dev.is_null() || mask == 0 { return -LINUX_EINVAL; }
    if dma_supported(dev, mask) == 0 { return -LINUX_EIO; }
    // SAFETY: dev follows the KPI struct device prefix from linux/device.h.
    unsafe { (*dev).coherent_dma_mask = mask; }
    crate::linux_pci::sync_dma_masks(dev, None, Some(mask));
    LINUX_OK
}

pub(crate) extern "C" fn dma_set_mask_and_coherent(dev: *mut LinuxDevice, mask: u64) -> i32 {
    let r = dma_set_mask(dev, mask);
    if r != LINUX_OK { return r; }
    dma_set_coherent_mask(dev, mask)
}

pub(crate) extern "C" fn dma_supported(_dev: *mut LinuxDevice, mask: u64) -> i32 {
    if mask == 0 { 0 } else { 1 }
}

pub(crate) extern "C" fn dma_get_required_mask(_dev: *mut LinuxDevice) -> u64 {
    dma_bit_mask(DMA_ADDRESS_BITS)
}

/// Largest one-shot mapping supported by Oxide's current VT-d/AMD-Vi IOVA
/// aperture. This is the Linux `dma_max_mapping_size` query used to segment
/// large DRM and network transfers before submitting DMA.
pub(crate) extern "C" fn dma_max_mapping_size(_dev: *mut LinuxDevice) -> usize {
    MAX_DMA_MAPPING_BYTES
}

/// Return the preferred contiguous transfer size without exceeding this DMA backend's hard limit. # C: O(1)
pub(crate) extern "C" fn dma_opt_mapping_size(dev: *mut LinuxDevice) -> usize {
    dma_max_mapping_size(dev)
}

/// Return this backend's safe segment merge boundary; zero forbids implicit merging. # C: O(1)
pub(crate) extern "C" fn dma_get_merge_boundary(_dev: *mut LinuxDevice) -> usize { 0 }

/// Report whether a completed mapping must be torn down by the active DMA backend. # C: O(1)
pub(crate) extern "C" fn dma_need_unmap(dev: *mut LinuxDevice) -> bool {
    crate::linux_pci::bdf_for_device(dev).is_some()
}

/// Report whether this DMA owner can map PCI peer-resource memory. # C: O(1)
pub(crate) extern "C" fn dma_pci_p2pdma_supported(_dev: *mut LinuxDevice) -> bool {
    // IOMMU mappings currently own RAM pages only; no P2PDMA resource owner exists.
    false
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
