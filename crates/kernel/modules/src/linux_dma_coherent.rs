use super::*;
pub(crate) extern "C" fn dma_alloc_coherent(dev: *mut LinuxDevice, size: usize, dma_handle: *mut u64, flags: u64) -> *mut c_void {
    dma_alloc_attrs(dev, size, dma_handle, flags, 0)
}

pub(crate) extern "C" fn dma_alloc_attrs(dev: *mut LinuxDevice, size: usize, dma_handle: *mut u64, flags: u64, attrs: u64) -> *mut c_void {
    let _ = flags;
    if attrs & DMA_ATTR_NO_KERNEL_MAPPING != 0 { return null_mut(); }
    if size == 0 || dma_handle.is_null() { return null_mut(); }
    let order = match order_for_size(size) { Some(v) => v, None => return null_mut() };
    let (pa, va) = match linux_alloc::page_run_alloc(order, true) { Some(v) => v, None => return null_mut() };
    let dma = match map_for_device(dev, pa, size, device_dma_mask(dev, true)) { Some(value) => value, None => {
        linux_alloc::page_run_free_pa(pa, order);
        return null_mut();
    } };
    if !fits_mask(dma, size, device_dma_mask(dev, true)) {
        unmap_for_device(dev, dma, size);
        linux_alloc::page_run_free_pa(pa, order);
        return null_mut();
    }
    // SAFETY: dma_handle is a non-null out pointer supplied by the caller.
    unsafe { *dma_handle = dma; }
    va as *mut c_void
}

pub(crate) extern "C" fn dma_free_coherent(_dev: *mut LinuxDevice, size: usize, cpu_addr: *mut c_void, dma_handle: u64) {
    dma_free_attrs(_dev, size, cpu_addr, dma_handle, 0);
}

pub(crate) extern "C" fn dma_free_attrs(dev: *mut LinuxDevice, size: usize, cpu_addr: *mut c_void, dma_handle: u64, _attrs: u64) {
    if size == 0 || cpu_addr.is_null() || dma_handle == DMA_MAPPING_ERROR { return; }
    let Some(pa) = linux_alloc::direct_pa_for_va(cpu_addr as *const u8) else { return; };
    if !unmap_for_device(dev, dma_handle, size) { return; }
    if let Some(order) = order_for_size(size) { linux_alloc::page_run_free_pa(pa, order); }
}

/// Describe a coherent DMA allocation for export without sending it back
/// through the streaming map path. Linux's coherent SG-table API preserves the
/// allocation's existing device address for exactly this reason.
pub(crate) extern "C" fn dma_get_sgtable_attrs(_dev: *mut LinuxDevice, table: *mut SgTable,
    cpu_addr: *mut c_void, dma_addr: u64, size: usize, _attrs: u64) -> i32 {
    if table.is_null() || cpu_addr.is_null() || size == 0 || size > u32::MAX as usize || dma_addr == DMA_MAPPING_ERROR
        || linux_alloc::direct_pa_for_va(cpu_addr as *const u8).and_then(|pa| pa.checked_add(size as u64 - 1)).is_none() {
        return -LINUX_EINVAL;
    }
    if sg_alloc_table(table, 1, 0) != LINUX_OK { return -LINUX_ENOMEM; }
    // SAFETY: sg_alloc_table initialized one owned entry in `table` above.
    unsafe {
        sg_set_buf((*table).sgl, cpu_addr, size as u32);
        (*(*table).sgl).dma_address = dma_addr;
        (*(*table).sgl).dma_length = size as u32;
    }
    LINUX_OK
}

