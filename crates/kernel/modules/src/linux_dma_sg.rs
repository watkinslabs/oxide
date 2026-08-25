use super::*;
pub(crate) extern "C" fn dma_map_sg(dev: *mut LinuxDevice, sg: *mut ScatterList, nents: i32, dir: i32) -> i32 {
    dma_map_sg_attrs(dev, sg, nents, dir, 0)
}

pub(crate) extern "C" fn dma_map_sg_attrs(dev: *mut LinuxDevice, sg: *mut ScatterList, nents: i32, dir: i32, attrs: u64) -> i32 {
    if sg.is_null() || nents <= 0 || !valid_dir(dir) { return 0; }
    let mut mapped = 0i32;
    for i in 0..nents as usize {
        // SAFETY: caller supplied an array containing nents scatterlist entries.
        let ent = unsafe { &mut *sg.add(i) };
        let dma = map_sg_entry(dev, ent, dir, attrs);
        if dma == DMA_MAPPING_ERROR {
            dma_unmap_sg_attrs(dev, sg, mapped, dir, attrs);
            return 0;
        }
        ent.dma_address = dma;
        ent.dma_length = ent.length;
        mapped += 1;
    }
    mapped
}

/// Linux's `dma_map_sgtable` wrapper maps the original entry count and then
/// publishes the hardware-visible count in `sgt->nents`. `dma_unmap_sgtable`
/// is inline in Linux headers and reaches the existing `dma_unmap_sg_attrs`.
pub(crate) extern "C" fn dma_map_sgtable(dev: *mut LinuxDevice, table: *mut SgTable,
    dir: i32, attrs: u64) -> i32 {
    if table.is_null() { return -LINUX_EINVAL; }
    // SAFETY: the Linux KPI requires a live `struct sg_table` for this call.
    let table = unsafe { &mut *table };
    if table.sgl.is_null() || table.orig_nents == 0 || table.orig_nents > i32::MAX as u32 {
        return -LINUX_EINVAL;
    }
    let mapped = dma_map_sg_attrs(dev, table.sgl, table.orig_nents as i32, dir, attrs);
    if mapped == 0 { return -LINUX_ENOMEM; }
    table.nents = mapped as u32;
    LINUX_OK
}

pub(crate) extern "C" fn dma_unmap_sg(_dev: *mut LinuxDevice, sg: *mut ScatterList, nents: i32, dir: i32) {
    dma_unmap_sg_attrs(_dev, sg, nents, dir, 0);
}

pub(crate) extern "C" fn dma_unmap_sg_attrs(dev: *mut LinuxDevice, sg: *mut ScatterList, nents: i32, dir: i32, attrs: u64) {
    if sg.is_null() || nents <= 0 || !valid_dir(dir) { return; }
    if attrs & DMA_ATTR_SKIP_CPU_SYNC == 0 { sync_for_cpu(dir); }
    for i in 0..nents as usize {
        // SAFETY: caller supplied an array containing nents scatterlist entries.
        let ent = unsafe { &mut *sg.add(i) };
        let _ = unmap_for_device(dev, ent.dma_address, ent.dma_length as usize);
        ent.dma_address = DMA_MAPPING_ERROR;
        ent.dma_length = 0;
    }
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
