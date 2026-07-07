// Linux scatterlist allocation helpers for DMA KPI.

use core::ptr::null_mut;

use crate::linux_alloc;
use crate::linux_dma::{self, ScatterList};

pub(crate) extern "C" fn sgl_alloc_order(
    len: u64,
    order: u32,
    _chainable: bool,
    gfp: u32,
    nent_p: *mut u32,
) -> *mut ScatterList {
    let seg_size = match linux_alloc::PAGE_SIZE.checked_shl(order) { Some(v) => v, None => return null_mut() };
    if len == 0 || seg_size == 0 { return null_mut(); }
    let nents_u64 = (len + seg_size as u64 - 1) / seg_size as u64;
    if nents_u64 > u32::MAX as u64 { return null_mut(); }
    let nents = nents_u64 as u32;
    let mut tbl = linux_dma::SgTable { sgl: null_mut(), nents: 0, orig_nents: 0 };
    if linux_dma::sg_alloc_table(&mut tbl, nents, gfp) != 0 { return null_mut(); }
    let mut remaining = len;
    for i in 0..nents as usize {
        let page = linux_alloc::alloc_pages(gfp, order);
        if page.is_null() {
            free_pages_in_entries(tbl.sgl, i, order);
            linux_dma::sg_free_table(&mut tbl);
            return null_mut();
        }
        let chunk = remaining.min(seg_size as u64) as u32;
        // SAFETY: tbl.sgl contains nents entries allocated by sg_alloc_table.
        unsafe { linux_dma::sg_set_page(tbl.sgl.add(i), page, chunk, 0); }
        remaining -= chunk as u64;
    }
    if !nent_p.is_null() {
        // SAFETY: optional out pointer is supplied by the caller.
        unsafe { *nent_p = nents; }
    }
    tbl.sgl
}

pub(crate) extern "C" fn sgl_free_n_order(sgl: *mut ScatterList, nents: i32, order: i32) {
    if sgl.is_null() || nents <= 0 || order < 0 { return; }
    free_pages_in_entries(sgl, nents as usize, order as u32);
    let mut tbl = linux_dma::SgTable { sgl, nents: nents as u32, orig_nents: nents as u32 };
    linux_dma::sg_free_table(&mut tbl);
}

fn free_pages_in_entries(sgl: *mut ScatterList, nents: usize, order: u32) {
    for i in 0..nents as usize {
        // SAFETY: caller supplies at least nents entries allocated by sgl_alloc_order.
        let ent = unsafe { &mut *sgl.add(i) };
        let page = ent.page_link & !linux_dma::SG_END;
        if page != 0 { linux_alloc::__free_pages(page as *mut linux_alloc::LinuxPage, order); }
        ent.page_link = 0; ent.offset = 0; ent.length = 0; ent.dma_address = linux_dma::DMA_MAPPING_ERROR; ent.dma_length = 0;
    }
}
