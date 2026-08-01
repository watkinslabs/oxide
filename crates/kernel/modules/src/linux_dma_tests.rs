use crate::linux_dma::*;
use crate::linux_alloc;
use core::ffi::c_void;
use core::ptr::null_mut;

const TEST_DMA_BUF_SIZE: usize = 32;

#[test]
fn coherent_alloc_returns_dma_address_and_zeroed_memory() {
    let _modules = crate::test_serial::claim();
    let mut dma = DMA_MAPPING_ERROR;
    let p = dma_alloc_coherent(null_mut(), linux_alloc::PAGE_SIZE, &mut dma, 0);
    assert!(!p.is_null());
    assert_ne!(dma, DMA_MAPPING_ERROR);
    // SAFETY: p is the PAGE_SIZE coherent buffer asserted non-null above, which dma_alloc_coherent
    // returns zeroed, so exactly PAGE_SIZE initialised bytes are readable before the free below.
    unsafe { assert_eq!(core::slice::from_raw_parts(p as *const u8, linux_alloc::PAGE_SIZE), &[0; linux_alloc::PAGE_SIZE]); }
    dma_free_coherent(null_mut(), linux_alloc::PAGE_SIZE, p, dma);
}

#[test]
fn streaming_map_checks_masks_and_directions() {
    let _modules = crate::test_serial::claim();
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
    let _modules = crate::test_serial::claim();
    let buf = [0u8; 16];
    let mut sg = [ScatterList { page_link: 0, offset: 0, length: 0, dma_address: 0, dma_length: 0 }; 2];
    // SAFETY: sg_init_table writes nents entries; `sg` is the two-element ScatterList stack array
    // declared on the previous line and sg.len() is exactly its length.
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
fn sg_table_and_miter_walk_real_bytes() {
    let _modules = crate::test_serial::claim();
    let mut tbl = SgTable { sgl: null_mut(), nents: 0, orig_nents: 0 };
    assert_eq!(sg_alloc_table(&mut tbl, 2, 0), 0);
    let mut a = [1u8, 2, 3, 4];
    let mut b = [5u8, 6, 7, 8];
    // SAFETY: sg_alloc_table returned 0 above, so tbl.sgl points at 2 initialised entries; index 1
    // is therefore in bounds, and a/b are live 4-byte stack arrays that outlive the sg_copy below.
    unsafe {
        sg_set_buf(tbl.sgl, a.as_mut_ptr() as *const c_void, a.len() as u32);
        sg_set_buf(tbl.sgl.add(1), b.as_mut_ptr() as *const c_void, b.len() as u32);
    }
    let mut out = [0u8; 8];
    assert_eq!(sg_copy_to_buffer(tbl.sgl, tbl.orig_nents, out.as_mut_ptr() as *mut c_void, out.len()), out.len());
    assert_eq!(out, [1, 2, 3, 4, 5, 6, 7, 8]);
    let mut m = SgMappingIter { page: null_mut(), addr: null_mut(), length: 0, consumed: 0, piter: SgPageIter { sg: null_mut(), sg_pgoffset: 0, nents: 0, pg_advance: 0 }, offset: 0, remaining: 0, flags: 0 };
    sg_miter_start(&mut m, tbl.sgl, tbl.orig_nents, SG_MITER_FROM_SG);
    assert_eq!(sg_miter_next(&mut m), true);
    assert_eq!(m.length, a.len());
    sg_miter_stop(&mut m);
    sg_free_table(&mut tbl);
    assert!(tbl.sgl.is_null());
}

#[test]
fn sgl_alloc_order_returns_owned_page_backed_entries() {
    let _modules = crate::test_serial::claim();
    let mut nents = 0u32;
    let sgl = crate::linux_dma_sgl::sgl_alloc_order((linux_alloc::PAGE_SIZE * 2) as u64, 0, false, 0, &mut nents);
    assert!(!sgl.is_null());
    assert_eq!(nents, 2);
    // SAFETY: sgl is the entry array sgl_alloc_order returned (asserted non-null) and it reported
    // nents == 2 for the PAGE_SIZE*2 request, so indexes 0 and 1 are initialised and in bounds
    // until sgl_free_n_order below.
    unsafe {
        assert!((*sgl).page_link != 0);
        assert!((*sgl.add(1)).page_link != 0);
    }
    crate::linux_dma_sgl::sgl_free_n_order(sgl, nents as i32, 0);
}

#[test]
fn export_symbols_registers_dma_surface() {
    let _modules = crate::test_serial::claim();
    export_symbols();
    for name in [
        "dma_alloc_coherent", "dma_free_coherent", "dma_map_single",
        "dma_unmap_single", "dma_map_page", "dma_map_sg", "dma_unmap_sg",
        "dma_mapping_error", "dma_set_mask", "dma_set_coherent_mask",
        "dma_set_mask_and_coherent", "sg_init_table", "sg_set_buf", "sg_set_page",
        "sg_alloc_table", "sg_free_table", "sg_copy_to_buffer", "sg_miter_start",
        "sg_miter_next", "sg_miter_stop", "sgl_alloc_order", "sgl_free_n_order",
    ] {
        assert!(crate::symtab::is_exported(name));
    }
}
