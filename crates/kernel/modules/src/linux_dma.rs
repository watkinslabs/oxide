// Linux DMA mapping KPI manifest: types owns ABI records/constants; coherent,
// streaming, scatterlist, and policy children own their Linux-shaped mapping domains;
// backend owns shared address/mask and synchronization helpers.

mod pool;
#[allow(unused_imports)]
pub(crate) use crate::linux_alloc;
#[allow(unused_imports)]
pub(crate) use alloc::alloc::{alloc_zeroed, dealloc};
#[allow(unused_imports)]
pub(crate) use core::alloc::Layout;
#[allow(unused_imports)]
pub(crate) use core::cmp::min;
#[allow(unused_imports)]
pub(crate) use core::ffi::c_void;
#[allow(unused_imports)]
pub(crate) use core::mem::{align_of, size_of};
#[allow(unused_imports)]
pub(crate) use core::ptr::{copy_nonoverlapping, null_mut, write_bytes};
#[allow(unused_imports)]
pub(crate) use core::sync::atomic::{compiler_fence, fence, Ordering};
#[path = "linux_dma_types.rs"] mod types;
#[path = "linux_dma_coherent.rs"] mod coherent;
#[path = "linux_dma_streaming.rs"] mod streaming;
#[path = "linux_dma_sg.rs"] mod sg;
#[path = "linux_dma_policy.rs"] mod policy;
#[path = "linux_dma_backend.rs"] mod backend;

pub(crate) use crate::linux_device::types::LinuxDevice;
pub(crate) use crate::linux_alloc::LinuxPage;
pub(crate) use types::*;
pub(crate) use coherent::{dma_alloc_attrs, dma_alloc_coherent, dma_free_attrs, dma_free_coherent, dma_get_sgtable_attrs};
pub(crate) use streaming::{
    dma_map_page, dma_map_page_attrs, dma_map_single, dma_map_phys, dma_map_resource,
    dma_unmap_page, dma_unmap_page_attrs, dma_unmap_phys, dma_unmap_resource, dma_unmap_single,
};
pub(crate) use sg::{
    dma_map_sg, dma_map_sg_attrs, dma_map_sgtable,
    dma_unmap_sg, dma_unmap_sg_attrs, sg_alloc_table, sg_copy_to_buffer, sg_free_table,
    sg_miter_next, sg_miter_start, sg_miter_stop, sg_next, sg_set_buf, sg_set_page,
};
pub(crate) use policy::{
    dma_get_merge_boundary, dma_get_required_mask, dma_max_mapping_size, dma_need_unmap,
    dma_opt_mapping_size, dma_pci_p2pdma_supported, dma_set_coherent_mask, dma_set_mask,
    dma_set_mask_and_coherent, dma_supported, dma_mapping_error, dma_sync_single_for_cpu,
    dma_sync_single_for_device, dma_sync_sg_for_cpu, dma_sync_sg_for_device, sg_init_one,
    sg_init_table,
};
pub(crate) use backend::{
    device_dma_mask, dma_bit_mask, fits_mask, map_for_device, map_sg_entry, order_for_size,
    page_range_valid, sg_cpu_ptr_len, sg_cpu_ptr_len_with_offset, sg_layout, sync_for_cpu,
    sync_for_device, unmap_for_device, valid_dir,
};

/// Register Linux DMA mapping KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("dma_alloc_coherent",        dma_alloc_coherent        as *const () as usize),
        ("dma_alloc_attrs",           dma_alloc_attrs           as *const () as usize),
        ("dmam_alloc_coherent",       crate::linux_dma_managed::dmam_alloc_coherent as *const () as usize),
        ("dmam_alloc_attrs",          crate::linux_dma_managed::dmam_alloc_attrs as *const () as usize),
        ("dma_free_coherent",         dma_free_coherent         as *const () as usize),
        ("dma_free_attrs",            dma_free_attrs            as *const () as usize),
        ("dmam_free_coherent",        crate::linux_dma_managed::dmam_free_coherent as *const () as usize),
        ("dma_map_single",            dma_map_single            as *const () as usize),
        ("dma_unmap_single",          dma_unmap_single          as *const () as usize),
        ("dma_map_page",              dma_map_page              as *const () as usize),
        ("dma_map_page_attrs",        dma_map_page_attrs        as *const () as usize),
        ("dma_unmap_page",            dma_unmap_page            as *const () as usize),
        ("dma_unmap_page_attrs",      dma_unmap_page_attrs      as *const () as usize),
        ("dma_map_phys",              dma_map_phys              as *const () as usize),
        ("dma_unmap_phys",            dma_unmap_phys            as *const () as usize),
        ("dma_map_resource",          dma_map_resource          as *const () as usize),
        ("dma_unmap_resource",        dma_unmap_resource        as *const () as usize),
        ("dma_map_sg",                dma_map_sg                as *const () as usize),
        ("dma_map_sg_attrs",          dma_map_sg_attrs          as *const () as usize),
        ("dma_map_sgtable",           dma_map_sgtable           as *const () as usize),
        ("dma_unmap_sg",              dma_unmap_sg              as *const () as usize),
        ("dma_unmap_sg_attrs",        dma_unmap_sg_attrs        as *const () as usize),
        ("dma_mapping_error",         dma_mapping_error         as *const () as usize),
        ("dma_sync_single_for_cpu",    dma_sync_single_for_cpu    as *const () as usize),
        ("dma_sync_single_for_device", dma_sync_single_for_device as *const () as usize),
        ("__dma_sync_single_for_cpu",  dma_sync_single_for_cpu    as *const () as usize),
        ("__dma_sync_single_for_device", dma_sync_single_for_device as *const () as usize),
        ("__dma_sync_sg_for_cpu",      dma_sync_sg_for_cpu        as *const () as usize),
        ("__dma_sync_sg_for_device",   dma_sync_sg_for_device     as *const () as usize),
        ("dma_set_mask",              dma_set_mask              as *const () as usize),
        ("dma_set_coherent_mask",     dma_set_coherent_mask     as *const () as usize),
        ("dma_set_mask_and_coherent", dma_set_mask_and_coherent as *const () as usize),
        ("dma_supported",             dma_supported             as *const () as usize),
        ("dma_get_required_mask",     dma_get_required_mask     as *const () as usize),
        ("dma_max_mapping_size",      dma_max_mapping_size      as *const () as usize),
        ("dma_opt_mapping_size",      dma_opt_mapping_size      as *const () as usize),
        ("dma_get_merge_boundary",    dma_get_merge_boundary    as *const () as usize),
        ("dma_need_unmap",            dma_need_unmap            as *const () as usize),
        ("dma_pci_p2pdma_supported",  dma_pci_p2pdma_supported  as *const () as usize),
        ("dma_get_sgtable_attrs",     dma_get_sgtable_attrs     as *const () as usize),
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
        ("dma_pool_create_node",       pool::dma_pool_create_node as *const () as usize),
        ("dma_pool_destroy",           pool::dma_pool_destroy as *const () as usize),
        ("dma_pool_alloc",             pool::dma_pool_alloc as *const () as usize),
        ("dma_pool_free",              pool::dma_pool_free as *const () as usize),
    ] {
        let gpl_only = matches!(name, "dma_map_phys" | "dma_unmap_phys" | "dma_map_sgtable" | "dma_max_mapping_size");
        export(name, addr, gpl_only);
    }
}

#[cfg(test)]
#[path = "linux_dma_tests.rs"]
mod tests;
