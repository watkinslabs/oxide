// Module manifest: types owns allocator state; frontend owns exported KPIs;
// pages owns LinuxPage lifecycle; bytes owns raw allocation and formatting.

extern crate alloc;

#[path = "linux_alloc_cache.rs"]
pub(crate) mod cache;
#[path = "linux_alloc_vmap.rs"]
mod vmap;
#[path = "linux_alloc_vmalloc.rs"]
mod vmalloc;
#[path = "linux_alloc_types.rs"]
mod types;
#[path = "linux_alloc_frontend.rs"]
mod frontend;
#[path = "linux_alloc_pages.rs"]
mod pages;
#[path = "linux_alloc_bytes.rs"]
mod bytes;

pub(crate) use bytes::{alloc_bytes, free_bytes};
#[allow(unused_imports)]
pub(crate) use pages::{
    __alloc_pages_noprof, __free_pages, __get_free_pages, alloc_pages, alloc_pages_noprof,
    direct_pa_for_va, free_pages, get_free_pages, linux_page_phys, page_address, page_put,
    page_ref_count, page_run_alloc, page_run_free_pa, page_run_free_va, page_run_len, page_to_phys,
};
#[allow(unused_imports)]
pub(crate) use pages::c_strlen;
#[allow(unused_imports)]
#[cfg(any(test, feature = "hosted"))]
pub(crate) use pages::page_get;
pub use types::{LinuxKmemCache, LinuxPage};
pub(crate) use types::{
    CACHE_MAGIC, GFP_ZERO, KMALLOC_CACHES, MIN_ALIGN, PAGE_SIZE, PAGE_OFFSET_BASE,
    RANDOM_KMALLOC_SEED, VMEMMAP_BASE,
};
#[cfg(test)]
pub(crate) use core::ffi::c_void;
pub use frontend::export_symbols;
#[allow(unused_imports)]
pub(crate) use frontend::{
    __kmalloc_cache_node_noprof, __kmalloc_cache_noprof, __kmalloc_large_noprof,
    __kmalloc_node_noprof, __kmalloc_noprof, __kvmalloc_node_noprof, kcalloc, kfree, kfree_sensitive,
    kmalloc, kmemdup_noprof, kstrdup, kstrndup, kasprintf, kzalloc, kvfree, kvfree_call_rcu,
    vfree, vmalloc, vzalloc_noprof, __vmalloc_noprof,
};

pub use vmalloc::{snapshot as vmalloc_snapshot, Snapshot as VmallocSnapshot};

pub(crate) fn vmalloc_alloc(size: usize, zero: bool) -> *mut u8 { vmalloc::alloc(size, zero) }
pub(crate) fn vmalloc_free(base: *mut u8) -> bool { vmalloc::free(base) }
pub(crate) fn vmalloc_page_pa(base: *const u8, off: usize) -> Option<u64> { vmalloc::page_pa(base, off) }

#[cfg(test)]
#[path = "linux_alloc_tests.rs"]
mod tests;
