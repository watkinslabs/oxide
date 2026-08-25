use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::{size_of};
use core::ptr::{copy_nonoverlapping, null_mut, write_bytes};
use core::sync::atomic::AtomicUsize;
#[cfg(target_os = "oxide-kernel")]
use core::sync::atomic::Ordering;

use super::{alloc_bytes, free_bytes, cache, vmap, vmalloc as vmalloc_backend, GFP_ZERO,
    KMALLOC_CACHES, MIN_ALIGN, PAGE_OFFSET_BASE, PAGE_SIZE, RANDOM_KMALLOC_SEED,
    VMEMMAP_BASE, LinuxKmemCache};
use super::bytes::format_c;
use super::pages::{
    __alloc_pages_noprof, __free_pages, __get_free_pages, alloc_pages, alloc_pages_noprof,
    c_strlen, free_pages, get_free_pages, page_address, page_to_phys,
};
use super::types::{ALLOC_MAGIC, Header};
/// Register Linux allocation KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    #[cfg(target_os = "oxide-kernel")]
    {
        PAGE_OFFSET_BASE.store(pmm::setup::direct_map_base() as usize, Ordering::Release);
        VMEMMAP_BASE.store(pmm::setup::native_page_base() as usize, Ordering::Release);
    }
    export("kmalloc",          kmalloc          as *const () as usize, false);
    export("kzalloc",          kzalloc          as *const () as usize, false);
    export("kcalloc",          kcalloc          as *const () as usize, false);
    export("kfree",            kfree            as *const () as usize, false);
    export("kvfree",           kvfree           as *const () as usize, false);
    export("kvfree_call_rcu",   kvfree_call_rcu  as *const () as usize, true);
    export("vmalloc",          vmalloc          as *const () as usize, false);
    export("is_vmalloc_addr",  is_vmalloc_addr  as *const () as usize, false);
    export("vfree",            vfree            as *const () as usize, false);
    export("vmap",             vmap::vmap       as *const () as usize, false);
    export("vunmap",           vmap::vunmap     as *const () as usize, false);
    export("alloc_pages",      alloc_pages      as *const () as usize, false);
    export("alloc_pages_noprof", alloc_pages_noprof as *const () as usize, false);
    export("__alloc_pages_noprof", __alloc_pages_noprof as *const () as usize, false);
    export("__free_pages",     __free_pages     as *const () as usize, false);
    export("__get_free_pages", __get_free_pages as *const () as usize, false);
    export("get_free_pages",   get_free_pages   as *const () as usize, false);
    export("free_pages",       free_pages       as *const () as usize, false);
    export("page_address",     page_address     as *const () as usize, false);
    export("page_to_phys",     page_to_phys     as *const () as usize, false);
    export("kstrdup",          kstrdup          as *const () as usize, false);
    export("kstrndup",         kstrndup         as *const () as usize, false);
    export("kasprintf",        kasprintf        as *const () as usize, false);
    export("kmemdup_noprof",   kmemdup_noprof   as *const () as usize, false);
    export("__kmalloc_noprof", __kmalloc_noprof as *const () as usize, false);
    export("__kmalloc_large_noprof", __kmalloc_large_noprof as *const () as usize, false);
    export("__kmalloc_node_noprof", __kmalloc_node_noprof as *const () as usize, false);
    export("__kmalloc_cache_noprof", __kmalloc_cache_noprof as *const () as usize, false);
    export("__kmalloc_cache_node_noprof", __kmalloc_cache_node_noprof as *const () as usize, false);
    export("__kvmalloc_node_noprof", __kvmalloc_node_noprof as *const () as usize, false);
    export("__kmem_cache_create_args", cache::__kmem_cache_create_args as *const () as usize, false);
    export("kmem_cache_alloc_noprof", cache::kmem_cache_alloc_noprof as *const () as usize, false);
    export("kmem_cache_free", cache::kmem_cache_free as *const () as usize, false);
    export("kmem_cache_destroy", cache::kmem_cache_destroy as *const () as usize, false);
    export("vzalloc_noprof",   vzalloc_noprof   as *const () as usize, false);
    export("__vmalloc_noprof", __vmalloc_noprof as *const () as usize, false);
    export("kfree_sensitive",  kfree_sensitive  as *const () as usize, false);
    export("kmalloc_caches",   KMALLOC_CACHES.as_ptr() as usize, false);
    export("random_kmalloc_seed", &RANDOM_KMALLOC_SEED as *const usize as usize, false);
    export("page_offset_base", &PAGE_OFFSET_BASE as *const AtomicUsize as usize, false);
    export("vmemmap_base", &VMEMMAP_BASE as *const AtomicUsize as usize, false);
}

/// # C: O(1)
pub(crate) extern "C" fn is_vmalloc_addr(ptr: *const u8) -> bool { vmalloc_backend::is_addr(ptr) }

pub(crate) extern "C" fn kmalloc(size: usize, flags: u32) -> *mut u8 {
    alloc_bytes(size, MIN_ALIGN, flags & GFP_ZERO != 0)
}

pub(crate) extern "C" fn __kmalloc_noprof(size: usize, flags: u32) -> *mut u8 {
    kmalloc(size, flags)
}

// The Linux large-allocation entry point returns a page-aligned allocation
// which kfree can release through the normal allocation surface.
pub(crate) extern "C" fn __kmalloc_large_noprof(size: usize, flags: u32) -> *mut u8 {
    alloc_bytes(size, PAGE_SIZE, flags & GFP_ZERO != 0)
}

pub(crate) extern "C" fn __kmalloc_node_noprof(size: usize, _bucket: usize, flags: u32, _node: i32) -> *mut u8 {
    kmalloc(size, flags)
}

pub(crate) extern "C" fn __kmalloc_cache_noprof(_cache: *mut LinuxKmemCache, flags: u32, size: usize) -> *mut u8 {
    if !_cache.is_null() { cache::kmem_cache_alloc_noprof(_cache, flags) } else { kmalloc(size, flags) }
}

pub(crate) extern "C" fn __kmalloc_cache_node_noprof(cache: *mut LinuxKmemCache, flags: u32, _node: i32, size: usize) -> *mut u8 {
    __kmalloc_cache_noprof(cache, flags, size)
}

pub(crate) extern "C" fn __kvmalloc_node_noprof(size: usize, flags: u32, _node: i32) -> *mut u8 {
    vmalloc_backend::alloc(size, flags & GFP_ZERO != 0)
}

pub(crate) extern "C" fn kzalloc(size: usize, _flags: u32) -> *mut u8 {
    alloc_bytes(size, MIN_ALIGN, true)
}

pub(crate) extern "C" fn kcalloc(n: usize, size: usize, flags: u32) -> *mut u8 {
    let _ = flags;
    match n.checked_mul(size) {
        Some(total) => alloc_bytes(total, MIN_ALIGN, true),
        None => null_mut(),
    }
}

pub(crate) extern "C" fn kfree(ptr: *mut u8) {
    // SAFETY: the kfree KPI requires ptr to be NULL or the live result of this allocator's allocation surface.
    unsafe { free_bytes(ptr); }
}

pub(crate) extern "C" fn kvfree(ptr: *mut u8) {
    if !vmalloc_backend::free(ptr) {
        // SAFETY: kvfree's non-vmalloc path has the same allocator-pointer contract as kfree.
        unsafe { free_bytes(ptr); }
    }
}

pub(crate) extern "C" fn kvfree_call_rcu(_head: *mut c_void, ptr: *mut c_void) {
    let addr = ptr as usize;
    sync::call_rcu(Box::new(move || {
        let ptr = addr as *mut u8;
        if !vmalloc_backend::free(ptr) {
            // SAFETY: kvfree_call_rcu retains the same allocator-pointer contract until this callback frees ptr.
            unsafe { free_bytes(ptr); }
        }
    }));
}

pub(crate) extern "C" fn vmalloc(size: usize) -> *mut u8 {
    vmalloc_backend::alloc(size, false)
}

pub(crate) extern "C" fn vzalloc_noprof(size: usize) -> *mut u8 {
    vmalloc_backend::alloc(size, true)
}

pub(crate) extern "C" fn __vmalloc_noprof(size: usize, flags: u32) -> *mut u8 {
    vmalloc_backend::alloc(size, flags & GFP_ZERO != 0)
}

pub(crate) extern "C" fn kfree_sensitive(ptr: *const u8) {
    if ptr.is_null() { return; }
    // SAFETY: kfree_sensitive receives a live allocation from this allocator, whose header records its full size.
    unsafe {
        let header = ptr.sub(size_of::<Header>()) as *const Header;
        if (*header).magic == ALLOC_MAGIC {
            write_bytes(ptr as *mut u8, 0, (*header).total.saturating_sub((*header).off));
        }
        free_bytes(ptr as *mut u8);
    }
}

pub(crate) extern "C" fn vfree(ptr: *mut u8) {
    let _ = vmalloc_backend::free(ptr);
}
pub(crate) unsafe extern "C" fn kstrdup(s: *const u8, flags: u32) -> *mut u8 {
    if s.is_null() { return null_mut(); }
    // SAFETY: caller supplies a NUL-terminated C string.
    let len = unsafe { c_strlen(s) };
    let p = alloc_bytes(len + 1, MIN_ALIGN, flags & GFP_ZERO != 0);
    if p.is_null() { return null_mut(); }
    // SAFETY: p has len+1 bytes and s is readable through the terminator.
    unsafe { copy_nonoverlapping(s, p, len + 1); }
    p
}

pub(crate) unsafe extern "C" fn kstrndup(s: *const u8, max: usize, flags: u32) -> *mut u8 {
    if s.is_null() { return null_mut(); }
    let mut len = 0usize;
    // SAFETY: caller supplies a C string readable up to max bytes or NUL.
    while len < max && unsafe { *s.add(len) } != 0 { len += 1; }
    let p = alloc_bytes(len + 1, MIN_ALIGN, flags & GFP_ZERO != 0);
    if p.is_null() { return null_mut(); }
    // SAFETY: p has len+1 bytes and s is readable for len bytes.
    unsafe { copy_nonoverlapping(s, p, len); *p.add(len) = 0; }
    p
}

pub(crate) unsafe extern "C" fn kmemdup_noprof(src: *const c_void, len: usize, flags: u32) -> *mut c_void {
    if src.is_null() { return null_mut(); }
    let p = alloc_bytes(len, MIN_ALIGN, flags & GFP_ZERO != 0);
    if p.is_null() { return null_mut(); }
    // SAFETY: src is readable for len bytes and p is writable for len bytes.
    unsafe { copy_nonoverlapping(src as *const u8, p, len); }
    p as *mut c_void
}

pub(crate) unsafe extern "C" fn kasprintf(flags: u32, fmt: *const u8, mut ap: ...) -> *mut u8 {
    if fmt.is_null() { return null_mut(); }
    let mut out = Vec::new();
    // SAFETY: fmt is NUL-terminated and ap matches its conversion list.
    unsafe { format_c(&mut out, fmt, &mut ap); }
    let p = alloc_bytes(out.len() + 1, MIN_ALIGN, flags & GFP_ZERO != 0);
    if p.is_null() { return null_mut(); }
    // SAFETY: p has out.len()+1 bytes; copy payload and write NUL.
    unsafe {
        copy_nonoverlapping(out.as_ptr(), p, out.len());
        *p.add(out.len()) = 0;
    }
    p
}
