use super::*;
use core::sync::atomic::{AtomicUsize, Ordering};

unsafe fn cstr(p: *const u8) -> &'static str {
    // SAFETY: tests pass pointers returned by KPI string allocators.
    let n = unsafe { c_strlen(p) };
    // SAFETY: same allocation is valid for the measured string bytes.
    let s = unsafe { core::slice::from_raw_parts(p, n) };
    core::str::from_utf8(s).unwrap()
}

#[test]
fn kmalloc_round_trip_and_zero_allocs() {
    let p = kmalloc(16, 0);
    assert!(!p.is_null());
    unsafe { *p = 0xaa; }
    kfree(p);
    let z = kzalloc(8, 0);
    assert!(!z.is_null());
    unsafe { assert_eq!(core::slice::from_raw_parts(z, 8), &[0; 8]); }
    kfree(z);
}

#[test]
fn kcalloc_checks_overflow_and_zeroes() {
    assert!(kcalloc(usize::MAX, 2, 0).is_null());
    let p = kcalloc(4, 4, 0);
    assert!(!p.is_null());
    unsafe { assert_eq!(core::slice::from_raw_parts(p, 16), &[0; 16]); }
    kfree(p);
}

#[test]
fn page_runs_support_struct_page_and_free_pages() {
    let page = alloc_pages(GFP_ZERO, 1);
    assert!(!page.is_null());
    let addr = page_address(page);
    assert!(!addr.is_null());
    assert_ne!(page_to_phys(page), 0);
    unsafe { assert_eq!(core::slice::from_raw_parts(addr, PAGE_SIZE * 2), &[0; PAGE_SIZE * 2]); }
    __free_pages(page, 1);
    let addr = __get_free_pages(0, 0);
    assert_ne!(addr, 0);
    free_pages(addr, 0);
}

#[test]
fn string_helpers_copy_and_format() {
    let dup = unsafe { kstrdup(b"drv\0".as_ptr(), 0) };
    assert_eq!(unsafe { cstr(dup) }, "drv");
    kfree(dup);
    let s = unsafe { kasprintf(0, b"%s:%d:%x:%p\0".as_ptr(), b"irq\0".as_ptr(), -7i32, 0x2au32, 0x1234usize as *mut c_void) };
    assert_eq!(unsafe { cstr(s) }, "irq:-7:2a:0x1234");
    kfree(s);
}

#[test]
fn modern_noprof_allocators_match_linux_entry_points() {
    let p = __kmalloc_noprof(24, GFP_ZERO);
    assert!(!p.is_null());
    unsafe { assert_eq!(core::slice::from_raw_parts(p, 24), &[0; 24]); }
    kvfree(p);

    let c = __kmalloc_cache_noprof(core::ptr::null_mut(), 0, 12);
    assert!(!c.is_null());
    kfree(c);

    let v = __kvmalloc_node_noprof(20, 0, -1);
    assert!(!v.is_null());
    kvfree_call_rcu(core::ptr::null_mut(), v as *mut c_void);

    let d = unsafe { kmemdup_noprof(b"copy".as_ptr() as *const c_void, 4, 0) };
    assert!(!d.is_null());
    unsafe { assert_eq!(core::slice::from_raw_parts(d as *const u8, 4), b"copy"); }
    kfree(d as *mut u8);
}

static CTOR_CALLS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn cache_ctor(obj: *mut c_void) {
    CTOR_CALLS.fetch_add(1, Ordering::SeqCst);
    // SAFETY: cache object has at least one byte in this test.
    unsafe { *(obj as *mut u8) = 0x5a; }
}

#[test]
fn kmem_cache_create_alloc_free_destroy_honors_args() {
    CTOR_CALLS.store(0, Ordering::SeqCst);
    let args = cache::LinuxKmemCacheArgs {
        align: 16,
        useroffset: 0,
        usersize: 0,
        freeptr_offset: 0,
        use_freeptr_offset: false,
        ctor: Some(cache_ctor),
    };
    let cache = unsafe { cache::__kmem_cache_create_args(b"sample\0".as_ptr(), 32, &args, 0) };
    assert!(!cache.is_null());
    let obj = cache::kmem_cache_alloc_noprof(cache, GFP_ZERO);
    assert!(!obj.is_null());
    assert_eq!(CTOR_CALLS.load(Ordering::SeqCst), 1);
    unsafe { assert_eq!(*obj, 0x5a); }
    cache::kmem_cache_free(cache, obj as *mut c_void);
    cache::kmem_cache_destroy(cache);
}

#[test]
fn noprof_page_allocators_return_page_descriptors() {
    let page = alloc_pages_noprof(GFP_ZERO, 0);
    assert!(!page.is_null());
    assert!(!page_address(page).is_null());
    __free_pages(page, 0);

    let page = __alloc_pages_noprof(0, 0, -1, core::ptr::null_mut());
    assert!(!page.is_null());
    __free_pages(page, 0);
}

#[test]
fn export_symbols_registers_allocator_surface() {
    crate::symtab::_reset();
    export_symbols();
    for name in [
        "kmalloc", "kzalloc", "kcalloc", "kfree", "vmalloc", "vfree",
        "alloc_pages", "__free_pages", "__get_free_pages", "get_free_pages",
        "free_pages", "page_address", "page_to_phys", "kstrdup", "kasprintf",
        "__kmalloc_noprof", "__kmalloc_cache_noprof", "__kvmalloc_node_noprof",
        "alloc_pages_noprof", "__alloc_pages_noprof", "kvfree", "kvfree_call_rcu",
        "kmemdup_noprof", "__kmem_cache_create_args", "kmem_cache_alloc_noprof",
        "kmem_cache_free", "kmem_cache_destroy", "vzalloc_noprof",
        "kmalloc_caches", "random_kmalloc_seed",
    ] {
        assert!(crate::symtab::resolve(name, true).is_ok(), "{name}");
    }
}
