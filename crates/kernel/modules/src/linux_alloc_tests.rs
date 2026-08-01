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
    let _modules = crate::test_serial::claim();
    let p = kmalloc(16, 0);
    assert!(!p.is_null());
    // SAFETY: p is the 16-byte kmalloc block asserted non-null on the line above, so byte 0 of it
    // is writable and still owned by this test until the kfree below.
    unsafe { *p = 0xaa; }
    kfree(p);
    let z = kzalloc(8, 0);
    assert!(!z.is_null());
    // SAFETY: z is the 8-byte kzalloc block asserted non-null above, so exactly 8 initialised
    // bytes are readable from it; the slice does not outlive the kfree below.
    unsafe { assert_eq!(core::slice::from_raw_parts(z, 8), &[0; 8]); }
    kfree(z);
}

#[test]
fn kcalloc_checks_overflow_and_zeroes() {
    let _modules = crate::test_serial::claim();
    assert!(kcalloc(usize::MAX, 2, 0).is_null());
    let p = kcalloc(4, 4, 0);
    assert!(!p.is_null());
    // SAFETY: p is the kcalloc(4, 4) block asserted non-null above, i.e. 4*4 = 16 bytes that
    // kcalloc zero-initialised, so reading exactly 16 bytes stays inside it.
    unsafe { assert_eq!(core::slice::from_raw_parts(p, 16), &[0; 16]); }
    kfree(p);
}

#[test]
fn page_runs_support_struct_page_and_free_pages() {
    let _modules = crate::test_serial::claim();
    let page = alloc_pages(GFP_ZERO, 1);
    assert!(!page.is_null());
    let addr = page_address(page);
    assert!(!addr.is_null());
    assert_ne!(page_to_phys(page), 0);
    // SAFETY: addr is page_address of the order-1 run allocated above, so it covers 2 << 0 pages =
    // PAGE_SIZE * 2 bytes, zeroed because GFP_ZERO was passed and not yet freed.
    unsafe { assert_eq!(core::slice::from_raw_parts(addr, PAGE_SIZE * 2), &[0; PAGE_SIZE * 2]); }
    __free_pages(page, 1);
    let addr = __get_free_pages(0, 0);
    assert_ne!(addr, 0);
    free_pages(addr, 0);
}

#[test]
fn vmap_single_page_aliases_and_unmaps() {
    let _modules = crate::test_serial::claim();
    let page = alloc_pages(GFP_ZERO, 0);
    assert!(!page.is_null());
    let mut pages = [page];
    // SAFETY: vmap's contract is count entries of a live struct page array; `pages` is the
    // one-element stack array just built from the alloc_pages descriptor, so count = 1 matches.
    let addr = unsafe { vmap::vmap(pages.as_mut_ptr(), 1, 0, 0) };
    assert_eq!(addr as *mut u8, page_address(page));
    vmap::vunmap(addr);
    __free_pages(page, 0);
}

#[test]
fn vmap_rejects_non_contiguous_page_list() {
    let _modules = crate::test_serial::claim();
    let a = alloc_pages(GFP_ZERO, 0);
    let b = alloc_pages(GFP_ZERO, 0);
    assert!(!a.is_null());
    assert!(!b.is_null());
    let mut pages = [a, b];
    // SAFETY: `pages` is the two-element stack array of the descriptors a and b allocated and
    // asserted non-null above, so the count of 2 passed to vmap matches its length exactly.
    let addr = unsafe { vmap::vmap(pages.as_mut_ptr(), 2, 0, 0) };
    assert!(addr.is_null());
    __free_pages(a, 0);
    __free_pages(b, 0);
}

#[test]
fn string_helpers_copy_and_format() {
    let _modules = crate::test_serial::claim();
    // SAFETY: kstrdup requires a NUL-terminated string; the b"drv\0" literal is a 'static array
    // whose final byte is the terminator, so c_strlen inside kstrdup stops within it.
    let dup = unsafe { kstrdup(b"drv\0".as_ptr(), 0) };
    // SAFETY: dup is kstrdup's copy of "drv\0", which copied len+1 bytes including the NUL, so
    // cstr's c_strlen terminates inside that allocation and it is still live until the kfree.
    assert_eq!(unsafe { cstr(dup) }, "drv");
    kfree(dup);
    // SAFETY: the NUL-terminated fmt literal's four conversions match the varargs in order and C
    // promotion class: %s a char pointer to the b"irq\0" literal, %d an int, %x an unsigned int,
    // %p a pointer, and kasprintf dereferences only the %s argument.
    let s = unsafe { kasprintf(0, b"%s:%d:%x:%p\0".as_ptr(), b"irq\0".as_ptr(), -7i32, 0x2au32, 0x1234usize as *mut c_void) };
    // SAFETY: s is kasprintf's buffer, allocated as out.len()+1 bytes with an explicit NUL
    // written at the end, so cstr's c_strlen stops inside it; freed on the next line.
    assert_eq!(unsafe { cstr(s) }, "irq:-7:2a:0x1234");
    kfree(s);
}

#[test]
fn modern_noprof_allocators_match_linux_entry_points() {
    let _modules = crate::test_serial::claim();
    let p = __kmalloc_noprof(24, GFP_ZERO);
    assert!(!p.is_null());
    // SAFETY: p is the 24-byte __kmalloc_noprof block asserted non-null above, zeroed because
    // GFP_ZERO was passed, so exactly 24 initialised bytes are readable from it.
    unsafe { assert_eq!(core::slice::from_raw_parts(p, 24), &[0; 24]); }
    kvfree(p);

    let c = __kmalloc_cache_noprof(core::ptr::null_mut(), 0, 12);
    assert!(!c.is_null());
    kfree(c);

    let v = __kvmalloc_node_noprof(20, 0, -1);
    assert!(!v.is_null());
    kvfree_call_rcu(core::ptr::null_mut(), v as *mut c_void);

    // SAFETY: kmemdup_noprof reads len bytes from src; the b"copy" literal is a 'static 4-byte
    // array and len is 4, so the copy stays inside it.
    let d = unsafe { kmemdup_noprof(b"copy".as_ptr() as *const c_void, 4, 0) };
    assert!(!d.is_null());
    // SAFETY: d is the 4-byte kmemdup_noprof duplicate asserted non-null above, fully initialised
    // by that copy, so reading exactly 4 bytes stays in bounds.
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
    let _modules = crate::test_serial::claim();
    CTOR_CALLS.store(0, Ordering::SeqCst);
    let args = cache::LinuxKmemCacheArgs {
        align: 16,
        useroffset: 0,
        usersize: 0,
        freeptr_offset: 0,
        use_freeptr_offset: false,
        ctor: Some(cache_ctor),
    };
    // SAFETY: __kmem_cache_create_args wants a NUL-terminated name and a readable args struct;
    // b"sample\0" ends in a terminator and `args` is the stack value initialised just above,
    // borrowed for the duration of the call only.
    let cache = unsafe { cache::__kmem_cache_create_args(b"sample\0".as_ptr(), 32, &args, 0) };
    assert!(!cache.is_null());
    let obj = cache::kmem_cache_alloc_noprof(cache, GFP_ZERO);
    assert!(!obj.is_null());
    assert_eq!(CTOR_CALLS.load(Ordering::SeqCst), 1);
    // SAFETY: obj is the 32-byte object asserted non-null above; cache_ctor ran on it (CTOR_CALLS
    // == 1) and wrote byte 0, so that byte is initialised and in bounds.
    unsafe { assert_eq!(*obj, 0x5a); }
    cache::kmem_cache_free(cache, obj as *mut c_void);
    cache::kmem_cache_destroy(cache);
}

#[test]
fn noprof_page_allocators_return_page_descriptors() {
    let _modules = crate::test_serial::claim();
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
    let _modules = crate::test_serial::claim();
    export_symbols();
    for name in [
        "kmalloc", "kzalloc", "kcalloc", "kfree", "vmalloc", "vfree", "vmap", "vunmap",
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
