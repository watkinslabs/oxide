// Linux allocation KPI exports for loadable drivers.

extern crate alloc;

#[path = "linux_alloc_cache.rs"]
mod cache;
#[path = "linux_alloc_vmap.rs"]
mod vmap;
#[path = "linux_alloc_vmalloc.rs"]
mod vmalloc;

pub use vmalloc::{snapshot as vmalloc_snapshot, Snapshot as VmallocSnapshot};

use alloc::alloc::{alloc, dealloc, Layout};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::{c_void, VaList};
use core::mem::{align_of, size_of};
use core::ptr::{copy_nonoverlapping, null_mut, write_bytes};
use core::sync::atomic::{AtomicU32, Ordering};

const ALLOC_MAGIC: u64 = 0x4f58_4b50_4941_4c4c;
const PAGE_MAGIC: u64 = 0x4f58_4b50_4950_4147;
const CACHE_MAGIC: u64 = 0x4f58_4b50_4943_4143;
const MIN_ALIGN: usize = align_of::<usize>();
const GFP_ZERO: u32 = 0x8000;
pub(crate) const PAGE_SIZE: usize = 4096;
const KMALLOC_CACHE_SLOTS: usize = 128;

#[repr(C)]
pub struct LinuxKmemCache {
    magic: u64,
    object_size: usize,
    align: usize,
    ctor: Option<unsafe extern "C" fn(*mut c_void)>,
}

static KMALLOC_CACHES: [usize; KMALLOC_CACHE_SLOTS] = [0; KMALLOC_CACHE_SLOTS];
static RANDOM_KMALLOC_SEED: usize = 0;

#[repr(C)]
#[derive(Copy, Clone)]
struct Header {
    magic: u64,
    total: usize,
    align: usize,
    off: usize,
}

#[repr(C)]
pub struct LinuxPage {
    magic: u64,
    pa: u64,
    va: *mut u8,
    order: u32,
    refs: AtomicU32,
}

/// Register Linux allocation KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    export("kmalloc",          kmalloc          as *const () as usize, false);
    export("kzalloc",          kzalloc          as *const () as usize, false);
    export("kcalloc",          kcalloc          as *const () as usize, false);
    export("kfree",            kfree            as *const () as usize, false);
    export("kvfree",           kvfree           as *const () as usize, false);
    export("kvfree_call_rcu",   kvfree_call_rcu  as *const () as usize, true);
    export("vmalloc",          vmalloc          as *const () as usize, false);
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
    export("__kmalloc_cache_noprof", __kmalloc_cache_noprof as *const () as usize, false);
    export("__kmalloc_cache_node_noprof", __kmalloc_cache_node_noprof as *const () as usize, false);
    export("__kvmalloc_node_noprof", __kvmalloc_node_noprof as *const () as usize, false);
    export("__kmem_cache_create_args", cache::__kmem_cache_create_args as *const () as usize, false);
    export("kmem_cache_alloc_noprof", cache::kmem_cache_alloc_noprof as *const () as usize, false);
    export("kmem_cache_free", cache::kmem_cache_free as *const () as usize, false);
    export("kmem_cache_destroy", cache::kmem_cache_destroy as *const () as usize, false);
    export("vzalloc_noprof",   vzalloc_noprof   as *const () as usize, false);
    export("kmalloc_caches",   KMALLOC_CACHES.as_ptr() as usize, false);
    export("random_kmalloc_seed", &RANDOM_KMALLOC_SEED as *const usize as usize, false);
}

extern "C" fn kmalloc(size: usize, flags: u32) -> *mut u8 {
    alloc_bytes(size, MIN_ALIGN, flags & GFP_ZERO != 0)
}

extern "C" fn __kmalloc_noprof(size: usize, flags: u32) -> *mut u8 {
    kmalloc(size, flags)
}

extern "C" fn __kmalloc_cache_noprof(_cache: *mut LinuxKmemCache, flags: u32, size: usize) -> *mut u8 {
    if !_cache.is_null() { cache::kmem_cache_alloc_noprof(_cache, flags) } else { kmalloc(size, flags) }
}

extern "C" fn __kmalloc_cache_node_noprof(cache: *mut LinuxKmemCache, flags: u32, _node: i32, size: usize) -> *mut u8 {
    __kmalloc_cache_noprof(cache, flags, size)
}

extern "C" fn __kvmalloc_node_noprof(size: usize, flags: u32, _node: i32) -> *mut u8 {
    vmalloc::alloc(size, flags & GFP_ZERO != 0)
}

extern "C" fn kzalloc(size: usize, _flags: u32) -> *mut u8 {
    alloc_bytes(size, MIN_ALIGN, true)
}

extern "C" fn kcalloc(n: usize, size: usize, flags: u32) -> *mut u8 {
    let _ = flags;
    match n.checked_mul(size) {
        Some(total) => alloc_bytes(total, MIN_ALIGN, true),
        None => null_mut(),
    }
}

extern "C" fn kfree(ptr: *mut u8) {
    // SAFETY: the kfree KPI requires ptr to be NULL or the live result of this allocator's allocation surface.
    unsafe { free_bytes(ptr); }
}

extern "C" fn kvfree(ptr: *mut u8) {
    if !vmalloc::free(ptr) {
        // SAFETY: kvfree's non-vmalloc path has the same allocator-pointer contract as kfree.
        unsafe { free_bytes(ptr); }
    }
}

extern "C" fn kvfree_call_rcu(_head: *mut c_void, ptr: *mut c_void) {
    let addr = ptr as usize;
    sync::call_rcu(Box::new(move || {
        let ptr = addr as *mut u8;
        if !vmalloc::free(ptr) {
            // SAFETY: kvfree_call_rcu retains the same allocator-pointer contract until this callback frees ptr.
            unsafe { free_bytes(ptr); }
        }
    }));
}

extern "C" fn vmalloc(size: usize) -> *mut u8 {
    vmalloc::alloc(size, false)
}

extern "C" fn vzalloc_noprof(size: usize) -> *mut u8 {
    vmalloc::alloc(size, true)
}

extern "C" fn vfree(ptr: *mut u8) {
    let _ = vmalloc::free(ptr);
}

/// Allocate a Linux `struct page` descriptor plus owned contiguous pages.
/// # C: O(order)
pub(crate) extern "C" fn alloc_pages(flags: u32, order: u32) -> *mut LinuxPage {
    let (pa, va) = match page_run_alloc(order, flags & GFP_ZERO != 0) {
        Some(v) => v,
        None => return null_mut(),
    };
    let page = page_desc_alloc(LinuxPage {
        magic: PAGE_MAGIC,
        pa,
        va,
        order,
        refs: AtomicU32::new(1),
    });
    if page.is_null() {
        page_run_free_pa(pa, order);
        return null_mut();
    }
    page
}

extern "C" fn alloc_pages_noprof(flags: u32, order: u32) -> *mut LinuxPage {
    alloc_pages(flags, order)
}

extern "C" fn __alloc_pages_noprof(
    flags: u32,
    order: u32,
    _preferred_nid: i32,
    _nodemask: *mut c_void,
) -> *mut LinuxPage {
    alloc_pages(flags, order)
}

/// Free pages owned by a Linux `struct page` descriptor.
/// # C: O(order)
pub(crate) extern "C" fn __free_pages(page: *mut LinuxPage, order: u32) {
    if page.is_null() { return; }
    // SAFETY: __free_pages' KPI contract is that page came from alloc_pages, so it is a live
    // page_desc_alloc block; valid_page then rejects anything whose magic is not PAGE_MAGIC.
    if !unsafe { valid_page(page) } { return; }
    // SAFETY: valid_page just confirmed PAGE_MAGIC, so page is an initialised LinuxPage whose
    // pa field is the page_run_alloc run recorded by alloc_pages.
    let pa = unsafe { (*page).pa };
    page_run_free_pa(pa, order);
    page_desc_free(page);
}

extern "C" fn __get_free_pages(flags: u32, order: u32) -> usize {
    page_run_alloc(order, flags & GFP_ZERO != 0).map(|(_, va)| va as usize).unwrap_or(0)
}

extern "C" fn get_free_pages(flags: u32, order: u32) -> usize {
    __get_free_pages(flags, order)
}

extern "C" fn free_pages(addr: usize, order: u32) {
    if addr == 0 { return; }
    page_run_free_va(addr as *mut u8, order);
}

pub(crate) extern "C" fn page_address(page: *mut LinuxPage) -> *mut u8 {
    // SAFETY: page_address' KPI contract is that page is a descriptor from alloc_pages (or NULL,
    // which valid_page rejects); on a PAGE_MAGIC match the va field is the direct-map pointer
    // page_run_alloc returned for the same run, still owned by this descriptor.
    if unsafe { valid_page(page) } { unsafe { (*page).va } } else { null_mut() }
}

/// Bytes the page descriptor's run covers, i.e. `PAGE_SIZE << order`, or None for a foreign pointer.
/// # C: O(1)
pub(crate) fn page_run_len(page: *mut LinuxPage) -> Option<usize> {
    // SAFETY: page_run_len's precondition matches page_address' — page is NULL or a descriptor from
    // alloc_pages that __free_pages has not released — so valid_page may read its magic word, and a
    // PAGE_MAGIC match means `order` is the allocation order alloc_pages recorded for the same run.
    if !unsafe { valid_page(page) } { return None; }
    // SAFETY: valid_page returned true above, so page is a live page_desc_alloc descriptor whose
    // order field was written by alloc_pages; the shift is the same one page_run_alloc sized with.
    PAGE_SIZE.checked_shl(unsafe { (*page).order })
}

/// Return the number of owners of a live Linux page descriptor.
/// # C: O(1)
pub(crate) fn page_ref_count(page: *mut LinuxPage) -> Option<u32> {
    // SAFETY: the caller supplies a descriptor returned by alloc_pages which remains live while
    // this count is inspected; valid_page verifies that descriptor before reading its refcount.
    if unsafe { valid_page(page) } {
        // SAFETY: valid_page above proved page is an initialized live descriptor, so its atomic
        // refcount field is readable for this ownership observation.
        Some(unsafe { (*page).refs.load(Ordering::Acquire) })
    } else {
        None
    }
}

/// Add an owner to a live Linux page descriptor.
/// # C: O(1)
#[cfg(any(test, feature = "hosted"))]
pub(crate) fn page_get(page: *mut LinuxPage) -> bool {
    // SAFETY: the caller supplies a live descriptor returned by alloc_pages; valid_page verifies
    // that it is the allocator's descriptor before the reference count is incremented.
    if !unsafe { valid_page(page) } { return false; }
    // SAFETY: valid_page above proved page is an initialized live descriptor with an atomic
    // refcount field whose increment records the caller's new ownership reference.
    unsafe { (*page).refs.fetch_add(1, Ordering::AcqRel); }
    true
}

/// Release one owner of a live Linux page descriptor, freeing it on the final release.
/// # C: O(order)
pub(crate) fn page_put(page: *mut LinuxPage) {
    // SAFETY: the caller transfers one outstanding allocation ownership reference; valid_page
    // rejects NULL and non-allocator descriptors before touching the reference count.
    if !unsafe { valid_page(page) } { return; }
    // SAFETY: valid_page proved page is live. AcqRel pairs this final release with prior owners.
    if unsafe { (*page).refs.fetch_sub(1, Ordering::AcqRel) } == 1 {
        // SAFETY: this was the final reference, so releasing the backing run exactly once is valid.
        unsafe { __free_pages(page, (*page).order); }
    }
}

extern "C" fn page_to_phys(page: *mut LinuxPage) -> u64 {
    // SAFETY: page_to_phys accepts a live struct page descriptor from the page allocator KPI.
    unsafe { linux_page_phys(page).unwrap_or(0) }
}

pub(crate) unsafe fn linux_page_phys(page: *const LinuxPage) -> Option<u64> {
    // SAFETY: caller supplies a readable live page descriptor, so valid_page may read its magic.
    if unsafe { valid_page(page as *mut LinuxPage) } { Some(unsafe { (*page).pa }) } else { None }
}

unsafe extern "C" fn kstrdup(s: *const u8, flags: u32) -> *mut u8 {
    if s.is_null() { return null_mut(); }
    // SAFETY: caller supplies a NUL-terminated C string.
    let len = unsafe { c_strlen(s) };
    let p = alloc_bytes(len + 1, MIN_ALIGN, flags & GFP_ZERO != 0);
    if p.is_null() { return null_mut(); }
    // SAFETY: p has len+1 bytes and s is readable through the terminator.
    unsafe { copy_nonoverlapping(s, p, len + 1); }
    p
}

unsafe extern "C" fn kstrndup(s: *const u8, max: usize, flags: u32) -> *mut u8 {
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

unsafe extern "C" fn kmemdup_noprof(src: *const c_void, len: usize, flags: u32) -> *mut c_void {
    if src.is_null() { return null_mut(); }
    let p = alloc_bytes(len, MIN_ALIGN, flags & GFP_ZERO != 0);
    if p.is_null() { return null_mut(); }
    // SAFETY: src is readable for len bytes and p is writable for len bytes.
    unsafe { copy_nonoverlapping(src as *const u8, p, len); }
    p as *mut c_void
}

unsafe extern "C" fn kasprintf(flags: u32, fmt: *const u8, mut ap: ...) -> *mut u8 {
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

pub(crate) fn alloc_bytes(size: usize, align: usize, zero: bool) -> *mut u8 {
    if size == 0 { return null_mut(); }
    let align = align.max(MIN_ALIGN).next_power_of_two();
    let off = align_up(size_of::<Header>(), align);
    let total = match off.checked_add(size) { Some(v) => v, None => return null_mut() };
    let layout = match Layout::from_size_align(total, align.max(align_of::<Header>())) {
        Ok(v) => v,
        Err(_) => return null_mut(),
    };
    // SAFETY: alloc requires a non-zero-size layout; size != 0 was checked at entry and
    // total = off + size, so from_size_align above accepted a layout of at least `size` bytes.
    let base = unsafe { alloc(layout) };
    if base.is_null() { return null_mut(); }
    // SAFETY: off < total because total = off + size with size >= 1, so base.add(off) stays
    // inside the allocation `alloc` just returned for `layout`.
    let user = unsafe { base.add(off) };
    let h = Header { magic: ALLOC_MAGIC, total, align: layout.align(), off };
    // SAFETY: header slot is inside the allocation immediately before user.
    unsafe {
        (user.sub(size_of::<Header>()) as *mut Header).write(h);
        if zero { write_bytes(user, 0, size); }
    }
    user
}

unsafe fn free_bytes(ptr: *mut u8) {
    if ptr.is_null() { return; }
    // SAFETY: caller supplies the live result of alloc_bytes, so its immediately preceding Header is readable.
    let hp = unsafe { ptr.sub(size_of::<Header>()) as *mut Header };
    // SAFETY: the Header belongs to the live allocation supplied by the caller.
    let h = unsafe { *hp };
    if h.magic != ALLOC_MAGIC { return; }
    let layout = match Layout::from_size_align(h.total, h.align) {
        Ok(v) => v,
        Err(_) => return,
    };
    // SAFETY: base/layout are reconstructed from the header written by alloc_bytes.
    unsafe { dealloc(ptr.sub(h.off), layout); }
}

// Precondition: page is NULL or points to a readable, size_of::<LinuxPage>()-sized allocation —
// i.e. a descriptor from page_desc_alloc that page_desc_free has not yet released. Only the magic
// word is read, so a live-but-foreign block is rejected rather than trusted.
unsafe fn valid_page(page: *mut LinuxPage) -> bool {
    if page.is_null() { return false; }
    // SAFETY: the caller's precondition makes page a live page_desc_alloc block, so the magic
    // field written by alloc_pages is readable here.
    unsafe { (*page).magic == PAGE_MAGIC }
}

fn page_desc_alloc(page: LinuxPage) -> *mut LinuxPage {
    let layout = Layout::new::<LinuxPage>();
    // SAFETY: layout is the exact LinuxPage layout.
    let p = unsafe { alloc(layout) as *mut LinuxPage };
    if p.is_null() { return null_mut(); }
    // SAFETY: p has LinuxPage layout and is uninitialised.
    unsafe { p.write(page); }
    p
}

fn page_desc_free(page: *mut LinuxPage) {
    let layout = Layout::new::<LinuxPage>();
    // SAFETY: page was allocated by page_desc_alloc with this layout.
    unsafe { dealloc(page as *mut u8, layout); }
}

fn align_up(v: usize, a: usize) -> usize {
    (v + (a - 1)) & !(a - 1)
}

unsafe fn c_strlen(s: *const u8) -> usize {
    let mut n = 0usize;
    // SAFETY: caller supplied a NUL-terminated C string.
    unsafe { while *s.add(n) != 0 { n += 1; } }
    n
}

#[cfg(target_os = "oxide-kernel")]
/// Allocate a contiguous PMM page run for Linux KPI wrappers.
/// # C: O(order)
pub(crate) fn page_run_alloc(order: u32, zero: bool) -> Option<(u64, *mut u8)> {
    if order > pmm::MAX_ORDER as u32 { return None; }
    let pa = pmm::setup::alloc_contig_object(pmm::Order(order as u8))?;
    let va = pmm::setup::frame_ptr(pa)?;
    if zero {
        let bytes = PAGE_SIZE.checked_shl(order).unwrap_or(0);
        if bytes == 0 { return None; }
        // SAFETY: va covers the allocated contiguous PMM run.
        unsafe { write_bytes(va, 0, bytes); }
    }
    Some((pa, va))
}

#[cfg(target_os = "oxide-kernel")]
/// Free a contiguous PMM page run by physical address.
/// # C: O(order)
pub(crate) fn page_run_free_pa(pa: u64, order: u32) {
    if order > pmm::MAX_ORDER as u32 { return; }
    // SAFETY: caller owns the page run returned by page_run_alloc.
    unsafe { pmm::setup::free_contig(pa, pmm::Order(order as u8)); }
}

#[cfg(target_os = "oxide-kernel")]
/// Free a contiguous PMM page run by direct-map address.
/// # C: O(order)
pub(crate) fn page_run_free_va(va: *mut u8, order: u32) {
    if let Some(pa) = direct_pa_for_va(va as *const u8) { page_run_free_pa(pa, order); }
}

#[cfg(not(target_os = "oxide-kernel"))]
/// Allocate a hosted page-aligned run for Linux KPI tests.
/// # C: O(order)
pub(crate) fn page_run_alloc(order: u32, zero: bool) -> Option<(u64, *mut u8)> {
    let bytes = PAGE_SIZE.checked_shl(order)?;
    let va = alloc_bytes(bytes, PAGE_SIZE, zero);
    if va.is_null() { None } else { Some((va as u64, va)) }
}

#[cfg(not(target_os = "oxide-kernel"))]
/// Free a hosted page-aligned run by pseudo-physical address.
/// # C: O(1)
pub(crate) fn page_run_free_pa(pa: u64, _order: u32) {
    // SAFETY: hosted page_run_alloc returns this pointer value and its owner transfers it here exactly once.
    unsafe { free_bytes(pa as *mut u8); }
}

#[cfg(not(target_os = "oxide-kernel"))]
/// Free a hosted page-aligned run by virtual address.
/// # C: O(1)
pub(crate) fn page_run_free_va(va: *mut u8, _order: u32) {
    // SAFETY: hosted page_run_alloc returned va and its owner transfers it here exactly once.
    unsafe { free_bytes(va); }
}

#[cfg(target_os = "oxide-kernel")]
/// Translate a direct-map kernel virtual address to a physical address.
/// # C: O(1)
pub(crate) fn direct_pa_for_va(va: *const u8) -> Option<u64> {
    let hhdm = pmm::user_as::hhdm_offset() as usize;
    if hhdm == 0 || (va as usize) < hhdm { None } else { Some((va as usize - hhdm) as u64) }
}

#[cfg(not(target_os = "oxide-kernel"))]
/// Translate hosted pointers through the identity DMA test policy.
/// # C: O(1)
pub(crate) fn direct_pa_for_va(va: *const u8) -> Option<u64> {
    if va.is_null() { None } else { Some(va as u64) }
}

unsafe fn format_c(out: &mut Vec<u8>, fmt: *const u8, ap: &mut VaList) {
    let mut i = 0usize;
    loop {
        // SAFETY: fmt is a NUL-terminated format string.
        let b = unsafe { *fmt.add(i) };
        if b == 0 { break; }
        if b != b'%' { out.push(b); i += 1; continue; }
        i += 1;
        // SAFETY: reading the next format byte is within the NUL string.
        let mut c = unsafe { *fmt.add(i) };
        if c == b'%' { out.push(b'%'); i += 1; continue; }
        let mut long = false;
        if c == b'l' || c == b'z' {
            long = true; i += 1;
            // SAFETY: length modifier consumed; read conversion byte.
            c = unsafe { *fmt.add(i) };
            if c == b'l' {
                i += 1;
                // SAFETY: second l consumed; read conversion byte.
                c = unsafe { *fmt.add(i) };
            }
        }
        match c {
            b's' => {
                // SAFETY: kasprintf's contract is that the varargs match fmt; a %s conversion was
                // just parsed, so the next slot holds a char pointer and next_arg reads it as such.
                let p = unsafe { ap.next_arg::<*mut c_void>() as *const u8 };
                push_cstr(out, p);
            }
            b'c' => {
                // SAFETY: char is int-promoted in C varargs.
                out.push(unsafe { ap.next_arg::<i32>() as u8 });
            }
            b'd' | b'i' => {
                let v = if long {
                    // SAFETY: the l/z modifier consumed above means the caller passed a long or
                    // ssize_t for this %ld/%zd, which is exactly i64 on both LP64 kernel targets.
                    unsafe { ap.next_arg::<i64>() }
                } else {
                    // SAFETY: no length modifier was parsed, so bare %d/%i takes a C int, which
                    // after default argument promotion is the i32 read here.
                    unsafe { ap.next_arg::<i32>() as i64 }
                };
                push_i64(out, v);
            }
            b'u' | b'x' => {
                let v = if long {
                    // SAFETY: the l/z modifier consumed above means this %lu/%zx slot holds an
                    // unsigned long or size_t, which is exactly u64 on both LP64 kernel targets.
                    unsafe { ap.next_arg::<u64>() }
                } else {
                    // SAFETY: no length modifier was parsed, so bare %u/%x takes an unsigned int,
                    // which after default argument promotion is the u32 read here.
                    unsafe { ap.next_arg::<u32>() as u64 }
                };
                push_u64(out, v, if c == b'x' { 16 } else { 10 });
            }
            b'p' => {
                // SAFETY: a %p conversion was just parsed, so the caller's matching vararg is a
                // pointer; it is only widened to usize for hex formatting, never dereferenced.
                let p = unsafe { ap.next_arg::<*mut c_void>() as usize };
                out.extend_from_slice(b"0x");
                push_u64(out, p as u64, 16);
            }
            _ => { out.push(b'%'); out.push(c); }
        }
        i += 1;
    }
}

fn push_cstr(out: &mut Vec<u8>, p: *const u8) {
    if p.is_null() { out.extend_from_slice(b"(null)"); return; }
    let mut n = 0usize;
    // SAFETY: caller's format contract makes p a NUL-terminated C string.
    unsafe { while *p.add(n) != 0 { out.push(*p.add(n)); n += 1; } }
}

fn push_i64(out: &mut Vec<u8>, v: i64) {
    if v < 0 { out.push(b'-'); push_u64(out, v.unsigned_abs(), 10); }
    else { push_u64(out, v as u64, 10); }
}

fn push_u64(out: &mut Vec<u8>, mut v: u64, base: u64) {
    let mut buf = [0u8; 32];
    let mut i = buf.len();
    loop {
        i -= 1;
        let d = (v % base) as u8;
        buf[i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        v /= base;
        if v == 0 { break; }
    }
    out.extend_from_slice(&buf[i..]);
}

#[cfg(test)]
#[path = "linux_alloc_tests.rs"]
mod tests;
