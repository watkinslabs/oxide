#[cfg(not(target_os = "oxide-kernel"))]
use alloc::alloc::{alloc, dealloc, Layout};
use core::ffi::c_void;
use core::ptr::null_mut;
#[cfg(target_os = "oxide-kernel")]
use core::ptr::write_bytes;
use core::sync::atomic::Ordering;
#[cfg(not(target_os = "oxide-kernel"))]
use core::sync::atomic::AtomicU32;

use super::{LinuxPage, GFP_ZERO, PAGE_SIZE};
#[cfg(not(target_os = "oxide-kernel"))]
use super::{alloc_bytes, free_bytes};
#[cfg(target_os = "oxide-kernel")]
use super::types::NATIVE_PAGE_RUNS;
#[cfg(target_os = "oxide-kernel")]
use super::types::NativePageRun;
#[cfg(not(target_os = "oxide-kernel"))]
use super::types::PAGE_MAGIC;
/// Allocate a Linux `struct page` descriptor plus owned contiguous pages.
/// # C: O(order)
pub(crate) extern "C" fn alloc_pages(flags: u32, order: u32) -> *mut LinuxPage {
    #[cfg(target_os = "oxide-kernel")]
    {
        let (pa, _) = match page_run_alloc(order, flags & GFP_ZERO != 0) {
            Some(v) => v,
            None => return null_mut(),
        };
        let page = pmm::setup::native_page_for_pa(pa);
        if page.is_null() {
            page_run_free_pa(pa, order);
            return null_mut();
        }
        if !native_page_run_insert(pa, order) {
            page_run_free_pa(pa, order);
            return null_mut();
        }
        // SAFETY: PMM returned this physical run exclusively, and its native descriptor is permanent per-PFN storage.
        unsafe { (*page).refcount.store(1, Ordering::Release); }
        return page.cast();
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
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
}

pub(crate) extern "C" fn alloc_pages_noprof(flags: u32, order: u32) -> *mut LinuxPage {
    alloc_pages(flags, order)
}

pub(crate) extern "C" fn __alloc_pages_noprof(
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
    #[cfg(target_os = "oxide-kernel")]
    {
        // SAFETY: page is non-null (checked above); linux_page_phys's native_page_run casts it only as a pmm registry lookup key (see native_page_run below) and never dereferences it directly.
        let Some(pa) = (unsafe { linux_page_phys(page) }) else { return; };
        if !native_page_run_take(pa, order) { return; }
        // SAFETY: this allocation's caller supplied the matching order and transfers its final ownership.
        unsafe { (page as *mut pmm::NativePage).as_mut().unwrap().refcount.store(0, Ordering::Release); }
        page_run_free_pa(pa, order);
        return;
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
    // SAFETY: __free_pages' KPI contract is that page came from alloc_pages, so it is a live
    // page_desc_alloc block; valid_page then rejects anything whose magic is not PAGE_MAGIC.
    if !unsafe { valid_page(page) } { return; }
    // SAFETY: valid_page just confirmed PAGE_MAGIC, so page is an initialised LinuxPage whose
    // pa field is the page_run_alloc run recorded by alloc_pages.
    let pa = unsafe { (*page).pa };
    page_run_free_pa(pa, order);
    page_desc_free(page);
    }
}

pub(crate) extern "C" fn __get_free_pages(flags: u32, order: u32) -> usize {
    page_run_alloc(order, flags & GFP_ZERO != 0).map(|(_, va)| va as usize).unwrap_or(0)
}

pub(crate) extern "C" fn get_free_pages(flags: u32, order: u32) -> usize {
    __get_free_pages(flags, order)
}

pub(crate) extern "C" fn free_pages(addr: usize, order: u32) {
    if addr == 0 { return; }
    page_run_free_va(addr as *mut u8, order);
}

pub(crate) extern "C" fn page_address(page: *mut LinuxPage) -> *mut u8 {
    #[cfg(target_os = "oxide-kernel")]
    // SAFETY: page_address forwards page unchecked into linux_page_phys, but its native_page_run casts the pointer only as a pmm registry lookup key (see native_page_run below) and never dereferences it directly, so a null/foreign page cannot fault here.
    { return unsafe { linux_page_phys(page) }.and_then(pmm::setup::frame_ptr).unwrap_or(null_mut()); }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
    // SAFETY: page_address' KPI contract is that page is a descriptor from alloc_pages (or NULL,
    // which valid_page rejects); on a PAGE_MAGIC match the va field is the direct-map pointer
    // page_run_alloc returned for the same run, still owned by this descriptor.
    if unsafe { valid_page(page) } { unsafe { (*page).va } } else { null_mut() }
    }
}

/// Bytes the page descriptor's run covers, i.e. `PAGE_SIZE << order`, or None for a foreign pointer.
/// # C: O(1)
pub(crate) fn page_run_len(page: *mut LinuxPage) -> Option<usize> {
    #[cfg(target_os = "oxide-kernel")]
    {
        let (_, order) = native_page_run(page)?;
        return PAGE_SIZE.checked_shl(order);
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
    // SAFETY: page_run_len's precondition matches page_address' — page is NULL or a descriptor from
    // alloc_pages that __free_pages has not released — so valid_page may read its magic word, and a
    // PAGE_MAGIC match means `order` is the allocation order alloc_pages recorded for the same run.
    if !unsafe { valid_page(page) } { return None; }
    // SAFETY: valid_page returned true above, so page is a live page_desc_alloc descriptor whose
    // order field was written by alloc_pages; the shift is the same one page_run_alloc sized with.
    PAGE_SIZE.checked_shl(unsafe { (*page).order })
    }
}

/// Return the number of owners of a live Linux page descriptor.
/// # C: O(1)
pub(crate) fn page_ref_count(page: *mut LinuxPage) -> Option<u32> {
    #[cfg(target_os = "oxide-kernel")]
    {
        // SAFETY: page_ref_count forwards page unchecked into valid_page, whose oxide-kernel arm resolves it via native_page_run's pmm registry lookup (below) rather than a direct dereference, so an invalid page returns None instead of faulting.
        if !unsafe { valid_page(page) } { return None; }
        // SAFETY: valid_page proved this is a PMM native descriptor with an initialized refcount.
        return Some(unsafe { (*page.cast::<pmm::NativePage>()).refcount.load(Ordering::Acquire).max(0) as u32 });
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
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
    #[cfg(target_os = "oxide-kernel")]
    {
        let Some((_, order)) = native_page_run(page) else { return; };
        // SAFETY: valid_page proved this permanent descriptor belongs to an allocated PMM frame.
        if unsafe { (*page.cast::<pmm::NativePage>()).refcount.fetch_sub(1, Ordering::AcqRel) } == 1 {
            __free_pages(page, order);
        }
        return;
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
    // SAFETY: the caller transfers one outstanding allocation ownership reference; valid_page
    // rejects NULL and non-allocator descriptors before touching the reference count.
    if !unsafe { valid_page(page) } { return; }
    // SAFETY: valid_page proved page is live. AcqRel pairs this final release with prior owners.
    if unsafe { (*page).refs.fetch_sub(1, Ordering::AcqRel) } == 1 {
        // SAFETY: this was the final reference, so releasing the backing run exactly once is valid.
        unsafe { __free_pages(page, (*page).order); }
    }
    }
}

pub(crate) extern "C" fn page_to_phys(page: *mut LinuxPage) -> u64 {
    // SAFETY: page_to_phys accepts a live struct page descriptor from the page allocator KPI.
    unsafe { linux_page_phys(page).unwrap_or(0) }
}

pub(crate) unsafe fn linux_page_phys(page: *const LinuxPage) -> Option<u64> {
    #[cfg(target_os = "oxide-kernel")]
    { return native_page_run(page as *mut LinuxPage).map(|(pa, _)| pa); }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
    // SAFETY: caller supplies a readable live page descriptor, so valid_page may read its magic.
    if unsafe { valid_page(page as *mut LinuxPage) } { Some(unsafe { (*page).pa }) } else { None }
    }
}
#[cfg(target_os = "oxide-kernel")]
fn native_page_run_insert(pa: u64, order: u32) -> bool {
    let mut runs = NATIVE_PAGE_RUNS.lock();
    if runs.iter().any(|run| run.pa == pa) { return false; }
    runs.push(NativePageRun { pa, order });
    true
}

#[cfg(target_os = "oxide-kernel")]
fn native_page_run(page: *mut LinuxPage) -> Option<(u64, u32)> {
    let pa = pmm::setup::native_page_pa(page.cast())?;
    NATIVE_PAGE_RUNS.lock().iter()
        .find(|run| run.pa == pa)
        .map(|run| (run.pa, run.order))
}

#[cfg(target_os = "oxide-kernel")]
fn native_page_run_take(pa: u64, order: u32) -> bool {
    let mut runs = NATIVE_PAGE_RUNS.lock();
    let Some(index) = runs.iter().position(|run| run.pa == pa && run.order == order) else { return false; };
    runs.swap_remove(index);
    true
}

// Precondition: page is NULL or points to a readable, size_of::<LinuxPage>()-sized allocation —
// i.e. a descriptor from page_desc_alloc that page_desc_free has not yet released. Only the magic
// word is read, so a live-but-foreign block is rejected rather than trusted.
pub(crate) unsafe fn valid_page(page: *mut LinuxPage) -> bool {
    #[cfg(target_os = "oxide-kernel")]
    { return native_page_run(page).is_some(); }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
    if page.is_null() { return false; }
    // SAFETY: the caller's precondition makes page a live page_desc_alloc block, so the magic
    // field written by alloc_pages is readable here.
    unsafe { (*page).magic == PAGE_MAGIC }
    }
}

#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) fn page_desc_alloc(page: LinuxPage) -> *mut LinuxPage {
    let layout = Layout::new::<LinuxPage>();
    // SAFETY: layout is the exact LinuxPage layout.
    let p = unsafe { alloc(layout) as *mut LinuxPage };
    if p.is_null() { return null_mut(); }
    // SAFETY: p has LinuxPage layout and is uninitialised.
    unsafe { p.write(page); }
    p
}

#[cfg(not(target_os = "oxide-kernel"))]
fn page_desc_free(page: *mut LinuxPage) {
    let layout = Layout::new::<LinuxPage>();
    // SAFETY: page was allocated by page_desc_alloc with this layout.
    unsafe { dealloc(page as *mut u8, layout); }
}

pub(crate) fn align_up(v: usize, a: usize) -> usize {
    (v + (a - 1)) & !(a - 1)
}

pub(crate) unsafe fn c_strlen(s: *const u8) -> usize {
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
