//! PMM page-provider boundary for zsmalloc physical zspages.

use core::sync::atomic::{AtomicPtr, Ordering};

use block::{BlockError, KResult};

/// One PMM page-provider installed by the kernel after PMM initialization.
/// zsmalloc owns object placement; PMM remains sole owner of physical frames.
#[derive(Copy, Clone)]
pub struct PageProvider {
    pub(crate) alloc_object_page: fn() -> Option<u64>,
    pub(crate) release_object_page: fn(u64),
    pub(crate) page_ptr: fn(u64) -> Option<*mut u8>,
    pub(crate) try_lock_page: fn(u64) -> bool,
    pub(crate) unlock_page: fn(u64) -> bool,
}

impl PageProvider {
    /// Construct the sole physical-page provider accepted by zsmalloc. # C: O(1)
    pub const fn new(alloc_object_page: fn() -> Option<u64>, release_object_page: fn(u64),
                     page_ptr: fn(u64) -> Option<*mut u8>, try_lock_page: fn(u64) -> bool,
                     unlock_page: fn(u64) -> bool) -> Self {
        Self { alloc_object_page, release_object_page, page_ptr, try_lock_page, unlock_page }
    }
}

static PROVIDER: AtomicPtr<PageProvider> = AtomicPtr::new(core::ptr::null_mut());

/// Install the sole kernel PMM provider before creating any zram device.
/// A second, distinct installation is rejected rather than creating a second
/// physical-memory truth. # C: O(1)
pub fn install_page_provider(provider: PageProvider) -> KResult<()> {
    let raw = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(provider));
    match PROVIDER.compare_exchange(core::ptr::null_mut(), raw, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Ok(()),
        Err(existing) => {
            // SAFETY: `raw` was just allocated above and has not been published.
            unsafe { drop(alloc::boxed::Box::from_raw(raw)); }
            if existing.is_null() { return Err(BlockError::Eio); }
            Err(BlockError::Ebusy)
        }
    }
}

/// Snapshot the installed PMM provider. No provider means zram is unavailable;
/// there is deliberately no heap-backed production fallback. # C: O(1)
pub(crate) fn page_provider() -> Option<PageProvider> {
    let ptr = PROVIDER.load(Ordering::Acquire);
    if ptr.is_null() { return None; }
    // SAFETY: the successful installer leaks this immutable provider for the
    // kernel lifetime, and Release/Acquire publishes its initialized fields.
    Some(unsafe { *ptr })
}

/// Whether zram may create devices on this target. # C: O(1)
pub fn page_provider_ready() -> bool { page_provider().is_some() }

#[cfg(any(test, feature = "hosted"))]
mod hosted {
    use alloc::{boxed::Box, vec, vec::Vec};
    use std::sync::{Mutex, Once};

    use super::{install_page_provider, PageProvider};

    /// Hosted tests provide PMM-shaped physical pages explicitly.  This is
    /// deliberately test-only: production zram still fails closed until
    /// early PMM installs its sole provider.
    static INSTALL: Once = Once::new();
    static PAGES: Mutex<Vec<Option<Box<[u8]>>>> = Mutex::new(Vec::new());

    fn alloc_page() -> Option<u64> {
        let mut pages = PAGES.lock().ok()?;
        let page = vec![0; hal::PAGE_SIZE_BYTES as usize].into_boxed_slice();
        if let Some((index, slot)) = pages.iter_mut().enumerate().find(|(_, page)| page.is_none()) {
            *slot = Some(page);
            return u64::try_from(index + 1).ok()?.checked_mul(hal::PAGE_SIZE_BYTES);
        }
        pages.push(Some(page));
        u64::try_from(pages.len()).ok()?.checked_mul(hal::PAGE_SIZE_BYTES)
    }

    fn release_page(pa: u64) {
        let Ok(index) = usize::try_from(pa / hal::PAGE_SIZE_BYTES) else { return; };
        let Some(index) = index.checked_sub(1) else { return; };
        if let Ok(mut pages) = PAGES.lock() {
            if let Some(slot) = pages.get_mut(index) { *slot = None; }
        }
    }

    fn page_ptr(pa: u64) -> Option<*mut u8> {
        let index = usize::try_from(pa / hal::PAGE_SIZE_BYTES).ok()?.checked_sub(1)?;
        let mut pages = PAGES.lock().ok()?;
        Some(pages.get_mut(index)?.as_mut()?.as_mut_ptr())
    }

    fn try_lock_page(_pa: u64) -> bool { true }
    fn unlock_page(_pa: u64) -> bool { true }

    pub(super) fn install() {
        INSTALL.call_once(|| {
            install_page_provider(PageProvider::new(
                alloc_page, release_page, page_ptr, try_lock_page, unlock_page,
            )).expect("install hosted zram PMM provider");
        });
    }
}

#[cfg(any(test, feature = "hosted"))]
/// Installs the explicit hosted PMM fixture before a zram/pool test creates
/// storage. Production builds never compile this provider. # C: O(1)
pub(crate) fn install_hosted_test_provider() { hosted::install(); }
