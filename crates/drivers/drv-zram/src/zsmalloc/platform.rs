//! PMM page-provider boundary for zsmalloc physical zspages.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};
use sync::{Spinlock, TaskList};

use block::{BlockError, KResult};
use movable::{Mode, MoveError, Ops, OwnerId};

struct Owner { id: OwnerId, device: Weak<crate::Zram> }
static OWNERS: Spinlock<Vec<Owner>, TaskList> = Spinlock::new(Vec::new());

fn device(id: OwnerId) -> Option<Arc<crate::Zram>> {
    OWNERS.lock().iter().find(|owner| owner.id == id)?.device.upgrade()
}
fn isolate(id: OwnerId, pa: u64, _mode: Mode) -> bool {
    let Some(device) = device(id) else { return false; };
    let Some(mut state) = device.state.try_lock() else { return false; };
    state.pool.isolate_frame(pa)
}
fn migrate(id: OwnerId, destination: u64, source: u64, _mode: Mode) -> Result<(), MoveError> {
    let Some(device) = device(id) else { return Err(MoveError::Permanent); };
    let Some(mut state) = device.state.try_lock() else { return Err(MoveError::Busy); };
    state.pool.migrate_isolated_frame(source, destination).map_err(|error| match error { BlockError::Ebusy => MoveError::Busy, _ => MoveError::Permanent })
}
fn putback(id: OwnerId, pa: u64) {
    if let Some(device) = device(id) {
        if let Some(mut state) = device.state.try_lock() { state.pool.putback_frame(pa); }
    }
}

/// Bind one zram device to a generic PMM movable-owner entry. # C: O(owners)
pub(crate) fn bind_owner(device: &Arc<crate::Zram>) -> KResult<OwnerId> {
    let provider = page_provider().ok_or(BlockError::Enomem)?;
    let id = (provider.register_movable_owner)(Ops { isolate, migrate, putback }).map_err(|_| BlockError::Enomem)?;
    let mut owners = OWNERS.lock();
    owners.try_reserve(1).map_err(|_| BlockError::Enomem)?;
    owners.push(Owner { id, device: Arc::downgrade(device) });
    Ok(id)
}

/// Retire a zram movable-owner entry after every zspage was released. # C: O(owners)
pub(crate) fn unbind_owner(id: OwnerId) -> KResult<()> {
    let provider = page_provider().ok_or(BlockError::Enomem)?;
    (provider.unregister_movable_owner)(id).map_err(|_| BlockError::Ebusy)?;
    let mut owners = OWNERS.lock();
    let index = owners.iter().position(|owner| owner.id == id).ok_or(BlockError::Eio)?;
    owners.swap_remove(index);
    Ok(())
}

/// One PMM page-provider installed by the kernel after PMM initialization.
/// zsmalloc owns object placement; PMM remains sole owner of physical frames.
#[derive(Copy, Clone)]
pub struct PageProvider {
    pub(crate) legacy_test_pages: bool,
    pub(crate) alloc_object_page: fn() -> Option<u64>,
    pub(crate) release_object_page: fn(u64),
    pub(crate) page_ptr: fn(u64) -> Option<*mut u8>,
    pub(crate) try_lock_page: fn(u64) -> bool,
    pub(crate) unlock_page: fn(u64) -> bool,
    pub(crate) register_movable_owner: fn(Ops) -> Result<OwnerId, MoveError>,
    pub(crate) unregister_movable_owner: fn(OwnerId) -> Result<(), MoveError>,
    pub(crate) alloc_movable_page: fn(OwnerId) -> Option<u64>,
    pub(crate) release_movable_page: fn(OwnerId, u64) -> bool,
}

impl PageProvider {
    /// Construct a page provider without movable-page support. Test fixtures
    /// use this compatibility constructor; production must use `new_movable`.
    /// # C: O(1)
    pub const fn new(alloc_object_page: fn() -> Option<u64>, release_object_page: fn(u64),
                     page_ptr: fn(u64) -> Option<*mut u8>, try_lock_page: fn(u64) -> bool,
                     unlock_page: fn(u64) -> bool) -> Self {
        Self { legacy_test_pages: true, alloc_object_page, release_object_page, page_ptr, try_lock_page, unlock_page,
            register_movable_owner: unsupported_register, unregister_movable_owner: unsupported_unregister,
            alloc_movable_page: unsupported_alloc, release_movable_page: unsupported_release }
    }

    /// Construct the sole physical-page provider accepted by zsmalloc. # C: O(1)
    pub const fn new_movable(alloc_object_page: fn() -> Option<u64>, release_object_page: fn(u64),
                     page_ptr: fn(u64) -> Option<*mut u8>, try_lock_page: fn(u64) -> bool,
                     unlock_page: fn(u64) -> bool, register_movable_owner: fn(Ops) -> Result<OwnerId, MoveError>,
                     unregister_movable_owner: fn(OwnerId) -> Result<(), MoveError>, alloc_movable_page: fn(OwnerId) -> Option<u64>,
                     release_movable_page: fn(OwnerId, u64) -> bool) -> Self {
        Self { legacy_test_pages: false, alloc_object_page, release_object_page, page_ptr, try_lock_page, unlock_page, register_movable_owner, unregister_movable_owner, alloc_movable_page, release_movable_page }
    }
}

fn unsupported_register(_ops: Ops) -> Result<OwnerId, MoveError> { Err(MoveError::Permanent) }
fn unsupported_unregister(_owner: OwnerId) -> Result<(), MoveError> { Err(MoveError::Permanent) }
fn unsupported_alloc(_owner: OwnerId) -> Option<u64> { None }
fn unsupported_release(_owner: OwnerId, _pa: u64) -> bool { false }

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
    use movable::{MoveError, Ops, OwnerId};

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
    fn register_owner(_ops: Ops) -> Result<OwnerId, MoveError> { Ok(OwnerId { slot: 0, generation: 0 }) }
    fn unregister_owner(_owner: OwnerId) -> Result<(), MoveError> { Ok(()) }
    fn alloc_movable(_owner: OwnerId) -> Option<u64> { alloc_page() }
    fn release_movable(_owner: OwnerId, pa: u64) -> bool { release_page(pa); true }

    pub(super) fn install() {
        INSTALL.call_once(|| {
            install_page_provider(PageProvider::new_movable(
                alloc_page, release_page, page_ptr, try_lock_page, unlock_page,
                register_owner, unregister_owner, alloc_movable, release_movable,
            )).expect("install hosted zram PMM provider");
        });
    }
}

#[cfg(any(test, feature = "hosted"))]
/// Installs the explicit hosted PMM fixture before a zram/pool test creates
/// storage. Production builds never compile this provider. # C: O(1)
pub(crate) fn install_hosted_test_provider() { hosted::install(); }
