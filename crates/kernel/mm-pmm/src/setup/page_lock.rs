//! PMM page-lock slow path.
//!
//! A page lock is an atomic flag on `PageMeta`, but it is not a spin lock:
//! a contended process-context acquisition parks on a bounded hash table and
//! retries after the matching unlock makes the bit visible.

use sched::live::{wait_event_uninterruptible_prepare, WaitList};

use super::metadata::page_meta;

const PAGE_WAIT_TABLE_BITS: usize = 8;
const PAGE_WAIT_TABLE_SIZE: usize = 1 << PAGE_WAIT_TABLE_BITS;
const PAGE_WAIT_TABLE_MASK: usize = PAGE_WAIT_TABLE_SIZE - 1;

static PAGE_WAIT_TABLE: [WaitList; PAGE_WAIT_TABLE_SIZE] =
    [const { WaitList::new() }; PAGE_WAIT_TABLE_SIZE];

fn pfn(pa: u64) -> hal::Pfn { hal::Pfn(pa / hal::PAGE_SIZE_BYTES) }

fn wait_bucket(pfn: hal::Pfn) -> &'static WaitList {
    &PAGE_WAIT_TABLE[pfn.0 as usize & PAGE_WAIT_TABLE_MASK]
}

fn wait_for_lock(wait: &WaitList, meta: &crate::PageMetaArr, page: hal::Pfn,
                 mut try_lock: impl FnMut() -> bool) -> bool {
    if try_lock() { return true; }
    // SAFETY: every caller is process context and has dropped all locks that
    // can be needed by the page-lock holder before entering this slow path.
    unsafe { wait_event_uninterruptible_prepare(wait,
        || { let _ = meta.set_page_waiters(page); },
        || try_lock()); }
    true
}

/// Try to acquire a PMM-managed page's migration/I/O lock. A missing metadata
/// slot is not a managed page and therefore cannot participate in migration.
/// # C: O(1)
pub fn try_lock_page(pa: u64) -> bool {
    let pfn = pfn(pa); let Some(meta) = page_meta() else { return false; };
    let locked = meta.try_lock_page(pfn).unwrap_or(false);
    #[cfg(feature = "debug-watchdog")]
    if locked {
        meta.note_page_lock_owner(pfn, sched::live::current().map(|task| task.tid).unwrap_or(0));
    }
    locked
}

/// Acquire a PMM page lock, sleeping rather than spinning if it is contended.
/// The caller must be in process context and must not hold a lock required by
/// the current page-lock owner.
/// # Ctx: process
/// # Sleeps: yes
/// # C: O(1) uncontended; O(N wakeups) contended
pub fn lock_page(pa: u64) -> bool {
    let page = pfn(pa);
    let Some(meta) = page_meta() else { return false; };
    if meta.get(page).is_none() { return false; }
    wait_for_lock(wait_bucket(page), meta, page, || try_lock_page(pa))
}

fn unlock(meta: &crate::PageMetaArr, page: hal::Pfn) -> bool {
    #[cfg(feature = "debug-watchdog")]
    meta.clear_page_lock_owner(page);
    let unlocked = meta.unlock_page(page).unwrap_or(false);
    if unlocked && meta.page_has_waiters(page).unwrap_or(false) {
        let wait = wait_bucket(page);
        wait.wake_all();
        if !wait.has_waiters() { let _ = meta.clear_page_waiters(page); }
    }
    unlocked
}

/// Release a PMM page lock and wake contending page-lock waiters.
/// # Ctx: process
/// # C: O(N bucket waiters)
pub fn unlock_page(pa: u64) -> bool {
    let page = pfn(pa); let Some(meta) = page_meta() else { return false; };
    unlock(meta, page)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn contended_acquire_uses_the_shared_wait_loop() {
        let wait = WaitList::new();
        let page = alloc::boxed::Box::leak(alloc::boxed::Box::new(crate::PageMeta::new()));
        let meta = crate::PageMetaArr::new(0, core::slice::from_ref(page));
        let tries = AtomicU32::new(0);
        assert!(wait_for_lock(&wait, &meta, hal::Pfn(0), || tries.fetch_add(1, Ordering::Relaxed) != 0));
        assert_eq!(tries.load(Ordering::Relaxed), 2);
        assert!(meta.page_has_waiters(hal::Pfn(0)).unwrap());
    }

    #[test]
    fn page_lock_table_is_bounded_and_stable() {
        assert_eq!(wait_bucket(hal::Pfn(7)) as *const _, wait_bucket(hal::Pfn(7)) as *const _);
        assert_eq!(wait_bucket(hal::Pfn(7)) as *const _, wait_bucket(hal::Pfn(7 + PAGE_WAIT_TABLE_SIZE as u64)) as *const _);
    }

    #[test]
    fn unlock_clears_the_page_lock_bit_before_waking() {
        let page = alloc::boxed::Box::leak(alloc::boxed::Box::new(crate::PageMeta::new()));
        let arr = crate::PageMetaArr::new(0, core::slice::from_ref(page));
        assert_eq!(arr.try_lock_page(hal::Pfn(0)), Some(true));
        arr.set_page_waiters(hal::Pfn(0)).unwrap();
        assert!(unlock(&arr, hal::Pfn(0)));
        assert_eq!(arr.try_lock_page(hal::Pfn(0)), Some(true));
        assert!(!arr.page_has_waiters(hal::Pfn(0)).unwrap());
    }
}
