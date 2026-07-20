use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use sync::{Spinlock, TaskList as TaskListClass};

use super::Ext4FrameStore;

/// Frame stores that have ever gone dirty (`MAP_SHARED` writable mappings).
/// `msync(2)` carries only an address, not an fd, and this crate must not walk
/// the VMA tree (mm-vmm owns that); so `sys_msync` flushes via this list. A
/// store registers itself on its FIRST dirty transition; dead `Weak`s are
/// pruned on flush. Flushing a superset of the requested range is POSIX-legal.
static DIRTY_STORES: Spinlock<Vec<Weak<Ext4FrameStore>>, TaskListClass> = Spinlock::new(Vec::new());
/// Every live regular-file mapping. This is the sole filesystem-side index
/// used by the PMM shrinker to return an isolated file-LRU page to its owner.
static ALL_STORES: Spinlock<Vec<Weak<Ext4FrameStore>>, TaskListClass> = Spinlock::new(Vec::new());

pub(super) fn register_store(s: &Arc<Ext4FrameStore>) {
    ALL_STORES.lock().push(Arc::downgrade(s));
    let _ = pmm::shrinker::register_shrinker(pmm::shrinker::Shrinker {
        count_objects: count_clean_pages,
        scan_objects: scan_clean_pages,
    });
}

fn count_clean_pages() -> usize {
    let stores: Vec<Weak<Ext4FrameStore>> = { ALL_STORES.lock().iter().cloned().collect() };
    let count = stores.iter().filter_map(Weak::upgrade).map(|store| {
        let pages = store.pages.lock();
        let dirty = store.dirty.lock();
        pages.iter().filter(|(idx, page)| !dirty.contains(idx) && pmm::setup::frame_mapcount(page.pa) == 0).count()
    }).sum();
    ALL_STORES.lock().retain(|store| store.strong_count() > 0);
    count
}

fn scan_clean_pages(target: usize) -> usize {
    let mut released = 0usize;
    // The inactive LRU can contain mapped/dirty pages whose state changed
    // after the advisory count. Bound attempts so a refused oldest folio is
    // put back once, never selected forever by an unbounded caller.
    let mut attempts = count_clean_pages().min(target);
    while released < target && attempts != 0 {
        attempts -= 1;
        let isolated = match pmm::setup::isolate_inactive_file_lru() {
            Ok(Some(isolated)) => isolated,
            Ok(None) | Err(_) => break,
        };
        let pa = isolated.pfn().0 * hal::PAGE_SIZE_BYTES;
        if !pmm::setup::try_lock_page(pa) {
            let _ = pmm::setup::putback_isolated_lru(isolated);
            continue;
        }
        let stores: Vec<Weak<Ext4FrameStore>> = { ALL_STORES.lock().iter().cloned().collect() };
        let victim = stores.iter().filter_map(Weak::upgrade).find_map(|store| store.evict_clean_locked(pa));
        if let Some(page) = victim {
            pmm::kassert!(pmm::setup::release_isolated_lru(isolated).is_ok(), "file reclaim release lru invariant");
            let _ = pmm::setup::unlock_page(pa);
            // SAFETY: cache entry and its sole object reference were removed;
            // mapcount was proven zero under the page lock.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(page.pa); }
            cgroup::uncharge_memory(page.cgid, cgroup::MemoryKind::File, hal::PAGE_SIZE_BYTES);
            released += 1;
        } else {
            let _ = pmm::setup::putback_isolated_lru(isolated);
            let _ = pmm::setup::unlock_page(pa);
        }
    }
    ALL_STORES.lock().retain(|store| store.strong_count() > 0);
    released
}

pub(super) fn register(s: &Arc<Ext4FrameStore>) {
    DIRTY_STORES.lock().push(Arc::downgrade(s));
}

/// Flush every registered (ever-dirtied) ext4 frame store. The `msync(2)`
/// durability path. Snapshots the list, releases the lock, then flushes
/// (block I/O outside the lock), and prunes dead entries. Returns `Err(())` if
/// ANY store's writeback failed — every store is still attempted (POSIX msync
/// flushes what it can), but the caller must surface `EIO` like `fsync`, not
/// silently swallow the loss. # C: O(N_stores · N_dirty)
pub fn flush_all_dirty() -> Result<(), ()> {
    let snapshot: Vec<Weak<Ext4FrameStore>> = { DIRTY_STORES.lock().iter().cloned().collect() };
    let mut failed = false;
    let mut mount: Option<alloc::sync::Arc<crate::Mount>> = None;
    for w in &snapshot {
        if let Some(s) = w.upgrade() {
            if mount.is_none() { mount = Some(s.st.mount.clone()); }
            if s.writeback().is_err() { failed = true; }
        }
    }
    DIRTY_STORES.lock().retain(|w| w.strong_count() > 0);
    // Durability point (sync/syncfs/msync): drain the running batch to disk so
    // the metadata the writebacks just staged is actually committed.
    if let Some(m) = mount { if m.commit_batch().is_err() { failed = true; } }
    if failed { Err(()) } else { Ok(()) }
}
