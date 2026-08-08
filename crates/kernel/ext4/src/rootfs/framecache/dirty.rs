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
        let writeback = store.writeback.lock();
        pages.iter().filter(|(idx, page)| !dirty.contains(idx) && !writeback.contains_key(idx) && pmm::setup::frame_mapcount(page.pa) == 0).count()
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
pub fn flush_all_dirty() -> Result<(), ()> { flush_dirty(None) }

/// Flush the registered frame stores belonging to ONE mount — the
/// per-superblock scope `sync_fs` needs. `None` flushes every mount
/// (`msync(2)`, which names no filesystem).
///
/// `DIRTY_STORES` is process-wide across every ext4 mount, so the unscoped walk
/// made `syncfs(fd on /home)` write back `/`'s dirty frames and then commit
/// whichever mount happened to be first in the list — a different filesystem
/// from the one the caller named, and a different one from the `commit_batch`
/// its own `sync_fs` goes on to run.
/// # C: O(N_stores · N_dirty)
pub fn flush_dirty(only: Option<&alloc::sync::Arc<crate::Mount>>) -> Result<(), ()> {
    let (mut failed, mounts) = writeback_dirty_inner(only.map(|m| &**m));
    // Durability point (sync/syncfs/msync): drain the running batch of EVERY
    // mount whose frames were just staged — one arbitrary mount is not enough
    // when the walk covered several.
    for m in &mounts { if m.commit_batch().is_err() { failed = true; } }
    if failed { Err(()) } else { Ok(()) }
}

/// The data half of [`flush_dirty`] with no commit behind it: get every dirty
/// page of these mounts onto the device and stop there.
///
/// This is what `data=ordered` needs, and it is why the two halves are
/// separate: the ordering guarantee is "data BEFORE the metadata commit", so
/// the caller is the commit, and a data flush that finished by committing would
/// be calling the very thing it runs ahead of.
/// # C: O(N_stores · N_dirty)
pub fn writeback_dirty(only: Option<&crate::Mount>) -> Result<(), ()> {
    let (failed, _) = writeback_dirty_inner(only);
    if failed { Err(()) } else { Ok(()) }
}

/// Write back the selected stores; report failure and the mounts covered.
/// # C: O(N_stores · N_dirty)
fn writeback_dirty_inner(only: Option<&crate::Mount>)
    -> (bool, Vec<alloc::sync::Arc<crate::Mount>>)
{
    let snapshot: Vec<Weak<Ext4FrameStore>> = { DIRTY_STORES.lock().iter().cloned().collect() };
    let mut failed = false;
    let mut mounts: Vec<alloc::sync::Arc<crate::Mount>> = Vec::new();
    for w in &snapshot {
        let Some(s) = w.upgrade() else { continue };
        if let Some(m) = only {
            // Identity by ADDRESS, not by owning `Arc`: the ordered-data caller
            // is a `&Mount` inside a commit and holds no `Arc` of itself.
            if !core::ptr::eq(alloc::sync::Arc::as_ptr(&s.st.mount), m as *const crate::Mount) {
                continue;
            }
        }
        if !mounts.iter().any(|m| alloc::sync::Arc::ptr_eq(m, &s.st.mount)) {
            mounts.push(s.st.mount.clone());
        }
        if s.writeback().is_err() { failed = true; }
    }
    DIRTY_STORES.lock().retain(|w| w.strong_count() > 0);
    (failed, mounts)
}
