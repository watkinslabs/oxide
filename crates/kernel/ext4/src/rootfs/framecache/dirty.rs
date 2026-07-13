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
