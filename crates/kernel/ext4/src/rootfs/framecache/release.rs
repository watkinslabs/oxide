// Terminal frame-store release and its cache-accounting transition.

use core::sync::atomic::Ordering;

use super::Ext4FrameStore;

impl Ext4FrameStore {
    /// Linux final-inode page-cache teardown: reject later writeback, wait for
    /// already-running writeback, then discard every resident/dirty page while
    /// the orphan still owns its blocks.  `ext4_evict_inode` calls this before
    /// truncating and freeing the inode slot. # C: O(N_pages + active I/O)
    pub(crate) fn discard_for_eviction(&self) {
        self.evicting.store(true, Ordering::Release);
        // SAFETY: eviction runs in process context after it has closed new
        // writeback admission and holds no page-cache lock across the wait.
        let _ = unsafe { sched::live::wait_event_uninterruptible(&self.writeback_wait,
            || self.active_writebacks.load(Ordering::Acquire) == 0) };
        self.invalidate_range(0, u64::MAX);
    }
}

impl Drop for Ext4FrameStore {
    /// Flush then release every inode-owned resident frame. # C: O(N_pages)
    fn drop(&mut self) {
        // A linked inode's final cache drop remains a durability path.  An
        // unlinked inode was already discarded by `discard_for_eviction`; it
        // must never write through an inode number that may now name another
        // object.
        if !self.evicting.load(Ordering::Acquire) && !self.dirty.lock().is_empty() {
            let _ = self.writeback();
        }
        let g = self.pages.lock();
        for (_idx, page) in g.iter() {
            // SAFETY: each frame's remaining object reference belongs to this store.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(page.pa); }
            cgroup::uncharge_memory(page.cgid, cgroup::MemoryKind::File, hal::PAGE_SIZE_BYTES);
        }
        vfs::memory_accounting::account_file_cache_remove(g.len() as u64);
    }
}
