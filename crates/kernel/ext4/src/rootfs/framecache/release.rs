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
        let _ = unsafe { sched::live::wait_event_uninterruptible(&self.fill_wait,
            || self.active_fills.load(Ordering::Acquire) == 0) };
        self.invalidate_range(0, u64::MAX);
        // An unlinked inode's pages are discarded, not written, so the dirty
        // pin has nothing left to wait for and must not keep the store alive.
        self.unpin_if_clean();
    }
}

impl Drop for Ext4FrameStore {
    /// Flush then release every inode-owned resident frame. # C: O(N_pages)
    fn drop(&mut self) {
        // A final drop is guaranteed clean and writes nothing. A store holds a
        // strong reference to itself for exactly as long as it has dirty pages,
        // so reaching a zero count means the flusher, a sync or eviction has
        // already emptied the dirty set. Writing here instead meant a journal
        // commit ran on whichever stack released the last reference — a kernel
        // helper's ELF read, for instance — and carried the block layer down
        // with it.
        debug_assert!(self.evicting.load(Ordering::Acquire) || self.dirty.lock().is_empty(),
            "a dirty frame store must be pinned, so it cannot reach its final drop");
        let g = self.pages.lock();
        for (_idx, page) in g.iter() {
            // SAFETY: each frame's remaining object reference belongs to this store.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(page.pa); }
            cgroup::uncharge_memory(page.cgid, cgroup::MemoryKind::File, hal::PAGE_SIZE_BYTES);
        }
        vfs::memory_accounting::account_file_cache_remove(g.len() as u64);
    }
}
