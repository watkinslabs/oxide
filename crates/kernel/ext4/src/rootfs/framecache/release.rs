// Terminal frame-store release and its cache-accounting transition.

use super::Ext4FrameStore;

impl Drop for Ext4FrameStore {
    /// Flush then release every inode-owned resident frame. # C: O(N_pages)
    fn drop(&mut self) {
        if !self.dirty.lock().is_empty() { let _ = self.writeback(); }
        let g = self.pages.lock();
        for (_idx, page) in g.iter() {
            // SAFETY: each frame's remaining object reference belongs to this store.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(page.pa); }
            cgroup::uncharge_memory(page.cgid, cgroup::MemoryKind::File, hal::PAGE_SIZE_BYTES);
        }
        vfs::memory_accounting::account_file_cache_remove(g.len() as u64);
    }
}
