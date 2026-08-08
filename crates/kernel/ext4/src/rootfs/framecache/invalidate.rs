// Page-cache range eviction: the UNCONDITIONAL removal `truncate`/hole-punch
// needs, and the BEST-EFFORT one `POSIX_FADV_DONTNEED` needs. Split out of
// `framecache.rs` per `08§7` (file-length cap); the parent owns state and the
// read/write hot paths.
//
// The two are not interchangeable. Truncate removes bytes, so a page that
// survived would serve stale post-EOF data; the hint removes nothing, so a
// page that is mapped, dirty, or under writeback must survive or the cache
// stops being the single object every mapper of the inode shares.

use alloc::vec::Vec;

use super::{Ext4FrameStore, FileCachePage, PG};

/// Is a resident page safely droppable by a best-effort invalidate? A page is
/// evictable only when nothing else owns its residency: no page table maps it,
/// no modification is waiting to reach the backing store, and no flush is in
/// flight over it. Any of the three makes the drop either a data loss or an
/// unshare of a live mapping, and the hint's contract is to SKIP such a page,
/// not to force it. # C: O(1)
pub(crate) fn evictable(mapped: bool, dirty: bool, under_writeback: bool) -> bool {
    !mapped && !dirty && !under_writeback
}

impl Ext4FrameStore {
    /// Drop+`dec_ref` every resident frame whose whole page lies in
    /// `[start, end)` (Linux `truncate_inode_pages_range`), clearing dirty
    /// tags. A page is a victim iff `i·PG >= start && (i+1)·PG <= end`; pass a
    /// page-floored `start` (e.g. truncate floors i_size) to also drop the
    /// partial page so a refault re-reads zeros. Returns frames dropped.
    /// # C: O(pages in range)
    pub(crate) fn invalidate_range(&self, start: u64, end: u64) -> usize {
        let lo = (start + PG as u64 - 1) / PG as u64;       // first FULLY-covered page
        let hi = if end == u64::MAX { u64::MAX } else { end / PG as u64 }; // exclusive
        if lo >= hi { return 0; }
        // Pick and unpublish each victim under ONE pages lock. Apart from
        // avoiding a double-free race with a second invalidate, this makes the
        // resident-cache counter follow exactly the entries actually removed.
        let victims: Vec<(u64, FileCachePage)> = {
            let mut g = self.pages.lock();
            let ids: Vec<u64> = g.range(lo..hi).map(|(&idx, _)| idx).collect();
            ids.into_iter().filter_map(|idx| g.remove(&idx).map(|page| (idx, page))).collect()
        };
        let n = victims.len();
        if n != 0 { vfs::memory_accounting::account_file_cache_remove(n as u64); }
        for (_, page) in victims {
            // SAFETY: frame removed from the store; release the inode's object
            // reference (a still-mapped peer's inc_ref keeps it alive until
            // that peer's AS teardown decs).
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(page.pa); }
            cgroup::uncharge_memory(page.cgid, cgroup::MemoryKind::File, PG as u64);
        }
        let mut d = self.dirty.lock();
        let dirty_ids: Vec<u64> = d.range(lo..hi).copied().collect();
        for idx in &dirty_ids { d.remove(idx); }
        drop(d);
        if !dirty_ids.is_empty() { vfs::memory_accounting::account_file_cache_discard_dirty(dirty_ids.len() as u64); }
        // Truncation removes the index entirely, shadow included — a refault
        // there is a new page, not a returning one.
        self.shadows.lock().retain(|&i, _| i < lo || i >= hi);
        #[cfg(feature = "debug-fillverify")]
        self.sums.lock().retain(|&i, _| i < lo || i >= hi);
        n
    }

    /// Best-effort eviction over the INCLUSIVE page-index range
    /// `[start_idx, end_idx]` (Linux `invalidate_mapping_pages`), the
    /// `POSIX_FADV_DONTNEED` primitive. Only clean, unmapped, not-under-
    /// writeback pages are dropped; anything else is left exactly as it was —
    /// no dirty tag cleared, no frame released, no shadow left behind. A page
    /// whose PMM page lock is held is skipped too: that lock means an I/O
    /// transaction owns the frame right now.
    ///
    /// No eviction shadow is recorded for what this drops. A shadow exists so
    /// reclaim can later judge a refault's recency; a page the OWNER asked to
    /// discard carries no such signal, and stamping one would let a DONTNEED
    /// loop mint unbounded workingset metadata for pages nobody wants.
    ///
    /// Returns the number of indices invalidated — frames dropped plus stale
    /// eviction shadows cleared, which is what the range no longer holds.
    /// # C: O(pages in range)
    pub(crate) fn try_invalidate_pages(&self, start_idx: u64, end_idx: u64) -> usize {
        if start_idx > end_idx { return 0; }
        let hi = end_idx.saturating_add(1); // exclusive
        let cands: Vec<(u64, u64)> = {
            let g = self.pages.lock();
            g.range(start_idx..hi).map(|(&idx, page)| (idx, page.pa)).collect()
        };
        let mut victims: Vec<(u64, FileCachePage)> = Vec::new();
        for (idx, pa) in cands {
            // A page under active I/O is skipped rather than waited on: the
            // advice is a hint, and blocking on it would make a "free some
            // memory" call as slow as the read it collides with.
            if !pmm::setup::try_lock_page(pa) { continue; }
            let mapped = pmm::setup::frame_mapcount(pa) != 0;
            let dirty = self.dirty.lock().contains(&idx);
            let under_writeback = self.writeback.lock().contains_key(&idx);
            let mut taken = None;
            if evictable(mapped, dirty, under_writeback) {
                let mut g = self.pages.lock();
                // Re-check under the pages lock: the frame may have been
                // replaced between the snapshot above and this removal.
                if g.get(&idx).map(|page| page.pa) == Some(pa) { taken = g.remove(&idx); }
            }
            let _ = pmm::setup::unlock_page(pa);
            if let Some(page) = taken {
                #[cfg(feature = "debug-fillverify")]
                self.sums.lock().remove(&idx);
                victims.push((idx, page));
            }
        }
        let n = victims.len();
        if n != 0 { vfs::memory_accounting::account_file_cache_remove(n as u64); }
        for (_, page) in victims {
            // SAFETY: frame unpublished from the store under its page lock, and
            // it was unmapped at that moment; release the store's own object
            // reference, which frees the frame only once every other reference
            // (a racing reader's transient pin) has also gone.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(page.pa); }
            cgroup::uncharge_memory(page.cgid, cgroup::MemoryKind::File, PG as u64);
        }
        // Stale shadows in the range are cleared and counted: the caller has
        // declared it wants nothing from this range, history included.
        let shadows_cleared = {
            let mut s = self.shadows.lock();
            let ids: Vec<u64> = s.range(start_idx..hi).map(|(&i, _)| i).collect();
            for i in &ids { s.remove(i); }
            ids.len()
        };
        n + shadows_cleared
    }
}

#[cfg(test)]
mod tests {
    use super::evictable;

    /// A clean, unmapped, quiescent page is the only droppable one. The three
    /// refusals are each a distinct defect if dropped: evicting a MAPPED page
    /// unshares a live `MAP_SHARED` mapping (the next mapper refills a new
    /// frame and the two stop aliasing), evicting a DIRTY page loses the
    /// modification, and evicting one under WRITEBACK pulls the frame out from
    /// under an in-flight flush. # C: O(1)
    #[test]
    fn only_clean_unmapped_quiescent_pages_are_evictable() {
        assert!(evictable(false, false, false));
        assert!(!evictable(true, false, false));
        assert!(!evictable(false, true, false));
        assert!(!evictable(false, false, true));
        // Any combination containing a refusal is a refusal.
        assert!(!evictable(true, true, true));
        assert!(!evictable(true, false, true));
    }
}
