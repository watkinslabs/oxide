// `cachestat(2)` walk over one regular-file frame store (Linux
// `filemap_cachestat` over `mapping->i_pages`).

use vfs::{CachestatCounts, CachestatRange, PageState};

use super::Ext4FrameStore;

impl Ext4FrameStore {
    /// Classify every index this store holds inside `range`. Resident frames
    /// are cache pages carrying this store's dirty tag; shadow entries are
    /// evictions, judged recent by the nonresident-age refault distance.
    ///
    /// `nr_writeback` stays zero, and that is the true count rather than a
    /// missing one: this store has no in-flight writeback state to observe —
    /// a flush copies the frame to the device synchronously inside the
    /// requesting call, so no index is ever left tagged "writeback pending"
    /// for another task's syscall to see.
    ///
    /// Every page here is a single frame, so an entry never straddles a range
    /// boundary; the walk still clips through the range so the accounting is
    /// the same shape a multi-page entry would need.
    /// # C: O(entries in range)
    pub(crate) fn cachestat(&self, range: CachestatRange) -> CachestatCounts {
        let mut cs = CachestatCounts::default();
        if range.first > range.last { return cs; }
        // Snapshot the resident indices and their dirty tags under the two
        // store locks, then release both: the recency test reads the reclaim
        // LRU under its own lock, which must not nest inside these.
        let resident: alloc::vec::Vec<(u64, bool)> = {
            let pages = self.pages.lock();
            let dirty = self.dirty.lock();
            pages.range(range.first..=range.last).map(|(&idx, _)| (idx, dirty.contains(&idx))).collect()
        };
        for (idx, dirty) in resident {
            cs.account(PageState::Cache { dirty, writeback: false }, range.covered(idx, 1));
        }
        let shadows: alloc::vec::Vec<(u64, u64)> = {
            let g = self.shadows.lock();
            g.range(range.first..=range.last).map(|(&idx, &stamp)| (idx, stamp)).collect()
        };
        let age = pmm::reclaim::nonresident_age();
        let size = pmm::reclaim::workingset::file_workingset_size();
        for (idx, stamp) in shadows {
            let recent = pmm::reclaim::workingset::test_recent_sized(stamp, age, size);
            cs.account(PageState::Evicted { recent }, range.covered(idx, 1));
        }
        cs
    }
}
