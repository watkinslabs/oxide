// Asking a mapping what it holds without changing what it holds, and the
// best-effort eviction that is a HINT rather than a truncate.
//
// Both are surfaces `cache.rs` deliberately does not carry. `invalidate_range`
// there is truncate's UNCONDITIONAL removal: the caller has decided the bytes
// are gone, so a dirty page goes with them. The two below are the other half
// of the contract and neither may lose data:
//
// | ask | this file | `cache.rs` |
// |---|---|---|
// | the bytes are gone | — | `invalidate_range` |
// | drop what you can spare | `try_invalidate_range` | — |
// | what do you hold, and in what state | `page_states` | — |
//
// A DONTNEED hint that reached the truncate primitive would drop a page whose
// only copy of a write is in this cache.

use alloc::vec::Vec;

use crate::types::{InodeId, PAGE_BYTES};

use super::cache::PageCache;
use super::global;

/// One resident page's identity and the two states that decide whether it may
/// be dropped and how `cachestat(2)` classifies it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PageState {
    /// Page index within the inode (file offset / `PAGE_BYTES`).
    pub index: u64,
    /// Holds a modification the backing store does not have yet.
    pub dirty: bool,
    /// Handed to the writeback target and not yet completed.
    pub writeback: bool,
}

impl PageCache {
    /// `invalidate_mapping_pages` — drop the pages of `inode` in the INCLUSIVE
    /// index range that can be spared, reporting how many went.
    ///
    /// A page that is dirty, locked, or under writeback is LEFT ALONE: this is
    /// a hint (`POSIX_FADV_DONTNEED`), and the bytes still exist. Compare
    /// [`PageCache::invalidate_range`], which is truncate's unconditional
    /// removal and drops a dirty page with the rest.
    /// # C: O(pages in range)
    pub fn try_invalidate_range(&self, inode: InodeId, lo: u64, hi: u64) -> usize {
        if hi < lo { return 0; }
        let Some(map) = self.mapping(inode) else { return 0; };
        let mut dropped = 0usize;
        for index in map.keys_in_range(lo, hi.saturating_add(1)) {
            if map.evict(index).is_some() { dropped += 1; }
        }
        // Every page counted here was clean when it left, so the machine's
        // dirty total is untouched; only the resident total moves.
        global::account_cached(-(dropped as isize));
        dropped
    }

    /// What `inode` holds in the INCLUSIVE index range, in ascending order.
    ///
    /// Only pages that EXIST are reported, so a query over a sparse file costs
    /// what the file holds rather than what its index space could address —
    /// which is what makes an unbounded `cachestat(2)` range answerable at all.
    /// # C: O(pages in range)
    pub fn page_states(&self, inode: InodeId, lo: u64, hi: u64) -> Vec<PageState> {
        if hi < lo { return Vec::new(); }
        let Some(map) = self.mapping(inode) else { return Vec::new(); };
        let mut out = Vec::new();
        for index in map.keys_in_range(lo, hi.saturating_add(1)) {
            let Some(page) = map.get(index) else { continue };
            out.push(PageState { index, dirty: page.is_dirty(), writeback: page.is_writeback() });
        }
        out
    }

    /// Whether `inode` holds page `index` right now, without fetching it and
    /// without copying it out.
    ///
    /// Distinct from a lookup that hands back the page: an `mincore(2)` answer
    /// costs a tree walk, and paying a page copy for a one-bit question turns
    /// a cheap query over a large mapping into a memcpy per page.
    /// # C: O(height)
    pub fn holds(&self, inode: InodeId, index: u64) -> bool {
        let Some(map) = self.mapping(inode) else { return false; };
        map.get(index).is_some()
    }

    /// The page offset an index addresses. # C: O(1)
    pub fn offset_of(index: u64) -> u64 { index.wrapping_mul(PAGE_BYTES as u64) }
}
