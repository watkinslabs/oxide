// `cachestat(2)` page-cache accounting contract (`struct cachestat` ABI).
//
// The syscall walks ONE address_space's index space over an inclusive page
// range and classifies every entry present there: a live cache page (with its
// dirty / writeback tags) or a shadow left behind by eviction (with its
// recency verdict). This module owns the range decode and the counters; the
// per-backend walk is [`crate::AddressSpaceOps::cachestat`], because only the
// backend knows its own index structure.
//
// Ungated: the range arithmetic (page rounding, `len == 0` meaning EOF, the
// overflow behavior of `off + len - 1`) is the part that silently
// off-by-ones, and the slot file it serves cannot be tested hosted.

/// `struct cachestat` — the five page counts the syscall writes back, in UAPI
/// field order.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct CachestatCounts {
    /// Pages present in the cache.
    pub nr_cache: u64,
    /// Cache pages carrying the dirty tag.
    pub nr_dirty: u64,
    /// Cache pages with writeback in flight.
    pub nr_writeback: u64,
    /// Indices holding an eviction shadow instead of a page.
    pub nr_evicted: u64,
    /// Shadows whose refault distance still fits the workingset.
    pub nr_recently_evicted: u64,
}

/// One index's page-cache entry as the walk observes it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PageState {
    /// A resident cache page and its two writeback-machine tags.
    Cache { dirty: bool, writeback: bool },
    /// An eviction shadow; `recent` is `workingset_test_recent`'s verdict.
    Evicted { recent: bool },
}

impl CachestatCounts {
    /// Fold `nr_pages` pages sharing one state into the counters. `nr_pages`
    /// is the covered-page count for a multi-page entry clipped to the
    /// requested range, so a large folio straddling a boundary contributes
    /// only its covered part. # C: O(1)
    pub fn account(&mut self, state: PageState, nr_pages: u64) {
        match state {
            PageState::Cache { dirty, writeback } => {
                self.nr_cache += nr_pages;
                if dirty { self.nr_dirty += nr_pages; }
                if writeback { self.nr_writeback += nr_pages; }
            }
            PageState::Evicted { recent } => {
                self.nr_evicted += nr_pages;
                if recent { self.nr_recently_evicted += nr_pages; }
            }
        }
    }

    /// The five counts in UAPI field order, for the single writeback loop the
    /// syscall shim runs. # C: O(1)
    pub const fn as_uapi(&self) -> [u64; CACHESTAT_FIELDS] {
        [self.nr_cache, self.nr_dirty, self.nr_writeback, self.nr_evicted, self.nr_recently_evicted]
    }
}

/// `struct cachestat` field count (its size is `CACHESTAT_FIELDS * 8`).
pub const CACHESTAT_FIELDS: usize = 5;

/// Inclusive page-index range one `cachestat` request covers.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CachestatRange {
    /// First page index, inclusive.
    pub first: u64,
    /// Last page index, inclusive. `u64::MAX` = to the end of the index space.
    pub last: u64,
}

impl CachestatRange {
    /// Decode `struct cachestat_range { off, len }`. `len == 0` means "to the
    /// end of the file", which the kernel expresses as the maximum index
    /// rather than a size lookup. `off + len - 1` is computed with wrapping
    /// arithmetic exactly as the kernel's unsigned arithmetic does, so a
    /// caller-supplied range that overflows produces a wrapped — possibly
    /// empty — range instead of a panic or a clamp the kernel does not apply.
    /// The byte range is NOT validated: the syscall rejects no `off`/`len`
    /// combination. # C: O(1)
    pub const fn from_bytes(off: u64, len: u64, page_shift: u32) -> CachestatRange {
        let first = off >> page_shift;
        let last = if len == 0 { u64::MAX } else { off.wrapping_add(len).wrapping_sub(1) >> page_shift };
        CachestatRange { first, last }
    }

    /// Is `idx` inside the inclusive range? An inverted range (a wrapped
    /// `off + len`) contains nothing. # C: O(1)
    pub const fn contains(&self, idx: u64) -> bool { idx >= self.first && idx <= self.last }

    /// Pages of an entry spanning `[entry_first, entry_first + nr_pages)` that
    /// fall inside the range — the clipping `filemap_cachestat` applies so a
    /// folio straddling either boundary contributes only its covered pages.
    /// `0` when the entry is entirely outside. # C: O(1)
    pub const fn covered(&self, entry_first: u64, nr_pages: u64) -> u64 {
        if nr_pages == 0 { return 0; }
        let entry_last = entry_first.saturating_add(nr_pages - 1);
        if entry_last < self.first || entry_first > self.last { return 0; }
        let lo = if entry_first > self.first { entry_first } else { self.first };
        let hi = if entry_last < self.last { entry_last } else { self.last };
        hi - lo + 1
    }
}

#[cfg(test)]
mod tests;
