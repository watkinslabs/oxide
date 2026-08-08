// `address_space` (Linux `struct inode.i_mapping`) — the per-inode page
// cache contract per `17§4` / `17§5`. ONE object per inode, keyed by page
// index, shared by every mapper of that inode (Linux `i_mapping`). This is
// the object that makes two `mmap()`s of the same inode see the same pages:
// the cache lives on the inode, not on the per-mmap backing.
//
// Trait only — the frame-backed concrete type lives in a pmm-capable crate
// (`fs` tmpfs/shmem; ext4 regular files). `vfs` deps are `hal`+`sync` (no
// pmm), so the address_space contract names no pmm types: page frames are
// raw physical addresses (`u64`), I/O is over byte slices. This keeps the
// frame store out of the foundational crate while letting the page-fault
// handler and `InodeFileBacking` route through one per-inode object.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use crate::types::KResult;

/// A cache frame acquired for MAP_SHARED. `map_ref_held` is true only when
/// the mapping owner retained the exact PTE reference while its cache lock was
/// held; reclamation may never race that handoff.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SharedFrame { pub pa: u64, pub map_ref_held: bool }

/// `address_space->flags` writeback-error bits (Linux `enum mapping_flags`)
/// — recorded by `mapping_set_error` and harvested by
/// `filemap_check_errors` so a deferred writeback failure surfaces at the next
/// `fsync`/`close`. Exposed as OR-able masks (the kernel keeps them as bit
/// numbers tested via `test_bit`; the mask form is the idiomatic Rust shape).
/// `AS_EIO` is a generic write-back I/O error; `AS_ENOSPC` is the
/// out-of-space variant `fsync` maps to `ENOSPC`.
pub const AS_EIO:    u32 = 1 << 0;
pub const AS_ENOSPC: u32 = 1 << 1;

/// Dirty-page tag set for one address space (Linux page-cache xarray
/// `PAGECACHE_TAG_DIRTY`). Tracks which page indices hold modifications not yet
/// written back, so `writeback`/`fsync` flush exactly the dirty pages and
/// `truncate` drops their tags. State only — the embedding inode serialises
/// access under its own mapping lock (Linux `xa_lock(&mapping->i_pages)`), so
/// the methods take `&mut self` and the foundational `vfs` crate stays
/// lock-policy-free. tmpfs/ext4 embed one per regular-file inode.
#[derive(Default)]
pub struct DirtyPages {
    /// Dirty page indices in ascending order (BTreeSet iterates sorted, which
    /// is the writeback order the flush wants).
    dirty: BTreeSet<u64>,
    /// `mapping->flags` AS_* error accumulator (sticky until harvested).
    err: u32,
}

impl DirtyPages {
    /// Empty dirty set (a freshly faulted-in clean mapping). # C: O(1)
    pub const fn new() -> DirtyPages { DirtyPages { dirty: BTreeSet::new(), err: 0 } }

    /// `filemap_dirty_folio` — tag page `idx` dirty. Returns `true` iff it was
    /// previously clean (Linux returns whether the dirty state changed, the
    /// signal `__mark_inode_dirty` keys on). # C: O(log N)
    pub fn set_dirty(&mut self, idx: u64) -> bool { self.dirty.insert(idx) }

    /// Clear page `idx`'s dirty tag (writeback completion /
    /// `folio_clear_dirty_for_io`). Returns `true` iff it had been dirty.
    /// # C: O(log N)
    pub fn clear_dirty(&mut self, idx: u64) -> bool { self.dirty.remove(&idx) }

    /// Is page `idx` currently dirty? # C: O(log N)
    pub fn is_dirty(&self, idx: u64) -> bool { self.dirty.contains(&idx) }

    /// Count of dirty pages (Linux `mapping->nrpages` dirty subset — the
    /// writeback/throttle accounting input). # C: O(1)
    pub fn count(&self) -> usize { self.dirty.len() }

    /// No dirty pages outstanding (the `fsync` fast-path / clean-inode test).
    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.dirty.is_empty() }

    /// Drop dirty tags for every page index in the half-open range
    /// `[start_idx, end_idx)` (Linux `truncate_inode_pages_range`, which clears
    /// the dirty tag as it evicts). `end_idx == u64::MAX` clears from `start_idx`
    /// to the end. # C: O(N in range)
    pub fn clear_range(&mut self, start_idx: u64, end_idx: u64) {
        self.dirty.retain(|&i| i < start_idx || i >= end_idx);
    }

    /// `write_cache_pages` collection step: return the dirty page indices in
    /// ascending (writeback) order and clear the tags — the writer then flushes
    /// each and, on failure, re-marks via `set_dirty` / records `set_error`.
    /// # C: O(N dirty)
    pub fn take_writeback(&mut self) -> Vec<u64> {
        core::mem::take(&mut self.dirty).into_iter().collect()
    }

    /// `__filemap_fdatawrite_range` collection step — the range-limited form of
    /// [`Self::take_writeback`] behind `sync_file_range(2)` and a range `fsync`
    /// (Linux `wbc->range_start`/`range_end`). Returns the dirty page indices in
    /// the half-open range `[start_idx, end_idx)` in ascending writeback order
    /// and clears ONLY those tags — dirty pages outside the window stay dirty
    /// for a later flush, so a small `sync_file_range` does not silently clean
    /// (and thus fail to ever write back) the rest of the file. `end_idx ==
    /// u64::MAX` collects from `start_idx` to the end. # C: O(N dirty in range)
    pub fn take_writeback_range(&mut self, start_idx: u64, end_idx: u64) -> Vec<u64> {
        let hit: Vec<u64> = self.dirty.range(start_idx..end_idx).copied().collect();
        for i in &hit { self.dirty.remove(i); }
        hit
    }

    /// `mapping_set_error`: record a deferred
    /// writeback error. `ENOSPC` sets `AS_ENOSPC`, any other nonzero errno sets
    /// the generic `AS_EIO`; `0`/success is a no-op. The flag is sticky until
    /// [`Self::check_errors`] harvests it. `errno` is the POSIX positive code
    /// (e.g. `28` for ENOSPC). # C: O(1)
    pub fn set_error(&mut self, errno: i32) {
        if errno == 0 { return; }
        if errno == ENOSPC { self.err |= AS_ENOSPC; } else { self.err |= AS_EIO; }
    }

    /// `filemap_check_errors`: test-and-clear BOTH
    /// accumulated writeback errors in one pass, returning the errno `fsync`/
    /// `close` reports. Matching Linux, the `AS_EIO` assignment runs last, so
    /// `EIO` is the return value when both flags are set, `ENOSPC` when only it
    /// is, `0` when clean — but either way both bits are cleared. # C: O(1)
    pub fn check_errors(&mut self) -> i32 {
        let mut ret = 0;
        if self.err & AS_ENOSPC != 0 { self.err &= !AS_ENOSPC; ret = ENOSPC; }
        if self.err & AS_EIO != 0 { self.err &= !AS_EIO; ret = EIO; }
        ret
    }
}

/// POSIX `ENOSPC` / `EIO` positive codes (Linux uapi) — the writeback-error
/// pair `set_error`/`check_errors` translate to/from the AS_* flags.
const ENOSPC: i32 = 28;
const EIO:    i32 = 5;

/// Per-inode address space (Linux `struct address_space`, reached via
/// `inode->i_mapping`). Implemented by inodes whose data lives in
/// persistent page-cache frames (tmpfs/shmem now; regular files as ext4
/// opts in). All mappers of one inode share one implementor.
pub trait AddressSpaceOps: Send + Sync {
    /// `MAP_SHARED` cache frame for page-aligned file offset `off`,
    /// allocating + fill-from-backing on a cache miss. `Some(pa)` =
    /// the persistent PMM frame a shared mapping installs directly, so
    /// user writes alias the inode's own storage and propagate to
    /// `read`/`write` + every other mapper (Linux shmem / page cache).
    /// `None` only for an address space that cannot hand out a mappable
    /// frame. # C: O(log N_pages)
    fn shared_frame(&self, off: u64) -> KResult<Option<SharedFrame>>;

    /// Retained, already-resident cache frame for fault-around. This lookup
    /// MUST NOT allocate, swap in, or issue backing I/O: `None` is the normal
    /// cache-miss answer. A returned frame carries one prospective PTE
    /// reference, released by the caller if the PTE is not installed.
    /// # C: O(log N_pages)
    fn fault_around_frame(&self, off: u64) -> KResult<Option<SharedFrame>> {
        let _ = off;
        Ok(None)
    }

    /// Whether the object holds this page-aligned offset in ANY form —
    /// resident, mid-migration, or evicted — as opposed to a hole it has never
    /// held contents for. Non-faulting: no allocation, no swap-in, no I/O.
    ///
    /// Distinct from [`fault_around_frame`](Self::fault_around_frame), which
    /// answers the narrower "can a PTE be installed right now": a page that
    /// was evicted is one the object still holds, and reporting it as a hole
    /// misclassifies a fault over it.
    /// # C: O(log N_pages)
    fn backing_holds_page(&self, _off: u64) -> bool { false }

    /// Copy bytes from the cache starting at file offset `off` into `dst`
    /// (the `MAP_PRIVATE` / read-fault fill, Linux `do_cow_fault`'s read
    /// of the cache page before the private COW copy). Short reads
    /// zero-fill the tail at the caller. Errors retain VFS errno.
    /// # C: O(dst.len)
    fn read_at(&self, off: u64, dst: &mut [u8]) -> KResult<usize>;

    /// Flush dirty cache pages to the backing store (`msync`/`fsync`).
    /// No-op for shmem (pages ARE the store). # C: O(N_dirty)
    fn writeback(&self) -> Result<(), ()> { Ok(()) }

    /// Flush dirty cache pages overlapping the byte range `[start, end)` to the
    /// backing store (Linux `filemap_write_and_wait_range`, the engine behind a
    /// range `fsync`/`fdatasync` and `sync_file_range`). `end == u64::MAX` means
    /// "to EOF". The default flushes the WHOLE file — a correct superset of any
    /// range — by forwarding to [`AddressSpaceOps::writeback`]; a backend that
    /// tracks per-page dirtiness (via [`DirtyPages::take_writeback_range`])
    /// overrides this to flush only the dirty pages intersecting the range, so a
    /// `sync_file_range` over a small window does not rewrite the entire file.
    /// # C: O(N_dirty in range)
    fn writeback_range(&self, start: u64, end: u64) -> Result<(), ()> {
        let _ = (start, end);
        self.writeback()
    }

    /// Populate the cache for `nr_pages` pages starting at page index `start`,
    /// WITHOUT copying anything out (Linux `page_cache_ra_unbounded` /
    /// `force_page_cache_readahead`). This is the submit half of readahead: the
    /// window [`crate::File::ra_ondemand`] computes, and what
    /// `POSIX_FADV_WILLNEED` / `readahead(2)` ask for.
    ///
    /// The default fills page by page through [`AddressSpaceOps::read_at`] into
    /// a scratch buffer it discards — correct, and exactly what the callers used
    /// to open-code. A backend that can fetch a run in one device operation
    /// overrides this; that is the whole point of having the window.
    ///
    /// Best-effort: a failure to populate is not reported, because readahead is
    /// a hint and the demand fault will surface any real error.
    /// # C: O(nr_pages) reads
    fn readahead(&self, start: u64, nr_pages: u64) {
        if nr_pages == 0 { return; }
        let pg = crate::file::readahead::PAGE_SIZE;
        let size = self.size();
        let mut scratch = alloc::vec![0u8; pg as usize];
        for i in 0..nr_pages {
            let off = (start + i).saturating_mul(pg);
            if off >= size { break; }
            if self.mincore_page(off) { continue; }
            if self.read_at(off, &mut scratch).is_err() { break; }
        }
    }

    /// `filemap_cachestat` — classify every entry this address space holds in
    /// the inclusive page-index range and fold it into the `cachestat(2)`
    /// counters. Only entries that EXIST are visited (never the whole index
    /// space), so a `len == 0` request over a sparse file is O(entries), not
    /// O(2^52). Multi-page entries clip to the range via
    /// [`crate::CachestatRange::covered`].
    ///
    /// Default: all-zero, the honest answer for an address space that keeps no
    /// enumerable index (its pages are computed on demand and never evicted,
    /// so no page is "in the cache" in the sense the syscall reports).
    /// # C: O(entries in range)
    fn cachestat(&self, range: crate::CachestatRange) -> crate::CachestatCounts {
        let _ = range;
        crate::CachestatCounts::default()
    }

    /// Non-faulting `mincore(2)` query for a page-aligned file offset. This is
    /// the Linux `filemap_get_entry()` leg: report already-resident cache pages
    /// without allocating or reading from backing storage. # C: O(log N_pages)
    fn mincore_page(&self, off: u64) -> bool { let _ = off; false }

    /// Evict resident cache frames whose whole page lies in the byte range
    /// `[start, end)` (Linux `truncate_inode_pages_range`). A page is a
    /// victim only when fully covered: index `i` (page `[i·PG, (i+1)·PG)`)
    /// drops iff `i·PG >= start && (i+1)·PG <= end`; a page straddling
    /// either boundary is retained (the caller zeroes the partial bytes, as
    /// `truncate` zeroes the last page's tail). `end == u64::MAX` means
    /// "to EOF" — drop every resident page at/after `start`'s rounded-up
    /// page. Returns the count of whole frames dropped. Default `0` = an
    /// address space with no evictable resident frames (frames computed on
    /// demand / no droppable store). Callers invoke this on
    /// `ftruncate`/hole-punch so a later refault re-reads zeros, never
    /// stale post-EOF bytes. # C: O(pages in range)
    fn invalidate_range(&self, start: u64, end: u64) -> usize { let _ = (start, end); 0 }

    /// Try to evict the resident cache pages in the INCLUSIVE page-index range
    /// `[start_idx, end_idx]`, skipping every page that is not safely
    /// droppable (Linux `invalidate_mapping_pages`). This is the
    /// `POSIX_FADV_DONTNEED` primitive, and it is a HINT: a page is left alone
    /// when it is
    ///
    /// - MAPPED into any address space — its residency is not this cache's to
    ///   revoke, and the mapper must keep seeing the same frame every other
    ///   mapper and every `read`/`write` of the inode sees;
    /// - DIRTY — the data is not yet on the backing store, and eviction would
    ///   lose it (the caller flushes first, but a flush is asynchronous, so a
    ///   page may still be dirty here); or
    /// - under WRITEBACK — the flush owns the frame until it completes.
    ///
    /// This is the difference from [`AddressSpaceOps::invalidate_range`], which
    /// is `truncate`'s unconditional removal: after a truncate the bytes are
    /// GONE, so retaining a mapped page would serve stale post-EOF data, while
    /// after a DONTNEED hint the bytes still exist and every mapper must keep
    /// aliasing one frame. Wiring DONTNEED to the truncate primitive silently
    /// unshares a live `MAP_SHARED` mapping: the next mapper refills a NEW
    /// frame from disk and the two mappings stop seeing each other's writes.
    ///
    /// Returns the count of indices whose contents were invalidated. Default
    /// `0` — an address space with no droppable resident frames, which is also
    /// the honest answer for one whose pages ARE its storage (dropping them
    /// would lose data, so nothing is evictable). Note the default does NOT
    /// forward to `invalidate_range`: an unconditional drop is never a valid
    /// implementation of a best-effort one. # C: O(pages in range)
    fn try_invalidate_pages(&self, start_idx: u64, end_idx: u64) -> usize {
        let _ = (start_idx, end_idx);
        0
    }

    /// Optional backing-owned MAP_SHARED pageout. `None` preserves generic
    /// file-cache eviction; tmpfs returns its exact migration transaction.
    /// # C: O(pages in range)
    fn madvise_pageout(&self, off: u64, len: u64) -> Option<KResult<usize>> {
        let _ = (off, len);
        None
    }

    /// The backend half of `fsync` for this address_space: commit the metadata
    /// describing the pages [`Self::writeback_range`] just wrote and issue the
    /// device barrier (for ext4: the journal transaction carrying this inode,
    /// then `blkdev_issue_flush`).
    ///
    /// This exists because `msync(MS_SYNC)` and inode eviction reach an
    /// address_space through a VMA, which carries no open file description, so
    /// `f_op->fsync(struct file *)` is unreachable — Linux gets there via
    /// `vma->vm_file`. Same work, same ordering (the caller runs writeback
    /// first; see [`crate::File::vfs_fsync_range`]), reached from the mapping.
    ///
    /// Default `Ok(())` is correct for shmem/tmpfs: the pages ARE the store, so
    /// there is nothing behind them to commit. `Err` is a REAL durability
    /// failure and must not be swallowed. # C: O(journal tx) + one barrier
    fn sync_backing(&self) -> Result<(), ()> { Ok(()) }

    /// Whether these pages ARE the object's storage rather than a cache of
    /// something durable behind it. A userfaultfd minor-fault registration is
    /// only meaningful over such an address space, where "already resident in
    /// the backing but absent from the page table" is a real state.
    /// # C: O(1)
    fn is_shmem(&self) -> bool { false }

    /// Logical size (Linux `i_size`) the cache reflects. # C: O(1)
    fn size(&self) -> u64;
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use super::{AddressSpaceOps, SharedFrame};
    use crate::inode::InodeBuilder;
    use crate::inode_ops::{default_inode_ops, mk_mode};
    use crate::file_ops::default_file_ops;
    use crate::types::{FileType, KResult};

    const PG: u64 = 4096;

    // A toy address_space: page idx -> a deterministic "frame" pa, shared by
    // every mapper. Models the per-inode page cache without pmm.
    struct ToyMapping;
    impl AddressSpaceOps for ToyMapping {
        fn shared_frame(&self, off: u64) -> KResult<Option<SharedFrame>> {
            Ok(Some(SharedFrame { pa: 0x10_0000 + (off / PG) * PG, map_ref_held: false }))
        }
        fn read_at(&self, _off: u64, dst: &mut [u8]) -> KResult<usize> {
            for b in dst.iter_mut() { *b = 0xAB; } Ok(dst.len())
        }
        fn size(&self) -> u64 { 8192 }
    }

    // Inode WITH an i_mapping — `mmap_shared_frame` must forward to it (the
    // `FileOps::mmap_shared_frame` default routes through `inode.i_mapping()`).
    fn make_mapped_inode() -> crate::InodeRef {
        InodeBuilder::new(1, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
            .size(8192).mapping(Arc::new(ToyMapping)).build()
    }

    // Inode WITHOUT an i_mapping — default None on both hooks.
    fn make_plain_inode() -> crate::InodeRef {
        InodeBuilder::new(2, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
    }

    // The wiring contract: `mmap_shared_frame` forwards through `i_mapping`.
    #[test]
    fn mmap_shared_frame_forwards_through_i_mapping() {
        let i = make_mapped_inode();
        // Same offset → same frame as the address_space hands out (one cache).
        assert_eq!(i.mmap_shared_frame(0), i.i_mapping().unwrap().shared_frame(0));
        assert_eq!(i.mmap_shared_frame(PG).map(|f| f.map(|f| f.pa)), Ok(Some(0x10_0000 + PG)));
        // Repeated calls are stable (shared, not per-call).
        assert_eq!(i.mmap_shared_frame(0), i.mmap_shared_frame(0));
    }

    // No i_mapping → no shareable frame (MAP_PRIVATE copy path upstream).
    #[test]
    fn plain_inode_has_no_mapping() {
        let i = make_plain_inode();
        assert!(i.i_mapping().is_none());
        assert_eq!(i.mmap_shared_frame(0), Ok(None));
    }
}
