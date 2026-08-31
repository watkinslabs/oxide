// ext4 per-inode frame-backed page store (D8). Mirrors the tmpfs/shmem
// `TmpfsFileData.pages` model (`fs/tmpfs.rs:174`): a regular file's data lives
// in PMM page FRAMES (`page_idx -> pa`), not a `Vec<u8>`. This is the object
// that makes `read(2)`, `write(2)`, and a `MAP_SHARED` mmap of one ext4 inode
// all alias the SAME frames, so writes propagate every direction (Linux page
// cache). Unlike tmpfs, a miss FILLS the frame from disk
// (`Mount::read_file_block`) rather than zeroing, and the inode's `Drop`
// `dec_ref`s every frame back to the buddy.
//
// Persistence: `read`/`write` go write-through to disk via the existing
// `Mount::write_at` path; a `MAP_SHARED` writable mmap mutates the frame
// directly (no syscall), so its dirty data only reaches disk at an explicit
// flush — `writeback`/`writeback_range`, driven by `fsync`/`msync` and the
// inode `Drop`. Dirty tracking follows Linux's page_mkwrite boundary: a frame
// handed out by `shared_frame` remains clean until a shared write fault is
// admitted.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{KResult, VfsError};
use sched::live::WaitList;

mod readahead;

use super::state::RootfsState;

mod cachestat;
mod dirty;
mod invalidate;
#[cfg(feature = "debug-fillverify")]
mod debug;
#[cfg(feature = "debug-framecache-verify")]
mod verify;
mod read;
mod release;
mod writeback;
pub use dirty::{flush_all_dirty, flush_dirty, flush_dirty_nowait, flush_pass, writeback_dirty, writeback_inode};
#[cfg(test)]
mod tests;

/// Page granule (Linux PAGE_SIZE). ext4 block size is `<= PG`; a page holds
/// `PG / block_size` consecutive file blocks.
const PG: usize = hal::PAGE_SIZE_BYTES as usize;

/// Small nonresident history retained even when a mapping has no resident
/// file frames. Additional shadows scale with cache state, so a sparse
/// eviction/truncate workload cannot turn eviction metadata into an unbounded
/// second page cache.
const SHADOW_FLOOR: usize = 64;

/// Report one coalesced page-cache fill's duration into the fault profile,
/// however the fill returns. # C: O(1)
#[cfg(feature = "debug-faultcost")]
struct FillCostGuard(u64);

#[cfg(feature = "debug-faultcost")]
impl Drop for FillCostGuard {
    fn drop(&mut self) { pmm::faultcost::note_fill(pmm::faultcost::stamp().saturating_sub(self.0)); }
}

struct FillGuard<'a> { store: &'a Ext4FrameStore }

impl Drop for FillGuard<'_> {
    fn drop(&mut self) { self.store.finish_fill(); }
}

fn shadow_budget(resident_pages: usize) -> usize {
    resident_pages.saturating_mul(2).saturating_add(SHADOW_FLOOR)
}

/// Discard the least-recently evicted shadows that exceed `resident_pages`'
/// history budget. # C: O(shadows²) worst case
fn trim_shadows(shadows: &mut BTreeMap<u64, u64>, resident_pages: usize) {
    let budget = shadow_budget(resident_pages);
    while shadows.len() > budget {
        let Some(oldest) = shadows.iter().min_by_key(|(_, stamp)| *stamp).map(|(&idx, _)| idx) else { break };
        shadows.remove(&oldest);
    }
}

/// Resolve the current allocator's memcg at the page-cache allocation point.
/// A pre-scheduler kernel context belongs to root; a published page never
/// follows a later task migration. # C: O(log n)
fn allocating_memcg() -> u64 {
    sched::current().map(|t| cgroup::cgroup_of(t.tid as u64)).unwrap_or_else(cgroup::kernel_context_memcg)
}

/// One published regular-file cache page and its immutable memcg owner.
#[derive(Clone, Copy)]
struct FileCachePage { pa: u64, cgid: u64 }

/// Per-inode frame store. One per regular-file inode, held in `Ext4FileData`
/// and shared (via `Arc`) with that inode's `Ext4FileMapping` (`i_mapping`),
/// so every mapper/reader/writer of the inode hits THESE frames.
pub(crate) struct Ext4FrameStore {
    /// Owning mount (device + extent map + journal). Same `Arc` the inode's
    /// `Ext4FileData` holds.
    pub(crate) st:  Arc<RootfsState>,
    /// ext4 inode number this store backs.
    pub(crate) ino: u32,
    /// Authoritative in-memory file size (bytes). A buffered `write(2)` grows
    /// this WITHOUT touching disk (Linux page-cache / delayed writeback); the
    /// on-disk `i_size` catches up only at `writeback`. `writeback_idxs` clamps
    /// flushed pages to `max(this, on-disk i_size)`, so a buffered growth is
    /// never truncated at flush and a store that predates a write still honors
    /// the real on-disk size. Kept in step with `Ext4FileData.size_hint` /
    /// `inode.i_size` by write/truncate/fallocate.
    size: AtomicU64,
    /// Prevent duplicate asynchronous readahead jobs for one inode store.
    readahead_queued: AtomicBool,
    /// Parsed on-disk inode reused by page-cache fills. Linux keeps this
    /// metadata in the inode cache; re-reading the inode-table slot for every
    /// frame miss adds an uncached metadata I/O to each fill window.
    disk_inode: Spinlock<Option<crate::Inode>, TaskListClass>,
    /// `page_idx -> frame pa`. Sparse: an absent page is filled from disk on
    /// first touch (a hole reads as zero).
    pages: Spinlock<BTreeMap<u64, FileCachePage>, TaskListClass>,
    /// Dirty page indices (Linux `PAGECACHE_TAG_DIRTY`). Pages are tagged by
    /// `page_mkwrite` immediately before a shared mapping becomes writable;
    /// read-side frame lookup remains clean.
    dirty: Spinlock<BTreeSet<u64>, TaskListClass>,
    /// Per-index writeback references. A page can be dirtied and queued again
    /// while an earlier flush is still copying it, so this is a count rather
    /// than a boolean. It is the authoritative `cachestat` writeback state.
    writeback: Spinlock<BTreeMap<u64, u32>, TaskListClass>,
    /// Self-`Weak` so `mark_dirty` can register this store in the global
    /// dirty list (for `msync`, which has no fd). Set once in `new`.
    me: Spinlock<Weak<Ext4FrameStore>, TaskListClass>,
    /// One-shot: registered in the global dirty list (on first dirty).
    registered: AtomicBool,
    /// A strong reference to itself, held for exactly as long as this store has
    /// dirty pages. The cycle is deliberate: the reference tracks the same
    /// thing the reference implementation's writeback list does, which owns a
    /// dirty inode until its pages are written. While it is held the store
    /// cannot reach a zero count, so its final drop is guaranteed to be clean
    /// — and `Drop` therefore does not have to write anything, which is what
    /// used to put a journal commit, a block allocation and an extent-tree
    /// rewrite onto whichever unrelated stack released the last reference.
    pin: Spinlock<Option<Arc<Ext4FrameStore>>, TaskListClass>,
    /// Final inode eviction has started.  Linux sets AS_EXITING and waits for
    /// inode writeback before `truncate_inode_pages_final`; once published,
    /// no new writeback may reach this inode's blocks.
    evicting: AtomicBool,
    /// Writebacks admitted before `evicting` was published.  Final eviction
    /// waits for this count to drain before discarding pages and freeing the
    /// orphan's blocks, mirroring `inode_wait_for_writeback`.
    active_writebacks: AtomicU32,
    /// Waiters for the final active writeback completion.
    writeback_wait: WaitList,
    /// Page-cache fills admitted before final inode eviction. This covers
    /// inode/extent/data reads between a fault miss and frame publication.
    active_fills: AtomicU32,
    /// Waiters for final active fill completion.
    fill_wait: WaitList,
    /// Eviction shadows (Linux workingset shadow entries in the mapping
    /// xarray): `page_idx -> nonresident-age stamp` for a page reclaim dropped.
    /// The index stays *present* in the cache's index space with no frame, so
    /// `cachestat(2)` can report it as evicted and judge its recency. A refault
    /// consumes the shadow; truncate/invalidate deletes it along with the page.
    shadows: Spinlock<BTreeMap<u64, u64>, TaskListClass>,
    /// DIAG (debug-fillverify): checksum of each page at fill time,
    /// re-verified on every read of a still-clean page. Distinguishes
    /// lower-layer read nondeterminism ([FILLRACE], caught at fill) from a
    /// later wild write to the cached frame ([FRAME-CORRUPT], caught at read).
    #[cfg(feature = "debug-fillverify")]
    sums: Spinlock<BTreeMap<u64, u64>, TaskListClass>,
}


impl Ext4FrameStore {
    /// Build a frame store for `ino` on mount `st`, seeded with the inode's
    /// current on-disk `size`. # C: O(1)
    pub(crate) fn new(st: Arc<RootfsState>, ino: u32, size: u64) -> Arc<Ext4FrameStore> {
        let s = Arc::new(Ext4FrameStore {
            st, ino,
            size: AtomicU64::new(size),
            readahead_queued: AtomicBool::new(false),
            disk_inode: Spinlock::new(None),
            pages: Spinlock::new(BTreeMap::new()),
            dirty: Spinlock::new(BTreeSet::new()),
            writeback: Spinlock::new(BTreeMap::new()),
            me: Spinlock::new(Weak::new()),
            registered: AtomicBool::new(false),
            pin: Spinlock::new(None),
            evicting: AtomicBool::new(false),
            active_writebacks: AtomicU32::new(0),
            writeback_wait: WaitList::new(),
            active_fills: AtomicU32::new(0),
            fill_wait: WaitList::new(),
            shadows: Spinlock::new(BTreeMap::new()),
            #[cfg(feature = "debug-fillverify")]
            sums: Spinlock::new(BTreeMap::new()),
        });
        *s.me.lock() = Arc::downgrade(&s);
        dirty::register_store(&s);
        s
    }

    /// Return the cached parsed inode, loading it once on the first fill. # C: O(1) hit + one inode read
    fn inode_for_fill(&self) -> Result<crate::Inode, crate::MountError> {
        if let Some(inode) = self.disk_inode.lock().as_ref().copied() { return Ok(inode); }
        let inode = self.st.mount.read_inode(self.ino)?;
        *self.disk_inode.lock() = Some(inode);
        Ok(inode)
    }

    /// Invalidate the fill snapshot before an extent or inode mutation. # C: O(1)
    pub(crate) fn invalidate_inode_cache(&self) { *self.disk_inode.lock() = None; }

    /// Publish a post-mutation inode snapshot for subsequent fills. # C: O(1)
    pub(crate) fn refresh_inode_cache(&self, inode: crate::Inode) {
        *self.disk_inode.lock() = Some(inode);
    }

    fn finish_fill(&self) {
        if self.active_fills.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.fill_wait.wake_all();
        }
    }

    fn self_arc(&self) -> Arc<Ext4FrameStore> {
        self.me.lock().upgrade().expect("live frame store")
    }

    /// Admit one cache fill unless final eviction has started. The second
    /// check closes the race where eviction publishes `evicting` between the
    /// first check and the counter increment.
    fn begin_fill(&self) -> Option<FillGuard<'_>> {
        if self.evicting.load(Ordering::Acquire) { return None; }
        self.active_fills.fetch_add(1, Ordering::AcqRel);
        if self.evicting.load(Ordering::Acquire) {
            self.finish_fill();
            return None;
        }
        Some(FillGuard { store: self })
    }

    /// Resident frame for page `idx`, filling from disk on a miss. Block I/O
    /// runs OUTSIDE the `pages` lock (alloc+fill, then publish), so a slow
    /// device read never serializes other pages and the spinlock never spans
    /// I/O. A concurrent filler that won the publish race frees the loser's
    /// frame. Reads the on-disk inode ONLY on a genuine page miss — that read is
    /// an UNCACHED, busy-polled device read of the inode-table block (~10ms), so
    /// keeping it off the all-cached hot path is what makes process startup fast
    /// (executables/libs demand-fault through here via read_framed).
    /// # C: O(PG/bs) on miss, O(log N) on hit
    fn ensure_page(&self, idx: u64) -> KResult<u64> {
        if let Some(page) = self.pages.lock().get(&idx) { return Ok(page.pa); }
        // Eviction is sweeping this store: the miss cannot be filled now, but
        // nothing is wrong with the file. Reported as a transient so a fault
        // retries rather than taking it for an I/O error and dying.
        let Some(_active_fill) = self.begin_fill() else { return Err(VfsError::Eagain); };
        let dinode = self.inode_for_fill().map_err(|_e| {
            // DIAG (debug-fillverify): inode-table errors otherwise collapse
            // to EIO before the range-read diagnostic can identify them.
            #[cfg(feature = "debug-fillverify")]
            {
                klog::write_raw(b"[FILLVERIFY] read-inode failed ino=");
                klog::write_dec_u64(self.ino as u64);
                klog::write_raw(b" page="); klog::write_dec_u64(idx);
                klog::write_raw(b" why="); klog::write_raw(debug::fill_error_label(_e));
                klog::write_raw(b"\n");
            }
            fill_err(b"read-inode", self.ino, idx);
            VfsError::Eio
        })?;
        if !dinode.is_reg() {
            fill_err(b"not-reg", self.ino, idx);
            return Err(VfsError::Eio);
        }
        self.fill_window(&dinode, idx).inspect_err(|_| fill_err(b"fill-window", self.ino, idx))
    }

    /// Pages fetched in ONE coalesced device read. 64 KiB, Linux-conservative.
    const READAHEAD_WINDOW_PAGES: u64 = 16;

    /// Populate `nr_pages` pages from `start` without copying anything out —
    /// the submit half of readahead (Linux `page_cache_ra_unbounded`). Issued
    /// as coalesced window-sized device reads, so a sequential window is a
    /// handful of block requests rather than one per page. Best-effort: a
    /// failure stops the fill and leaves the demand fault to report it.
    /// # C: O(nr_pages / window) device reads
    pub fn readahead(&self, start: u64, nr_pages: u64) {
        readahead::schedule(self, start, nr_pages);
    }

    /// Synchronous worker body for readahead. The public entry queues this
    /// after the foreground read, matching Linux's page-cache workers.
    pub(super) fn readahead_sync(&self, start: u64, nr_pages: u64) {
        if nr_pages == 0 { return; }
        let total = self.size.load(Ordering::Acquire);
        let last_page = (total + PG as u64 - 1) / PG as u64;
        let end = (start + nr_pages).min(last_page);
        if start >= end { return; }
        // Linux page-cache readahead first tests the mapping for a useful
        // resident range. Do not fetch the inode table merely to discover
        // that every requested page is already present.
        let has_miss = {
            let pages = self.pages.lock();
            (start..end).any(|idx| !pages.contains_key(&idx))
        };
        if !has_miss { return; }
        let Ok(dinode) = self.inode_for_fill() else { return };
        if !dinode.is_reg() { return; }
        let mut idx = start;
        while idx < end {
            if self.pages.lock().contains_key(&idx) { idx += 1; continue; }
            if self.fill_window(&dinode, idx).is_err() { return; }
            idx += Self::READAHEAD_WINDOW_PAGES;
        }
    }

    /// Fill page `start_idx` AND a readahead window (Linux page-cache readahead)
    /// in ONE coalesced device read: a contiguous executable/library maps to one
    /// physical run, so the whole window is a single virtio-blk request instead
    /// of one serialized per-page read — the cold process-startup bottleneck.
    /// Returns `start_idx`'s frame; the window is best-effort. # C: O(window)
    fn fill_window(&self, dinode: &crate::Inode, start_idx: u64) -> KResult<u64> {
        #[cfg(feature = "debug-faultcost")]
        let __fill_t0 = pmm::faultcost::stamp();
        #[cfg(feature = "debug-faultcost")]
        let _fill_cost = FillCostGuard(__fill_t0);
        let bs = self.st.mount.sb.block_size.max(1) as u64;
        let bpp = (PG as u64 / bs).max(1);
        // Clamp to the file's last page so no past-EOF page is ever cached.
        let total = self.size.load(Ordering::Acquire);
        let last_page = (total + PG as u64 - 1) / PG as u64;
        let window = Self::READAHEAD_WINDOW_PAGES.min(last_page.saturating_sub(start_idx)).max(1);
        let first_blk = start_idx.saturating_mul(bpp) as u32;
        let n_blks = window.saturating_mul(bpp) as u32;
        #[cfg(feature = "debug-faultcost")]
        let __fill_read_t0 = pmm::faultcost::stamp();
        let mut buf = self.st.mount.read_file_range(dinode, first_blk, n_blks).map_err(|_e| {
            // DIAG (debug-fillverify): the fill failure collapses to EIO here, so
            // the class that produced it is only recoverable at this one point.
            #[cfg(feature = "debug-fillverify")]
            {
                klog::write_raw(b"[FILLVERIFY] read-file-range failed ino=");
                klog::write_dec_u64(self.ino as u64);
                klog::write_raw(b" first-blk="); klog::write_dec_u64(first_blk as u64);
                klog::write_raw(b" n-blks=");    klog::write_dec_u64(n_blks as u64);
                klog::write_raw(b" why=");       klog::write_raw(debug::fill_error_label(_e));
                klog::write_raw(b"\n");
            }
            VfsError::Eio
        })?;
        #[cfg(feature = "debug-faultcost")]
        let __fill_read_ns = pmm::faultcost::stamp().saturating_sub(__fill_read_t0);
        #[cfg(feature = "debug-faultcost")]
        let __fill_publish_t0 = pmm::faultcost::stamp();
        // Zero the window past EOF: the last mapped block extends beyond i_size
        // and its tail is stale disk garbage a MAP_SHARED mapper must read as zero
        // (Linux page-cache EOF zeroing — matches the old fill_page tail-zero).
        let window_start_byte = start_idx.saturating_mul(PG as u64);
        if total > window_start_byte {
            let valid = (total - window_start_byte) as usize;
            if valid < buf.len() { for b in &mut buf[valid..] { *b = 0; } }
        }
        let mut target_pa: Option<u64> = None;
        for w in 0..window {
            let idx = start_idx + w;
            if let Some(pa) = self.pages.lock().get(&idx).map(|page| page.pa) {
                if idx == start_idx { target_pa = Some(pa); }
                continue;
            }
            let off = (w * PG as u64) as usize;
            match self.publish_from_bytes(idx, &buf[off..off + PG]) {
                Ok(pa) => if idx == start_idx { target_pa = Some(pa); },
                // The faulting page MUST succeed; a prefetch page is best-effort.
                Err(e) => { if idx == start_idx { return Err(e); } break; }
            }
        }
        #[cfg(feature = "debug-faultcost")]
        pmm::faultcost::note_fill_parts(
            __fill_read_ns,
            pmm::faultcost::stamp().saturating_sub(__fill_publish_t0),
        );
        target_pa.ok_or(VfsError::Eio)
    }

    /// Publish one already-read page (`src` = exactly PG bytes, zero-padded past
    /// EOF/holes by `read_file_range`) into the store, racing publishers safely.
    /// # C: O(log N)
    fn publish_from_bytes(&self, idx: u64, src: &[u8]) -> KResult<u64> {
        let cgid = allocating_memcg();
        if !cgroup::try_charge_memory(cgid, cgroup::MemoryKind::File, PG as u64) { return Err(VfsError::Enomem); }
        let pa = match pmm::setup::alloc_object_frame() {
            Some(pa) => pa,
            None => { cgroup::uncharge_memory(cgid, cgroup::MemoryKind::File, PG as u64); return Err(VfsError::Enomem); }
        };
        let base = match pmm::setup::frame_ptr(pa) {
            Some(base) => base,
            None => {
                // SAFETY: pa came from alloc_object_frame (refcount 1, mapcount 0).
                unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
                cgroup::uncharge_memory(cgid, cgroup::MemoryKind::File, PG as u64);
                return Err(VfsError::Eio);
            }
        };
        hal::zerotrap::trap(base as *const u8, PG);
        // SAFETY: pa owned here; src is exactly PG bytes; base is the writable
        // HHDM mirror of the frame, non-overlapping with src (a distinct Vec).
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), base, PG.min(src.len())); }
        #[cfg(feature = "debug-fillverify")]
        let fsum = debug::page_sum(base);
        let mut g = self.pages.lock();
        if let Some(existing) = g.get(&idx).copied() {
            drop(g);
            // SAFETY: lost the publish race; free our now-unused fill frame.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
            cgroup::uncharge_memory(cgid, cgroup::MemoryKind::File, PG as u64);
            return Ok(existing.pa);
        }
        pmm::setup::classify_file_page(pa, cgid);
        pmm::kassert!(pmm::setup::admit_file_lru(pa).is_ok(), "file lru admission invariant");
        g.insert(idx, FileCachePage { pa, cgid });
        // Refault: the page is back, so its eviction shadow is consumed.
        self.shadows.lock().remove(&idx);
        vfs::memory_accounting::account_file_cache_publish(1);
        drop(g);
        #[cfg(feature = "debug-fillverify")]
        self.sums.lock().insert(idx, fsum);
        Ok(pa)
    }

    /// Pin and lock a published cache page for buffered I/O.  The object pin
    /// closes lookup versus reclaim; the PMM page lock serializes this I/O
    /// with clean eviction and writeback state transitions.  The caller owns
    /// one object pin and the page lock on success.
    fn lock_cache_page(&self, idx: u64) -> KResult<u64> {
        loop {
            let pa = self.ensure_page(idx)?;
            {
                let pages = self.pages.lock();
                if pages.get(&idx).map(|page| page.pa) != Some(pa) { continue; }
                // SAFETY: `pages` proves the store's object reference exists
                // until this transient I/O reference has been acquired.
                unsafe { pmm::setup::inc_object_ref(pa); }
            }
            if !pmm::setup::lock_page(pa) { continue; }
            if self.pages.lock().get(&idx).map(|page| page.pa) == Some(pa) { return Ok(pa); }
            let _ = pmm::setup::unlock_page(pa);
            // SAFETY: release the transient non-PTE pin acquired above.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
        }
    }

    /// Finish one `lock_cache_page` transaction. # C: O(1)
    fn unlock_cache_page(&self, pa: u64) {
        let _ = pmm::setup::unlock_page(pa);
        // SAFETY: exactly matches the transient non-PTE pin from lock_cache_page.
        unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
    }

    /// Remove one clean, unmapped page while its PMM page lock is held by the
    /// shrinker. Dirty pages are categorically refused: writeback owns their
    /// persistence transition and reclaim never drops data. # C: O(N_pages)
    fn evict_clean_locked(&self, pa: u64) -> Option<FileCachePage> {
        if pmm::setup::frame_mapcount(pa) != 0 { return None; }
        let mut pages = self.pages.lock();
        let idx = pages.iter().find_map(|(&idx, page)| (page.pa == pa).then_some(idx))?;
        if self.dirty.lock().contains(&idx) || self.writeback.lock().contains_key(&idx) { return None; }
        let page = pages.remove(&idx)?;
        drop(pages);
        // Reclaim leaves a shadow, stamped with the nonresident age, so a later
        // `cachestat` can tell "evicted" from "never cached".
        let resident_pages = self.pages.lock().len();
        let mut shadows = self.shadows.lock();
        shadows.insert(idx, pmm::reclaim::workingset_eviction());
        trim_shadows(&mut shadows, resident_pages);
        #[cfg(feature = "debug-fillverify")]
        self.sums.lock().remove(&idx);
        vfs::memory_accounting::account_file_cache_remove(1);
        Some(page)
    }

    /// Set the authoritative in-memory `size` (truncate/fallocate: the size
    /// change is on disk, keep the writeback clamp in step). # C: O(1)
    pub(crate) fn set_size(&self, size: u64) { self.size.store(size, Ordering::Release); }

    /// Admit a newer canonical inode size when an existing store is found
    /// during inode construction. Growth is monotonic here: truncation owns
    /// the explicit shrinking `set_size` publication under the inode path.
    /// # C: O(1)
    pub(crate) fn set_size_max(&self, size: u64) { self.size.fetch_max(size, Ordering::AcqRel); }

    /// Prepare a buffered shared-mapping write at `off`. Linux's
    /// `page_mkwrite` dirties the page before the PTE becomes writable; a
    /// clean mapping fault must remain clean until this hook is reached.
    /// # C: O(PG/bs) on miss, O(log N) on hit
    pub(crate) fn page_mkwrite(&self, off: u64) -> KResult<()> {
        let idx = off / PG as u64;
        let pa = self.lock_cache_page(idx)?;
        self.mark_dirty(idx);
        self.unlock_cache_page(pa);
        Ok(())
    }

    // Range eviction — truncate's unconditional drop (`invalidate_range`) and
    // the DONTNEED hint's best-effort one (`try_invalidate_pages`) — lives in
    // the `invalidate` child module.

    // ── internals ────────────────────────────────────────────────────────

    fn mark_dirty(&self, idx: u64) {
        #[cfg(feature = "debug-fillverify")]
        self.sums.lock().remove(&idx); // DIAG: page may legitimately change now
        if self.dirty.lock().insert(idx) { vfs::memory_accounting::account_file_cache_dirty(1); }
        if !self.registered.swap(true, Ordering::AcqRel) {
            if let Some(arc) = self.me.lock().upgrade() { dirty::register(&arc); }
        }
        // Pin for as long as there is anything to write. Dropped again by
        // `unpin_if_clean` once the flusher, a sync, or eviction has emptied
        // the dirty set.
        let mut pin = self.pin.lock();
        if pin.is_none() { *pin = self.me.lock().upgrade(); }
    }

    /// Release the dirty pin once nothing is outstanding.
    ///
    /// The caller must hold its own reference to this store: dropping the pin
    /// can be the release that frees it, and it must not be the one taken while
    /// a method is running on `&self`. Every caller reached this store by
    /// upgrading out of a registry, so it does.
    /// # C: O(1)
    pub(crate) fn unpin_if_clean(&self) {
        if !self.dirty.lock().is_empty() || !self.writeback.lock().is_empty() { return; }
        let released = self.pin.lock().take();
        drop(released);
    }

}
mod io;

/// Name which leg of a page fill failed. The fault path turns any of them into
/// the same `Eio`, and the same SIGBUS, so without this the log says a fill
/// errored but not where — and the legs want different fixes.
/// # C: O(1)
pub(crate) fn fill_err(leg: &'static [u8], ino: u32, idx: u64) {
    klog::write_raw(b"[FILL-ERR ");
    klog::write_raw(leg);
    klog::write_raw(b" ino=");
    klog::write_dec_u64(ino as u64);
    klog::write_raw(b" page=");
    klog::write_hex_u64(idx);
    klog::write_raw(b"]\n");
}
