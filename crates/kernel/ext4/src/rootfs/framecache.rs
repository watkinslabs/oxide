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
// inode `Drop`. Dirty tracking is PESSIMISTIC: any frame ever handed out via
// `shared_frame` is marked dirty (a shared mapping may write it), so writeback
// re-persists it. Over-flushing an unmodified shared page is correct (writes
// identical bytes), just not minimal.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{KResult, VfsError};

use super::state::RootfsState;

mod dirty;
#[cfg(feature = "debug-fillverify")]
mod debug;
#[cfg(feature = "debug-framecache-verify")]
mod verify;
mod read;
mod release;
mod writeback;
pub use dirty::flush_all_dirty;
#[cfg(test)]
mod tests;

/// Page granule (Linux PAGE_SIZE). ext4 block size is `<= PG`; a page holds
/// `PG / block_size` consecutive file blocks.
const PG: usize = hal::PAGE_SIZE_BYTES as usize;

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
    /// `page_idx -> frame pa`. Sparse: an absent page is filled from disk on
    /// first touch (a hole reads as zero).
    pages: Spinlock<BTreeMap<u64, FileCachePage>, TaskListClass>,
    /// Dirty page indices (Linux `PAGECACHE_TAG_DIRTY`). Pessimistic: a page
    /// handed out via `shared_frame` is tagged dirty; `writeback` flushes +
    /// clears.
    dirty: Spinlock<BTreeSet<u64>, TaskListClass>,
    /// Self-`Weak` so `mark_dirty` can register this store in the global
    /// dirty list (for `msync`, which has no fd). Set once in `new`.
    me: Spinlock<Weak<Ext4FrameStore>, TaskListClass>,
    /// One-shot: registered in the global dirty list (on first dirty).
    registered: AtomicBool,
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
            pages: Spinlock::new(BTreeMap::new()),
            dirty: Spinlock::new(BTreeSet::new()),
            me: Spinlock::new(Weak::new()),
            registered: AtomicBool::new(false),
            #[cfg(feature = "debug-fillverify")]
            sums: Spinlock::new(BTreeMap::new()),
        });
        *s.me.lock() = Arc::downgrade(&s);
        dirty::register_store(&s);
        s
    }

    /// Fill freshly-allocated frame `pa` for page `idx` from disk: zero the
    /// whole page, then copy each on-disk block of the page over it (a
    /// `NotFound` block is a hole → stays zero). This mirrors the proven
    /// `RootfsState::read_cached` page-build closure (`state.rs:225`) so a
    /// frame read is byte-identical to the legacy `Vec` page-cache read,
    /// including B240 short-fill at EOF: a non-EOF page is filled completely
    /// (every block read), the post-EOF tail stays zero. # C: O(PG/bs)
    fn fill_page(&self, dinode: &crate::Inode, idx: u64, pa: u64) -> Result<(), ()> {
        let base = pmm::setup::frame_ptr(pa).ok_or(())?;
        // SAFETY: pa is a freshly-allocated PMM frame owned here; the HHDM
        // mirror is writable; PG is the page granule.
        hal::zerotrap::trap((base) as *const u8, (PG) as usize);
        unsafe { core::ptr::write_bytes(base, 0, PG); }
        let bs = self.st.mount.sb.block_size.max(1) as u64;
        let bpp = (PG as u64 / bs).max(1) as u32;
        let first_blk = (idx * PG as u64 / bs) as u32;
        for i in 0..bpp {
            match self.st.mount.read_file_block(dinode, first_blk + i) {
                Ok(blk) => {
                    let off = (i as usize) * (bs as usize);
                    if off >= PG { break; }
                    let n = blk.len().min(PG - off);
                    // SAFETY: pa owned here; [off, off+n) ⊆ [0, PG); src is a
                    // distinct Vec, non-overlapping with the HHDM mirror.
                    unsafe { core::ptr::copy_nonoverlapping(blk.as_ptr(), base.add(off), n); }
                }
                Err(crate::MountError::NotFound) => {} // sparse hole → stays zero
                Err(error) => {
                    #[cfg(feature = "debug-fillverify")]
                    {
                        klog::write_raw(b"[EXT4-FRAME-FILL] ino=");
                        klog::write_dec_u64(self.ino as u64);
                        klog::write_raw(b" page=");
                        klog::write_dec_u64(idx);
                        klog::write_raw(b" file-block=");
                        klog::write_dec_u64((first_blk + i) as u64);
                        klog::write_raw(b" error=");
                        klog::write_raw(debug::fill_error_label(error));
                        klog::write_raw(b"\n");
                    }
                    return Err(());
                }
            }
        }
        // Linux zeroes the page-cache page past EOF: the last on-disk block
        // extends beyond i_size and its tail bytes are stale disk garbage a
        // MAP_SHARED mapper would otherwise see raw.
        let size = dinode.size;
        let page_start = idx * PG as u64;
        if size > page_start && size < page_start + PG as u64 {
            let valid = (size - page_start) as usize;
            // SAFETY: pa owned here; [valid, PG) within the frame's HHDM mirror.
            // SAFETY: same bounds as the write_bytes below — [valid, PG) within the frame's HHDM mirror.
            hal::zerotrap::trap(unsafe { base.add(valid) } as *const u8, PG - valid);
            unsafe { core::ptr::write_bytes(base.add(valid), 0, PG - valid); }
        }
        Ok(())
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
        let dinode = self.st.mount.read_inode(self.ino).map_err(|_| VfsError::Eio)?;
        if !dinode.is_reg() { return Err(VfsError::Eio); }
        let dinode = &dinode;
        let cgid = allocating_memcg();
        if !cgroup::try_charge_memory(cgid, cgroup::MemoryKind::File, PG as u64) { return Err(VfsError::Enomem); }
        let pa = match pmm::setup::alloc_object_frame() {
            Some(pa) => pa,
            None => {
                cgroup::uncharge_memory(cgid, cgroup::MemoryKind::File, PG as u64);
                return Err(VfsError::Enomem);
            }
        };
        if self.fill_page(dinode, idx, pa).is_err() {
            // SAFETY: pa came from alloc_object_frame (object refcount 1,
            // mapcount 0); release the inode's sole reference → freed.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
            cgroup::uncharge_memory(cgid, cgroup::MemoryKind::File, PG as u64);
            return Err(VfsError::Eio);
        }
        // DIAG (debug-fillverify): verify the fill is reproducible — fill a second
        // frame from the same blocks and compare. A mismatch = the block/extent
        // layer returned different bytes for the same page back-to-back.
        #[cfg(feature = "debug-fillverify")]
        let mut fsum = 0u64;
        #[cfg(feature = "debug-fillverify")]
        if let Some(base) = pmm::setup::frame_ptr(pa) {
            fsum = debug::page_sum(base);
            if cgroup::try_charge_memory(cgid, cgroup::MemoryKind::File, PG as u64) {
                if let Some(pa2) = pmm::setup::alloc_object_frame() {
                    if self.fill_page(dinode, idx, pa2).is_ok() {
                        if let Some(base2) = pmm::setup::frame_ptr(pa2) {
                            let s2 = debug::page_sum(base2);
                            if s2 != fsum {
                                klog::write_raw(b"[FILLRACE] ino=");
                                klog::write_dec_u64(self.ino as u64);
                                klog::write_raw(b" idx=");
                                klog::write_dec_u64(idx);
                                klog::write_raw(b" s1=");
                                klog::write_hex_u64(fsum);
                                klog::write_raw(b" s2=");
                                klog::write_hex_u64(s2);
                                klog::write_raw(b"\n");
                            }
                        }
                    }
                    // SAFETY: pa2 is the diag scratch frame (refcount 1, unmapped).
                    unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa2); }
                }
                cgroup::uncharge_memory(cgid, cgroup::MemoryKind::File, PG as u64);
            }
        }
        let mut g = self.pages.lock();
        if let Some(existing) = g.get(&idx).copied() {
            drop(g);
            // SAFETY: lost the publish race; free our now-unused fill frame
            // (object refcount 1, mapcount 0).
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
            cgroup::uncharge_memory(cgid, cgroup::MemoryKind::File, PG as u64);
            return Ok(existing.pa);
        }
        pmm::setup::classify_file_page(pa, cgid);
        pmm::kassert!(pmm::setup::admit_file_lru(pa).is_ok(), "file lru admission invariant");
        g.insert(idx, FileCachePage { pa, cgid });
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
            while !pmm::setup::try_lock_page(pa) { core::hint::spin_loop(); }
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
        if self.dirty.lock().contains(&idx) { return None; }
        let page = pages.remove(&idx)?;
        drop(pages);
        #[cfg(feature = "debug-fillverify")]
        self.sums.lock().remove(&idx);
        vfs::memory_accounting::account_file_cache_remove(1);
        Some(page)
    }

    /// Read-side fill (read(2) / mmap read-fault): copy bytes from the frame
    /// store starting at file offset `off` into `dst`. Short read past i_size;
    /// holes read as zero. Byte-identical to `RootfsState::read_cached`.
    /// # C: O(dst.len)
    pub(crate) fn read_framed(&self, off: u64, dst: &mut [u8]) -> KResult<usize> {
        // Buffered writes publish the in-core i_size before delayed writeback
        // updates the ext4 inode, so the in-core `self.size` IS the authoritative
        // read size — no per-call on-disk inode read (that uncached device read
        // is the executable/library demand-fault bottleneck; ensure_page reads
        // the inode only on a genuine page miss now).
        let total = self.size.load(Ordering::Acquire);
        let mut written = 0usize;
        while written < dst.len() {
            let cur = off + written as u64;
            if cur >= total { break; }
            let idx = cur / PG as u64;
            let pgoff = (cur % PG as u64) as usize;
            let pa = self.lock_cache_page(idx)?;
            let Some(base) = pmm::setup::frame_ptr(pa) else {
                self.unlock_cache_page(pa);
                return Err(VfsError::Eio);
            };
            // DIAG (debug-fillverify): a clean page must still match its fill-time
            // checksum; a mismatch = something wrote the cached frame since fill.
            #[cfg(feature = "debug-fillverify")]
            if !self.dirty.lock().contains(&idx) {
                if let Some(&want) = self.sums.lock().get(&idx) {
                    let got = debug::page_sum(base);
                    if got != want {
                        klog::write_raw(b"[FRAME-CORRUPT] ino=");
                        klog::write_dec_u64(self.ino as u64);
                        klog::write_raw(b" idx=");
                        klog::write_dec_u64(idx);
                        klog::write_raw(b" want=");
                        klog::write_hex_u64(want);
                        klog::write_raw(b" got=");
                        klog::write_hex_u64(got);
                        klog::write_raw(b"\n");
                        self.sums.lock().insert(idx, got);
                    }
                }
            }
            let want = (dst.len() - written).min(PG - pgoff).min((total - cur) as usize);
            if want == 0 { break; }
            // SAFETY: pa is an inode-owned frame kept alive for this read by
            // the inode's reference; [pgoff, pgoff+want) ⊆ [0, PG); dst slice
            // is distinct from the HHDM mirror.
            unsafe { core::ptr::copy_nonoverlapping(base.add(pgoff), dst[written..].as_mut_ptr(), want); }
            written += want;
            self.unlock_cache_page(pa);
        }
        Ok(written)
    }

    /// Buffered `write(2)` (Linux `generic_perform_write`): copy `src` into the
    /// inode's page frames and tag them dirty — NO synchronous disk I/O. A
    /// partial or growing page is faulted in from disk first (RMW / zero-fill
    /// past EOF) so untouched bytes survive; the authoritative in-memory `size`
    /// grows to cover the write. Data reaches disk lazily via `writeback`
    /// (fsync/msync/sync/inode-drop). Replaces the old per-write `write_at`
    /// write-through, which cost one synchronous block RMW + inode round-trip
    /// per write(2) (systemd-hwdb-update: ~11.6k writes ≈ 56s). # C: O(src.len)
    pub(crate) fn write_buffered(&self, off: u64, src: &[u8]) -> KResult<usize> {
        if src.is_empty() { return Ok(0); }
        // Do NOT read the on-disk inode on the hot path. A write that lands in an
        // already-resident page needs nothing from it — Linux writes go through
        // the in-core inode, never a per-write disk read. `ensure_page` now reads
        // the inode (an UNCACHED, busy-polled inode-table block read) only on a
        // genuine page miss that must be RMW-filled from disk.
        let mut done = 0usize;
        while done < src.len() {
            let cur = off + done as u64;
            let idx = cur / PG as u64;
            let pgoff = (cur % PG as u64) as usize;
            let chunk = (PG - pgoff).min(src.len() - done);
            let pa = self.lock_cache_page(idx)?;
            let Some(base) = pmm::setup::frame_ptr(pa) else {
                self.unlock_cache_page(pa);
                return Err(VfsError::Eio);
            };
            // Publish dirty state before the first byte can change. A clean
            // shrinker holding this same page lock can therefore never evict
            // a page concurrently being modified.
            self.mark_dirty(idx);
            // SAFETY: pa is an inode-owned resident frame (resident or just
            // filled); [pgoff, pgoff+chunk) ⊆ [0, PG); src is a distinct caller
            // slice, non-overlapping with the HHDM frame mirror.
            unsafe { core::ptr::copy_nonoverlapping(src[done..].as_ptr(), base.add(pgoff), chunk); }
            self.unlock_cache_page(pa);
            done += chunk;
        }
        let newsz = off + src.len() as u64;
        #[cfg_attr(not(feature = "debug-wakelat"), allow(unused_variables))]
        let prev = self.size.fetch_max(newsz, Ordering::AcqRel);
        // DIAG (debug-wakelat): a buffered file whose size climbs past ~16MB is the
        // systemd-hwdb unbounded/circular-trie signature (hwdb.bin should be ~13.5MB).
        // Log each 8MB boundary crossing with the inode; if this keeps climbing for
        // one inode, the trie is unbounded (allocator-corruption). If it plateaus at
        // ~13.5MB, the spin is NOT unbounded output. Cheap: fires once per 8MB.
        #[cfg(feature = "debug-wakelat")]
        if newsz.max(prev) >> 23 != prev >> 23 {
            klog::write_raw(b"[FCSIZE ino="); klog::write_dec_u64(self.ino as u64);
            klog::write_raw(b" size="); klog::write_dec_u64(newsz);
            klog::write_raw(b"]\n");
        }
        Ok(done)
    }

    /// Set the authoritative in-memory `size` (truncate/fallocate: the size
    /// change is on disk, keep the writeback clamp in step). # C: O(1)
    pub(crate) fn set_size(&self, size: u64) { self.size.store(size, Ordering::Release); }

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
        #[cfg(feature = "debug-fillverify")]
        self.sums.lock().retain(|&i, _| i < lo || i >= hi);
        n
    }

    // ── internals ────────────────────────────────────────────────────────

    fn mark_dirty(&self, idx: u64) {
        #[cfg(feature = "debug-fillverify")]
        self.sums.lock().remove(&idx); // DIAG: page may legitimately change now
        if self.dirty.lock().insert(idx) { vfs::memory_accounting::account_file_cache_dirty(1); }
        if !self.registered.swap(true, Ordering::AcqRel) {
            if let Some(arc) = self.me.lock().upgrade() { dirty::register(&arc); }
        }
    }

}
