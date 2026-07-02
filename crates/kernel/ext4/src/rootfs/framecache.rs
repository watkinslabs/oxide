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
use core::sync::atomic::{AtomicBool, Ordering};

use block::types::InodeId;
use sync::{Spinlock, TaskList as TaskListClass};

use super::state::RootfsState;

/// Page granule (Linux PAGE_SIZE). ext4 block size is `<= PG`; a page holds
/// `PG / block_size` consecutive file blocks.
const PG: usize = 4096;

/// Per-inode frame store. One per regular-file inode, held in `Ext4FileData`
/// and shared (via `Arc`) with that inode's `Ext4FileMapping` (`i_mapping`),
/// so every mapper/reader/writer of the inode hits THESE frames.
pub(crate) struct Ext4FrameStore {
    /// Owning mount (device + extent map + journal). Same `Arc` the inode's
    /// `Ext4FileData` holds.
    pub(crate) st:  Arc<RootfsState>,
    /// ext4 inode number this store backs.
    pub(crate) ino: u32,
    /// `page_idx -> frame pa`. Sparse: an absent page is filled from disk on
    /// first touch (a hole reads as zero).
    pages: Spinlock<BTreeMap<u64, u64>, TaskListClass>,
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

/// DIAG: cheap 64-bit FNV-ish page checksum over the HHDM mirror. # C: O(PG)
#[cfg(feature = "debug-fillverify")]
fn page_sum(base: *const u8) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    // SAFETY: caller passes a live HHDM frame mirror; reads stay within PG.
    unsafe {
        let words = base as *const u64;
        for i in 0..(PG / 8) {
            h ^= core::ptr::read_volatile(words.add(i));
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    h
}

impl Ext4FrameStore {
    /// Build a frame store for `ino` on mount `st`. # C: O(1)
    pub(crate) fn new(st: Arc<RootfsState>, ino: u32) -> Arc<Ext4FrameStore> {
        let s = Arc::new(Ext4FrameStore {
            st, ino,
            pages: Spinlock::new(BTreeMap::new()),
            dirty: Spinlock::new(BTreeSet::new()),
            me: Spinlock::new(Weak::new()),
            registered: AtomicBool::new(false),
            #[cfg(feature = "debug-fillverify")]
            sums: Spinlock::new(BTreeMap::new()),
        });
        *s.me.lock() = Arc::downgrade(&s);
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
                Err(_) => return Err(()),
            }
        }
        Ok(())
    }

    /// Resident frame for page `idx`, filling from disk on a miss. Block I/O
    /// runs OUTSIDE the `pages` lock (alloc+fill, then publish), so a slow
    /// device read never serializes other pages and the spinlock never spans
    /// I/O. A concurrent filler that won the publish race frees the loser's
    /// frame. `dinode` is the caller's already-read on-disk inode (avoids a
    /// per-page inode read). # C: O(PG/bs) on miss, O(log N) on hit
    fn ensure_page(&self, dinode: &crate::Inode, idx: u64) -> Option<u64> {
        if let Some(&pa) = self.pages.lock().get(&idx) { return Some(pa); }
        let pa = pmm::setup::alloc_object_frame()?;
        if self.fill_page(dinode, idx, pa).is_err() {
            // SAFETY: pa came from alloc_object_frame (object refcount 1,
            // mapcount 0); release the inode's sole reference → freed.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
            return None;
        }
        // DIAG (debug-fillverify): verify the fill is reproducible — fill a second
        // frame from the same blocks and compare. A mismatch = the block/extent
        // layer returned different bytes for the same page back-to-back.
        #[cfg(feature = "debug-fillverify")]
        let mut fsum = 0u64;
        #[cfg(feature = "debug-fillverify")]
        if let Some(base) = pmm::setup::frame_ptr(pa) {
            fsum = page_sum(base);
            if let Some(pa2) = pmm::setup::alloc_object_frame() {
                if self.fill_page(dinode, idx, pa2).is_ok() {
                    if let Some(base2) = pmm::setup::frame_ptr(pa2) {
                        let s2 = page_sum(base2);
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
        }
        let mut g = self.pages.lock();
        if let Some(&existing) = g.get(&idx) {
            drop(g);
            // SAFETY: lost the publish race; free our now-unused fill frame
            // (object refcount 1, mapcount 0).
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
            return Some(existing);
        }
        g.insert(idx, pa);
        drop(g);
        #[cfg(feature = "debug-fillverify")]
        self.sums.lock().insert(idx, fsum);
        Some(pa)
    }

    /// `MAP_SHARED` writable backing: the inode's persistent frame for the page
    /// at file offset `off`, filled from disk on first touch. The page is
    /// tagged dirty (pessimistic) so a later `writeback` re-persists it.
    /// # C: O(PG/bs) on miss
    pub(crate) fn shared_frame(&self, off: u64) -> Option<u64> {
        let dinode = self.st.mount.read_inode(self.ino).ok()?;
        if !dinode.is_reg() { return None; }
        let idx = off / PG as u64;
        let pa = self.ensure_page(&dinode, idx)?;
        self.mark_dirty(idx);
        Some(pa)
    }

    /// Read-side fill (read(2) / mmap read-fault): copy bytes from the frame
    /// store starting at file offset `off` into `dst`. Short read past i_size;
    /// holes read as zero. Byte-identical to `RootfsState::read_cached`.
    /// # C: O(dst.len)
    pub(crate) fn read_framed(&self, off: u64, dst: &mut [u8]) -> Result<usize, ()> {
        let dinode = self.st.mount.read_inode(self.ino).map_err(|_| ())?;
        if !dinode.is_reg() { return Err(()); }
        let total = dinode.size;
        let mut written = 0usize;
        while written < dst.len() {
            let cur = off + written as u64;
            if cur >= total { break; }
            let idx = cur / PG as u64;
            let pgoff = (cur % PG as u64) as usize;
            let pa = match self.ensure_page(&dinode, idx) { Some(p) => p, None => break };
            let base = pmm::setup::frame_ptr(pa).ok_or(())?;
            // DIAG (debug-fillverify): a clean page must still match its fill-time
            // checksum; a mismatch = something wrote the cached frame since fill.
            #[cfg(feature = "debug-fillverify")]
            if !self.dirty.lock().contains(&idx) {
                if let Some(&want) = self.sums.lock().get(&idx) {
                    let got = page_sum(base);
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
        }
        Ok(written)
    }

    /// write(2) coherency: patch any RESIDENT frame in `[off, off+src.len())`
    /// with `src`, so a `MAP_SHARED` mapper and a subsequent `read` observe the
    /// write. The bytes are also written through to disk by the caller
    /// (`Ext4RegFileOps::write`), so a non-resident page need not be faulted —
    /// its next fault reads the updated disk bytes. # C: O(src.len)
    pub(crate) fn update_resident(&self, off: u64, src: &[u8]) {
        let mut done = 0usize;
        while done < src.len() {
            let cur = off + done as u64;
            let idx = cur / PG as u64;
            let pgoff = (cur % PG as u64) as usize;
            let chunk = (PG - pgoff).min(src.len() - done);
            let pa = self.pages.lock().get(&idx).copied();
            if let Some(pa) = pa {
                if let Some(base) = pmm::setup::frame_ptr(pa) {
                    // SAFETY: pa is an inode-owned resident frame; [pgoff,
                    // pgoff+chunk) ⊆ [0, PG); src slice is distinct.
                    unsafe { core::ptr::copy_nonoverlapping(src[done..].as_ptr(), base.add(pgoff), chunk); }
                    #[cfg(feature = "debug-fillverify")]
                    self.sums.lock().remove(&idx); // DIAG: legit write(2) patch
                }
            }
            done += chunk;
        }
    }

    /// Flush dirty frames (whole file) to disk via `Mount::write_at`
    /// (journaled), clamped to i_size. `fsync`/`msync`/inode-drop driver.
    /// # C: O(N_dirty)
    pub(crate) fn writeback(&self) -> Result<(), ()> {
        self.writeback_idxs(self.take_dirty_all())
    }

    /// Range-limited flush (`sync_file_range` / range `fsync`): flush only
    /// dirty pages intersecting `[start, end)` (`end == u64::MAX` = to EOF).
    /// Pages outside the window stay dirty. # C: O(N_dirty in range)
    pub(crate) fn writeback_range(&self, start: u64, end: u64) -> Result<(), ()> {
        let lo = start / PG as u64;
        let hi = if end == u64::MAX { u64::MAX } else { (end + PG as u64 - 1) / PG as u64 };
        self.writeback_idxs(self.take_dirty_range(lo, hi))
    }

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
        let victims: Vec<(u64, u64)> = {
            let g = self.pages.lock();
            g.range(lo..hi).map(|(&k, &v)| (k, v)).collect()
        };
        let mut n = 0usize;
        {
            let mut g = self.pages.lock();
            for (idx, _) in &victims { g.remove(idx); }
        }
        for (_, pa) in victims {
            // SAFETY: frame removed from the store; release the inode's object
            // reference (a still-mapped peer's inc_ref keeps it alive until
            // that peer's AS teardown decs).
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
            n += 1;
        }
        let mut d = self.dirty.lock();
        d.retain(|&i| i < lo || i >= hi);
        drop(d);
        #[cfg(feature = "debug-fillverify")]
        self.sums.lock().retain(|&i, _| i < lo || i >= hi);
        n
    }

    // ── internals ────────────────────────────────────────────────────────

    fn mark_dirty(&self, idx: u64) {
        #[cfg(feature = "debug-fillverify")]
        self.sums.lock().remove(&idx); // DIAG: page may legitimately change now
        self.dirty.lock().insert(idx);
        if !self.registered.swap(true, Ordering::AcqRel) {
            if let Some(arc) = self.me.lock().upgrade() { register(&arc); }
        }
    }

    fn take_dirty_all(&self) -> Vec<u64> {
        let mut d = self.dirty.lock();
        core::mem::take(&mut *d).into_iter().collect()
    }

    fn take_dirty_range(&self, lo: u64, hi: u64) -> Vec<u64> {
        let mut d = self.dirty.lock();
        let hit: Vec<u64> = d.range(lo..hi).copied().collect();
        for i in &hit { d.remove(i); }
        hit
    }

    /// Flush the given (already-cleared) dirty page indices to disk. Block I/O
    /// runs WITHOUT the `pages` lock held. A failed page is re-marked dirty.
    fn writeback_idxs(&self, idxs: Vec<u64>) -> Result<(), ()> {
        if idxs.is_empty() { return Ok(()); }
        let size = self.st.mount.read_inode(self.ino).map(|i| i.size).unwrap_or(0);
        // Plan under the lock: (idx, page_start, len, pa). No I/O here.
        let mut plan: Vec<(u64, u64, usize, u64)> = Vec::new();
        {
            let g = self.pages.lock();
            for idx in &idxs {
                if let Some(&pa) = g.get(idx) {
                    let page_start = *idx * PG as u64;
                    if page_start >= size { continue; }
                    let len = ((size - page_start) as usize).min(PG);
                    plan.push((*idx, page_start, len, pa));
                }
            }
        }
        let mut err = false;
        for (idx, page_start, len, pa) in plan {
            let base = match pmm::setup::frame_ptr(pa) { Some(b) => b, None => { err = true; continue; } };
            // SAFETY: pa is an inode-owned resident frame; [0, len) ⊆ [0, PG);
            // read-only view handed to the block layer for the duration.
            let slice = unsafe { core::slice::from_raw_parts(base, len) };
            if self.st.mount.write_at(self.ino, page_start, slice).is_err() {
                self.dirty.lock().insert(idx); // re-dirty for a later retry
                err = true;
            }
        }
        // Drop the legacy Vec page-cache view so the metadata path re-reads.
        self.st.page_cache.invalidate(InodeId(self.ino as u64));
        if err { Err(()) } else { Ok(()) }
    }
}

impl Drop for Ext4FrameStore {
    /// Release the inode's reference on every backing frame, flushing dirty
    /// data first (durability on last close / inode eviction). # C: O(N_pages)
    fn drop(&mut self) {
        if !self.dirty.lock().is_empty() { let _ = self.writeback(); }
        let g = self.pages.lock();
        for (_idx, &pa) in g.iter() {
            // SAFETY: pa was alloc_object_frame'd for this inode (object
            // refcount 1, mapcount 0); release the inode's reference → freed
            // when no mapper holds one.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
        }
    }
}

// ── global dirty registry (for msync, which has no fd) ───────────────────────

/// Frame stores that have ever gone dirty (`MAP_SHARED` writable mappings).
/// `msync(2)` carries only an address, not an fd, and this crate must not walk
/// the VMA tree (mm-vmm owns that); so `sys_msync` flushes via this list. A
/// store registers itself on its FIRST dirty transition; dead `Weak`s are
/// pruned on flush. Flushing a superset of the requested range is POSIX-legal.
static DIRTY_STORES: Spinlock<Vec<Weak<Ext4FrameStore>>, TaskListClass> = Spinlock::new(Vec::new());

fn register(s: &Arc<Ext4FrameStore>) {
    DIRTY_STORES.lock().push(Arc::downgrade(s));
}

/// Flush every registered (ever-dirtied) ext4 frame store. The `msync(2)`
/// durability path. Snapshots the list, releases the lock, then flushes
/// (block I/O outside the lock), and prunes dead entries. # C: O(N_stores ·
/// N_dirty)
pub fn flush_all_dirty() {
    let snapshot: Vec<Weak<Ext4FrameStore>> = { DIRTY_STORES.lock().iter().cloned().collect() };
    for w in &snapshot {
        if let Some(s) = w.upgrade() { let _ = s.writeback(); }
    }
    DIRTY_STORES.lock().retain(|w| w.strong_count() > 0);
}

#[cfg(test)]
mod logic_tests {
    // Pure index/range arithmetic for invalidate_range/writeback_range — the
    // page-coverage math, exercised without PMM (frame data paths are covered
    // by the hosted ext4-image fixture test `frame_coherency_image.rs`).
    const PG: u64 = 4096;

    // invalidate_range: page i dropped iff i*PG >= start && (i+1)*PG <= end.
    fn inv_bounds(start: u64, end: u64) -> (u64, u64) {
        let lo = (start + PG - 1) / PG;
        let hi = if end == u64::MAX { u64::MAX } else { end / PG };
        (lo, hi)
    }

    #[test]
    fn invalidate_drops_only_fully_covered_pages() {
        // [0, 2*PG): pages 0,1 fully covered.
        assert_eq!(inv_bounds(0, 2 * PG), (0, 2));
        // [1, 2*PG): page 0 partial (start=1) → not covered; page 1 covered.
        assert_eq!(inv_bounds(1, 2 * PG), (1, 2));
        // [0, 2*PG - 1): page 1 straddles end → not covered.
        assert_eq!(inv_bounds(0, 2 * PG - 1), (0, 1));
        // truncate floors start to a page → partial page IS dropped.
        let len = 3 * PG + 100;
        let floored = len & !(PG - 1);
        let (lo, hi) = inv_bounds(floored, u64::MAX);
        assert_eq!(lo, 3);            // page 3 (holding byte len) dropped
        assert_eq!(hi, u64::MAX);
    }

    // writeback_range: pages intersecting [start, end).
    fn wb_bounds(start: u64, end: u64) -> (u64, u64) {
        let lo = start / PG;
        let hi = if end == u64::MAX { u64::MAX } else { (end + PG - 1) / PG };
        (lo, hi)
    }

    #[test]
    fn writeback_range_covers_intersecting_pages() {
        // A single byte in page 0 → page 0.
        assert_eq!(wb_bounds(0, 1), (0, 1));
        // [PG, PG+1) → page 1 only.
        assert_eq!(wb_bounds(PG, PG + 1), (1, 2));
        // [100, 2*PG+50) → pages 0,1,2.
        assert_eq!(wb_bounds(100, 2 * PG + 50), (0, 3));
        // to EOF.
        assert_eq!(wb_bounds(PG, u64::MAX), (1, u64::MAX));
    }
}
