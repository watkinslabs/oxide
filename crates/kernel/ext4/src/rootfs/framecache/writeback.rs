// Dirty-page flush: takes the dirty-index set, plans a clamped-to-size read
// of each surviving page under one `pages` lock, then issues the actual
// block I/O (bounded adjacent-page clusters, one journal transaction) with
// that lock dropped. Split out of `framecache.rs` per `08§7` (file-length
// cap) — this module owns the plan/flush machinery; the parent owns state
// and the read/write hot paths.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use block::types::InodeId;

use super::{Ext4FrameStore, PG};

/// One writeback admitted before final inode eviction.  The counter spans the
/// complete dirty-tag removal, page copy and journal I/O sequence.
struct WritebackGuard<'a> { store: &'a Ext4FrameStore }

impl Drop for WritebackGuard<'_> {
    fn drop(&mut self) { self.store.active_writebacks.fetch_sub(1, Ordering::Release); }
}

fn start_writeback(dirty: &mut BTreeSet<u64>, writeback: &mut BTreeMap<u64, u32>, idxs: Vec<u64>) -> Vec<u64> {
    for idx in &idxs {
        dirty.remove(idx);
        *writeback.entry(*idx).or_insert(0) += 1;
    }
    idxs
}

fn finish_writeback(writeback: &mut BTreeMap<u64, u32>, idxs: &[u64]) {
    for idx in idxs {
        let Some(count) = writeback.get_mut(idx) else { continue };
        *count -= 1;
        if *count == 0 { writeback.remove(idx); }
    }
}

impl Ext4FrameStore {
    /// Enter writeback unless final eviction has started.  The second flag
    /// test closes `false read -> eviction publishes -> counter increment`:
    /// eviction may observe zero in that window, but this entrant then sees
    /// `evicting` and retires without touching storage. # C: O(1)
    fn begin_writeback(&self) -> Option<WritebackGuard<'_>> {
        if self.evicting.load(Ordering::Acquire) { return None; }
        self.active_writebacks.fetch_add(1, Ordering::AcqRel);
        if self.evicting.load(Ordering::Acquire) {
            self.active_writebacks.fetch_sub(1, Ordering::Release);
            return None;
        }
        Some(WritebackGuard { store: self })
    }

    /// Flush dirty frames (whole file) to disk via `Mount::write_at`
    /// (journaled), clamped to i_size. `fsync`/`msync`/inode-drop driver.
    /// # C: O(N_dirty)
    pub(crate) fn writeback(&self) -> Result<(), ()> {
        let Some(_active) = self.begin_writeback() else { return Ok(()); };
        self.writeback_idxs(self.take_dirty_all())
    }

    /// Range-limited flush (`sync_file_range` / range `fsync`): flush only
    /// dirty pages intersecting `[start, end)` (`end == u64::MAX` = to EOF).
    /// Pages outside the window stay dirty. # C: O(N_dirty in range)
    pub(crate) fn writeback_range(&self, start: u64, end: u64) -> Result<(), ()> {
        let Some(_active) = self.begin_writeback() else { return Ok(()); };
        let lo = start / PG as u64;
        let hi = if end == u64::MAX { u64::MAX } else { (end + PG as u64 - 1) / PG as u64 };
        self.writeback_idxs(self.take_dirty_range(lo, hi))
    }

    fn take_dirty_all(&self) -> Vec<u64> {
        let mut d = self.dirty.lock();
        let mut writeback = self.writeback.lock();
        let pages = d.iter().copied().collect();
        let pages = start_writeback(&mut d, &mut writeback, pages);
        if !pages.is_empty() { vfs::memory_accounting::account_file_cache_writeback_begin(pages.len() as u64); }
        pages
    }

    fn take_dirty_range(&self, lo: u64, hi: u64) -> Vec<u64> {
        let mut d = self.dirty.lock();
        let hit: Vec<u64> = d.range(lo..hi).copied().collect();
        let mut writeback = self.writeback.lock();
        let hit = start_writeback(&mut d, &mut writeback, hit);
        if !hit.is_empty() { vfs::memory_accounting::account_file_cache_writeback_begin(hit.len() as u64); }
        hit
    }

    /// Flush the given (already-cleared) dirty page indices to disk. Block I/O
    /// runs WITHOUT the `pages` lock held. Any failure aborts the journal batch
    /// and re-marks the whole planned set dirty.
    fn writeback_idxs(&self, idxs: Vec<u64>) -> Result<(), ()> {
        if idxs.is_empty() { return Ok(()); }
        #[cfg(feature = "debug-fsync-latency")]
        let writeback_started_ns = crate::fsync_latency::now_ns();
        // Clamp to the authoritative in-memory size (a buffered write grows this
        // before the on-disk i_size), but never below the on-disk size — so a
        // store that predates any buffered write still flushes its full extent.
        let disk = self.st.mount.read_inode(self.ino).map(|i| i.size).unwrap_or(0);
        let size = self.size.load(Ordering::Acquire).max(disk);
        // Plan under the lock: (idx, page_start, len, pa). No I/O here.
        let mut plan: Vec<(u64, u64, usize, u64)> = Vec::new();
        {
            let g = self.pages.lock();
            for idx in &idxs {
                if let Some(page) = g.get(idx) {
                    let page_start = *idx * PG as u64;
                    if page_start >= size { continue; }
                    let len = ((size - page_start) as usize).min(PG);
                    plan.push((*idx, page_start, len, page.pa));
                }
            }
        }
        let mut failed = false;
        // Batch every dirty page of this writeback into ONE journal transaction
        // (Linux jbd2 model), and issue adjacent page-cache frames as bounded
        // clusters. A page-at-a-time call makes `Mount::write_at`'s physical-run
        // coalescer see only one 4KiB block, recreating synchronous per-page
        // I/O for systemd-hwdb. Linux writeback constructs bounded contiguous
        // BIOs from adjacent dirty cache pages; our byte-oriented block API
        // uses this temporary cluster buffer for the same ownership and order.
        let rv = self.st.mount.run_journaled(|_m| {
            let mut cursor = 0usize;
            while cursor < plan.len() {
                if cursor != 0 && (cursor & 0x0f) == 0 {
                    // Linux writeback paths contain cond_resched() points; a
                    // large fsync must not monopolize the CPU while flushing
                    // hundreds of dirty pages from one address_space.
                    crate::mount::cooperative_yield();
                }
                let (_, page_start, _, _) = plan[cursor];
                let mut cluster = Vec::with_capacity(crate::extent_rw::DATA_WRITE_CLUSTER_BYTES);
                let mut next_start = page_start;
                let mut next = cursor;
                while next < plan.len() {
                    let (_, candidate_start, len, pa) = plan[next];
                    if candidate_start != next_start
                        || (!cluster.is_empty()
                            && cluster.len().saturating_add(len) > crate::extent_rw::DATA_WRITE_CLUSTER_BYTES)
                    {
                        break;
                    }
                    // `pa` was captured in `plan` above under the `pages` lock,
                    // which has since been dropped. The PMM shrinker
                    // (scan_clean_pages) can legitimately evict+free this exact
                    // frame in the gap (it only requires "not dirty,
                    // mapcount==0", both true for a page mid-writeback after its
                    // dirty tag cleared but before I/O completes) -- pin the
                    // frame here with the SAME per-page lock the shrinker takes
                    // (mirrors zsmalloc's copy_from/copy_to in
                    // drv-zram/src/zsmalloc/pool.rs) so a concurrent shrinker
                    // pass backs off (try_lock, not block) instead of freeing
                    // out from under this read.
                    if !pmm::setup::try_lock_page(pa) { failed = true; break; }
                    let base = match pmm::setup::frame_ptr(pa) {
                        Some(base) => base,
                        None => { pmm::setup::unlock_page(pa); failed = true; break; }
                    };
                    // DIAG (debug-framecache-verify, B1257 hunt): kept as a
                    // belt-and-suspenders check even with the pin above -- PMM
                    // exposes no per-frame owner/generation id, only a bare
                    // refcount, so this still can't catch a frame freed AND
                    // already reallocated to a new owner before the pin (should
                    // no longer be reachable now that the pin excludes the
                    // shrinker specifically, but leaves the check in place for
                    // any other freeing path this pin doesn't cover).
                    #[cfg(feature = "debug-framecache-verify")]
                    super::verify::verify_pa_live(self.ino, plan[next].0, pa, "writeback_idxs");
                    // SAFETY: pa is an inode-owned resident frame; [0, len) ⊆ [0, PG);
                    // try_lock_page above pins it against the shrinker for this read.
                    let slice = unsafe { core::slice::from_raw_parts(base, len) };
                    cluster.extend_from_slice(slice);
                    pmm::setup::unlock_page(pa);
                    next_start += len as u64;
                    next += 1;
                }
                if !cluster.is_empty() && self.st.mount.write_at(self.ino, page_start, &cluster).is_err() {
                    failed = true;
                }
                cursor = if next == cursor { cursor + 1 } else { next };
            }
            if failed { Err(crate::mount::MountError::BlockIo) } else { Ok(()) }
        });
        let mut redirtied = 0u64;
        if failed || rv.is_err() {
            let mut d = self.dirty.lock();
            for (idx, _, _, _) in &plan {
                if d.insert(*idx) { redirtied += 1; }
            }
        }
        finish_writeback(&mut self.writeback.lock(), &idxs);
        vfs::memory_accounting::account_file_cache_writeback_complete(idxs.len() as u64, redirtied);
        // Drop the legacy Vec page-cache view so the metadata path re-reads.
        self.st.page_cache.invalidate(InodeId(self.ino as u64));
        #[cfg(feature = "debug-fsync-latency")]
        crate::fsync_latency::report(b"writeback", writeback_started_ns, idxs.len() as u64);
        if failed || rv.is_err() { Err(()) } else { Ok(()) }
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::vec;

    use super::{finish_writeback, start_writeback};

    #[test]
    fn overlapping_writebacks_hold_state_until_the_last_completion() {
        let mut dirty = BTreeSet::from([7]);
        let mut writeback = BTreeMap::new();
        let first = start_writeback(&mut dirty, &mut writeback, vec![7]);
        dirty.insert(7);
        let second = start_writeback(&mut dirty, &mut writeback, vec![7]);

        finish_writeback(&mut writeback, &first);
        assert_eq!(writeback.get(&7), Some(&1));
        finish_writeback(&mut writeback, &second);
        assert!(!writeback.contains_key(&7));
    }
}
