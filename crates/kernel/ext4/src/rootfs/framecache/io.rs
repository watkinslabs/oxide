use super::*;

impl Ext4FrameStore {
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
            let pa = self.lock_cache_page(idx)
                .inspect_err(|_| super::fill_err(b"lock-cache-page", self.ino, idx))?;
            let Some(base) = pmm::setup::frame_ptr(pa) else {
                super::fill_err(b"frame-ptr-none", self.ino, idx);
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

}
