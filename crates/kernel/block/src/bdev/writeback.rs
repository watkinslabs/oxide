//! Writeback for a block-device mapping — the submit half, the wait half, and
//! the invalidation the coherence decorator drives.
//!
//! The split into `fdatawrite` (start I/O on every dirty page) and
//! `fdatawait_keep_errors` (wait for what was started, latch its errors) is
//! the shape `sync(2)` needs: one pass kicks every device, a second collects
//! them, so N devices cost one writeback latency rather than N. Pages are
//! handed to the driver through the owned-request completion path, so a driver
//! with a real hardware queue leaves them under writeback and the wait half
//! genuinely waits; a synchronous driver completes them inline.

extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::Ordering;

use crate::blockdev::BlockRequest;
use crate::types::{BlockError, KResult, PAGE_BYTES};

use super::coherence::page_span;
use super::mapping::{BdevMapping, PG};

impl BdevMapping {
    /// `filemap_fdatawrite` — start writeback on every dirty page. Returns
    /// once each page has been handed to the driver, NOT once it is durable;
    /// [`Self::fdatawait_keep_errors`] is the other half. # C: O(N_dirty)
    pub fn fdatawrite(self: &Arc<Self>) { self.fdatawrite_range(0, u64::MAX) }

    /// `__filemap_fdatawrite_range` — the byte-range-limited submit half.
    /// `end == u64::MAX` means "to the end of the device". # C: O(N_dirty in range)
    pub fn fdatawrite_range(self: &Arc<Self>, start: u64, end: u64) {
        if self.nrpages() == 0 { return; }
        let (lo, hi) = page_span(start, end);
        let batch: Vec<(u64, Vec<u8>)> = {
            let mut g = self.st.lock();
            let idxs = g.dirty.take_writeback_range(lo, hi);
            let mut batch = Vec::with_capacity(idxs.len());
            for idx in idxs {
                let Some(page) = g.pages.get(&idx) else { continue; };
                let payload = page.clone();
                g.writeback.insert(idx);
                batch.push((idx, payload));
            }
            batch
        };
        if batch.is_empty() { return; }
        self.inflight.fetch_add(batch.len(), Ordering::AcqRel);
        for (idx, payload) in batch { self.submit_page(idx, payload); }
    }

    /// Hand one dirty page to the driver. The completion — not this function —
    /// clears its writeback state, which is what makes the wait half real for
    /// a queued driver. # C: O(PG / block_size)
    fn submit_page(self: &Arc<Self>, idx: u64, mut payload: Vec<u8>) {
        let bs = self.dev.block_size() as u64;
        let off = idx.saturating_mul(PG);
        let cap = self.size();
        if bs == 0 || PG % bs != 0 || off >= cap {
            self.complete_page(idx, Err(BlockError::Eio));
            return;
        }
        // The last page of a device whose capacity is not a page multiple
        // carries only the blocks that exist.
        let bytes = core::cmp::min(PG, cap - off);
        let blocks = (bytes / bs) as u32;
        payload.truncate((blocks as usize).saturating_mul(bs as usize));
        crate::charge_io(payload.len() as u64, true);
        let req = BlockRequest::new_write(off / bs, blocks, payload);
        let me = Arc::clone(self);
        self.dev.submit(req, Box::new(move |_req, result| me.complete_page(idx, result)));
    }

    /// Writeback completion for one page: drop its writeback tag, and on
    /// failure re-dirty it and latch the error so the next `fsync` reports it
    /// (Linux `mapping_set_error`). # C: O(log N)
    fn complete_page(&self, idx: u64, result: KResult<()>) {
        {
            let mut g = self.st.lock();
            g.writeback.remove(&idx);
            if let Err(e) = result {
                g.dirty.set_dirty(idx);
                g.dirty.set_error(e as i32);
            }
        }
        self.inflight.fetch_sub(1, Ordering::AcqRel);
    }

    /// Wait for every page this mapping has under writeback. # C: O(in-flight)
    fn wait_for_writeback(&self) {
        while self.inflight.load(Ordering::Acquire) != 0 { core::hint::spin_loop(); }
    }

    /// `filemap_fdatawait_keep_errors` — the wait half of `sync(2)`'s device
    /// pass. Waits for the writeback the submit half started and reports the
    /// accumulated error WITHOUT consuming it, so a later `fsync` on a
    /// block-device fd still sees its own failure. # C: O(in-flight)
    pub fn fdatawait_keep_errors(&self) -> i32 {
        self.wait_for_writeback();
        self.st.lock().dirty.check_and_keep_errors()
    }

    /// `filemap_write_and_wait` — submit, wait, and CONSUME the error (the
    /// `fsync`/last-close path, which reports a writeback failure exactly
    /// once). # C: O(N_dirty)
    pub fn write_and_wait(self: &Arc<Self>) -> KResult<()> {
        self.fdatawrite();
        self.wait_for_writeback();
        match self.st.lock().dirty.check_errors() {
            0 => Ok(()),
            e if e == BlockError::Enospc as i32 => Err(BlockError::Enospc),
            _ => Err(BlockError::Eio),
        }
    }

    /// Write back and then drop every page intersecting `[start, end)`.
    ///
    /// This is what an external write to the same blocks demands: the cached
    /// bytes were written FIRST, so they go to the medium first, and the page
    /// is then dropped so a later raw read re-reads what the external writer
    /// left there. # C: O(pages in range)
    pub fn flush_and_invalidate_range(self: &Arc<Self>, start: u64, end: u64) {
        if self.nrpages() == 0 { return; }
        self.fdatawrite_range(start, end);
        self.wait_for_writeback();
        let (lo, hi) = page_span(start, end);
        let mut g = self.st.lock();
        let victims: Vec<u64> = g.pages.range(lo..hi).map(|(i, _)| *i).collect();
        let mut dropped = 0usize;
        for idx in victims {
            if g.writeback.contains(&idx) || g.dirty.is_dirty(idx) { continue; }
            g.pages.remove(&idx);
            dropped += 1;
        }
        drop(g);
        self.nr.fetch_sub(dropped, Ordering::AcqRel);
    }

    /// Write back every dirty page intersecting `[start, end)` and wait for
    /// it, keeping the pages resident. What an external READ of the same
    /// blocks demands: the reader must see bytes a raw write already put in
    /// the cache. # C: O(N_dirty in range)
    pub fn flush_range(self: &Arc<Self>, start: u64, end: u64) {
        if self.nrpages() == 0 { return; }
        self.fdatawrite_range(start, end);
        self.wait_for_writeback();
    }

    /// `invalidate_bdev` — drop clean, idle pages; dirty or in-flight pages
    /// stay, because dropping them would lose data the medium has not got yet.
    /// Returns the number of pages dropped. # C: O(N_pages)
    pub fn invalidate_clean(&self) -> usize {
        let mut g = self.st.lock();
        let victims: Vec<u64> = g.pages.keys().copied().collect();
        let mut dropped = 0usize;
        for idx in victims {
            if g.writeback.contains(&idx) || g.dirty.is_dirty(idx) { continue; }
            g.pages.remove(&idx);
            dropped += 1;
        }
        drop(g);
        self.nr.fetch_sub(dropped, Ordering::AcqRel);
        dropped
    }

    /// Whether page-aligned `off` is resident (Linux `filemap_get_entry`).
    /// # C: O(log N)
    pub fn is_resident(&self, off: u64) -> bool { self.st.lock().pages.contains_key(&(off / PG)) }
}

/// Page payload length invariant shared by the cache and its writeback.
const _: () = assert!(PAGE_BYTES == PG as usize);
