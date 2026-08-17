//! Writeback and reclaim passes (`17§4.3` steps 5-6, `17§4.4`).
//!
//! One place puts a dirty page on the medium: [`writeback_mapping`]. `fsync`,
//! the flusher and reclaim all call it, so "the page reached the medium" and
//! "the page is no longer dirty" are decided together and cannot disagree.
//!
//! The ordering that matters: a page is taken OFF the dirty list and marked
//! under writeback in the same locked step, and put back on the dirty list if
//! the write failed. Between those two points the page is neither evictable
//! (`17§1` invariant 3) nor a second flusher's work, and a failure leaves the
//! only copy of the bytes exactly where it was.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::Ordering;

use crate::blockdev::{BlockDevice, BlockRequest};
use crate::types::{BlockError, InodeId, KResult, PageFlags, PAGE_BYTES};

use super::global;
use super::mapping::{Mapping, PageOut, Writeback};

/// Writeback straight to a block device, file offset taken as device offset.
/// What a `PageCache` used over a raw device gets; a filesystem that
/// translates file offsets to physical blocks installs its own target.
pub struct DevWriteback { dev: Arc<dyn BlockDevice> }

impl DevWriteback {
    /// # C: O(1)
    pub fn new(dev: Arc<dyn BlockDevice>) -> Arc<dyn Writeback> { Arc::new(Self { dev }) }
}

impl DevWriteback {
    /// # C: O(PAGE_BYTES / block_size)
    fn write_one(&self, offset: u64, data: &[u8]) -> KResult<()> {
        let bs = self.dev.block_size() as u64;
        if bs == 0 || PAGE_BYTES as u64 % bs != 0 { return Err(BlockError::Einval); }
        let blocks = (PAGE_BYTES as u64 / bs) as u32;
        let mut req = BlockRequest::new_write(offset / bs, blocks, data.to_vec());
        self.dev.submit_sync(&mut req)?;
        crate::charge_io(PAGE_BYTES as u64, true);
        Ok(())
    }
}

impl Writeback for DevWriteback {
    /// A device mapping's page address IS its file offset, so a batch has no
    /// decision to take as a batch and is written page by page.
    /// # C: O(pages * PAGE_BYTES / block_size)
    fn writepages(&self, _ino: InodeId, pages: &[PageOut<'_>], results: &mut [KResult<()>]) {
        for (i, p) in pages.iter().enumerate() { results[i] = self.write_one(p.offset, p.data); }
    }

    /// # C: O(device flush)
    fn sync_medium(&self) -> KResult<()> { self.dev.flush() }
}

/// Where a claimed batch is put. The installed target is one; a filesystem
/// already inside its own writeback is the other — see [`writeback_mapping_with`].
pub type Sink<'s> = &'s mut dyn FnMut(InodeId, &[PageOut<'_>], &mut [KResult<()>]);

/// Write back up to `max` of one mapping's dirty pages and report how many
/// reached the medium. The first failure is returned once every page in the
/// batch has been attempted, so one bad block does not strand the rest.
/// # Ctx: process # Sleeps: y # C: O(pages written)
pub fn writeback_mapping(map: &Arc<Mapping>, max: usize) -> (usize, KResult<()>) {
    let Some(wb) = map.writeback_target() else { return (0, Ok(())); };
    let batch = map.take_for_writeback(max);
    submit_batch(map, &mut |ino, pages, results| wb.writepages(ino, pages, results), batch)
}

/// The same, into a sink the caller supplies instead of the installed target.
///
/// The installed target is entered from OUTSIDE the filesystem — the flusher
/// and reclaim reach a mapping holding none of that filesystem's locks, so the
/// target is free to take them. A filesystem's own flush points are the other
/// direction: `fsync`, a checkpoint and a truncate are already holding the
/// state the target would have to acquire, and calling through it would have
/// them wait on themselves. They pass the sink directly, and the claim and the
/// completion — which decide together whether a page is still dirty — stay in
/// the one place either way.
/// # Ctx: process # Sleeps: y # C: O(pages written)
pub fn writeback_mapping_with(map: &Arc<Mapping>, max: usize, sink: Sink<'_>)
    -> (usize, KResult<()>) {
    let batch = map.take_for_writeback(max);
    submit_batch(map, sink, batch)
}

/// [`writeback_mapping_with`] restricted to the INCLUSIVE index range
/// `[lo, hi]`.
///
/// What a range `fsync` and `sync_file_range(2)` ask for, and the difference
/// from the unbounded form is the whole cost of the call: a one-page range
/// `fsync` of a large file has no business writing every unplaced page of it.
/// A page outside the range keeps its dirty state and is the next unbounded
/// flush's work, so this loses nothing — it is narrower, not weaker.
/// # Ctx: process # Sleeps: y # C: O(dirty pages in range)
pub fn writeback_range_with(map: &Arc<Mapping>, lo: u64, hi: u64, max: usize, sink: Sink<'_>)
    -> (usize, KResult<()>) {
    if hi < lo { return (0, Ok(())); }
    let batch = map.take_range_for_writeback(lo, hi, max);
    submit_batch(map, sink, batch)
}

/// Write back exactly the named page if it is dirty. Reclaim's cleaning step:
/// `17§4.4` makes writeback the precondition of evicting a dirty page, and the
/// page reclaim chose is the one that has to be cleaned. # C: O(1 page)
pub fn writeback_page(map: &Arc<Mapping>, index: u64) -> bool {
    let Some(wb) = map.writeback_target() else { return false; };
    let (written, _) = writeback_page_with(map, index,
        &mut |ino, pages, results| wb.writepages(ino, pages, results));
    written == 1
}

/// Write back exactly the named page, into a sink the caller supplies.
///
/// [`writeback_mapping_with`] restricted to ONE named index — what a
/// filesystem whose flush point chooses its pages one at a time needs, and it
/// needs it because there is no other way to end a page's dirty state without
/// losing the page. The alternative such a caller is left with is to place the
/// bytes itself and then INVALIDATE the index, which throws away a page that
/// is now clean and correct and sends the next read of it back to the medium.
///
/// The claim and the completion stay in `submit_batch` with every other
/// writeback: a page is taken off the dirty list and marked under writeback in
/// one locked step, and put back on it if the sink reports a failure. Nothing
/// here is a way to clear the dirty bit and walk away — the page is under
/// writeback for exactly as long as the sink is running, which is the same
/// window the flusher and reclaim observe.
///
/// A page that is absent or already clean is `(0, Ok(()))`: someone else wrote
/// it, which is not this caller's error.
/// # Ctx: process # Sleeps: y # C: O(1 page)
pub fn writeback_page_with(map: &Arc<Mapping>, index: u64, sink: Sink<'_>) -> (usize, KResult<()>) {
    let Some(page) = map.take_index_for_writeback(index) else { return (0, Ok(())); };
    submit_batch(map, sink, alloc::vec![(index, page)])
}

/// Put an already-claimed batch on the medium, keeping the global counters and
/// the per-page state in step at every point.
fn submit_batch(map: &Arc<Mapping>, sink: Sink<'_>, batch: Vec<(u64, Arc<super::page::CachedPage>)>)
    -> (usize, KResult<()>)
{
    if batch.is_empty() { return (0, Ok(())); }
    let n = batch.len();
    global::account_dirty(-(n as isize));
    global::account_writeback(n as isize);
    map.inflight.fetch_add(n, Ordering::AcqRel);

    // Every payload is copied out from under the page locks BEFORE the target
    // is entered: the target is a filesystem or a driver call and may sleep,
    // which nothing may do holding a spinlock, and it is handed the whole
    // batch at once so it can decide the batch's placement as a batch.
    let payloads: Vec<Vec<u8>> = batch.iter().map(|(_, p)| p.data.lock().to_vec()).collect();
    let pages: Vec<PageOut<'_>> = batch.iter().zip(payloads.iter())
        .map(|((_, p), buf)| PageOut { offset: p.offset, data: buf }).collect();
    // Prefilled with a failure, so a target that returns without reporting a
    // page leaves that page re-dirtied rather than silently dropped.
    let mut results: Vec<KResult<()>> = (0..n).map(|_| Err(BlockError::Eio)).collect();
    sink(map.ino(), &pages, &mut results);
    drop(pages);

    let mut written = 0usize;
    let mut first_err: KResult<()> = Ok(());
    for ((index, _), result) in batch.into_iter().zip(results.into_iter()) {
        let requeued = map.end_writeback(index, result.is_ok());
        global::account_writeback(-1);
        map.inflight.fetch_sub(1, Ordering::AcqRel);
        if requeued { global::account_dirty(1); }
        match result {
            Ok(()) => written += 1,
            Err(e) => { if first_err.is_ok() { first_err = Err(e); } }
        }
    }
    (written, first_err)
}

/// One `kflushd` visit (`17§4.3` step 5): write back dirty mappings while the
/// machine is over its background dirty threshold, plus any mapping that has
/// been dirty longer than the expiry regardless of the threshold. Returns
/// pages written.
///
/// Ungated and driven by its arguments, so what the daemon does is checkable
/// without a daemon. # Ctx: process # Sleeps: y # C: O(pages written)
pub fn flush_pass(now: u64) -> usize {
    let background = global::background_threshold();
    let mut over = background > 0 && global::nr_dirty() > background;
    let mut written = 0usize;
    for map in global::dirty_inodes() {
        let expired = global::dirty_expired(map.dirtied_when.load(Ordering::Acquire), now);
        if !over && !expired { continue; }
        let (n, _) = writeback_mapping(&map, global::WRITEBACK_BATCH);
        written += n;
        if map.nr_dirty() == 0 { map.dirtied_when.store(0, Ordering::Release); }
        if over && global::nr_dirty() <= background { over = false; }
    }
    written
}

/// Reclaim `target` pages from the inactive list (`17§4.4`).
///
/// Per candidate, oldest first: a page under I/O is left alone; a page
/// referenced since it was queued gets its reference cleared and another pass;
/// a DIRTY page is written back and NOT evicted this round; only a clean, idle,
/// unreferenced page is dropped. Returns pages actually freed.
///
/// The dirty rule is the whole point: a cache that evicts a dirty page has
/// thrown away the only copy of a write the caller was told had succeeded.
/// # Ctx: process # Sleeps: y # C: O(target)
pub fn shrink(target: usize) -> usize {
    if target == 0 { return 0; }
    let mut freed = 0usize;
    for (map, index) in global::inactive_candidates(target) {
        if freed >= target { break; }
        let Some(page) = map.get(index) else { continue; };
        if page.is_locked() || page.is_writeback() { continue; }
        // A page a user page table maps is not reclaim's to take, and for a
        // different reason from the dirty rule below: dropping it leaves the
        // mapper writing a frame this cache has stopped tracking, and the next
        // fill of the same offset takes a different frame — two live copies of
        // one page. The reference unmaps a folio before it may evict it; nothing
        // here can, so the page stays.
        if page.user_mapped() { continue; }
        if page.flags().contains(PageFlags::REFERENCED) { page.clear_flags(PageFlags::REFERENCED); continue; }
        if page.is_dirty() { writeback_page(&map, index); continue; }
        if map.evict(index).is_some() { global::account_cached(-1); freed += 1; }
    }
    freed
}

/// Reclaimable pages for the memory-pressure count: clean resident pages are
/// droppable now, dirty ones are not until they have been written.
/// # C: O(1)
pub fn reclaimable_pages() -> usize {
    global::nr_cached().saturating_sub(global::nr_dirty()).saturating_sub(global::nr_writeback())
}
