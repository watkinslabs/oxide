//! The write side as a FILESYSTEM uses it (`17§4.3`): a whole-mapping
//! writeback target, a dirty mark that does not write back, and a balance the
//! writer makes for itself once its own locks are gone.
//!
//! The properties under test are data-integrity ones, not plumbing ones: a
//! write not yet written back is still readable, a sync puts it on the medium
//! exactly once, nothing evicts a dirty page, and a machine that stops before
//! a sync loses exactly what was not synced.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::pagecache::tests::fresh_machine;
use crate::pagecache::{
    install_totalram_pages, nr_dirty, shrink, PageCache, PageOut, Writeback,
};
use crate::types::{BlockError, InodeId, KResult, PAGE_BYTES};

const INO: InodeId = InodeId(7);
fn page(byte: u8) -> Vec<u8> { vec![byte; PAGE_BYTES] }

/// A filesystem's own writeback target: it keeps a medium of its own, records
/// every visit's batch size, and can be told to report fewer pages than it was
/// handed — which is what a target that half-fails looks like from the cache.
struct FsTarget {
    medium:  Mutex<BTreeMap<u64, Vec<u8>>>,
    /// Pages per `writepages` call, in call order.
    visits:  Mutex<Vec<usize>>,
    /// Report at most this many pages of each batch. `usize::MAX` = all.
    report:  Mutex<usize>,
    /// Fail (rather than skip) this many pages, from the front of each batch.
    fail:    Mutex<usize>,
    syncs:   Mutex<usize>,
}

impl FsTarget {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            medium: Mutex::new(BTreeMap::new()), visits: Mutex::new(Vec::new()),
            report: Mutex::new(usize::MAX), fail: Mutex::new(0), syncs: Mutex::new(0),
        })
    }
    fn visits(&self) -> Vec<usize> { self.visits.lock().unwrap().clone() }
    fn pages_written(&self) -> usize { self.visits.lock().unwrap().iter().sum() }
    fn syncs(&self) -> usize { *self.syncs.lock().unwrap() }
    fn medium_page(&self, offset: u64) -> Option<Vec<u8>> {
        self.medium.lock().unwrap().get(&offset).cloned()
    }
}

impl Writeback for FsTarget {
    fn writepages(&self, _ino: InodeId, pages: &[PageOut<'_>], results: &mut [KResult<()>]) {
        let report = *self.report.lock().unwrap();
        let mut fail = *self.fail.lock().unwrap();
        let mut landed = 0usize;
        for (i, p) in pages.iter().enumerate() {
            if i >= report { break; }
            if fail > 0 { fail -= 1; results[i] = Err(BlockError::Eio); continue; }
            self.medium.lock().unwrap().insert(p.offset, p.data.to_vec());
            results[i] = Ok(());
            landed += 1;
        }
        self.visits.lock().unwrap().push(landed);
    }
    fn sync_medium(&self) -> KResult<()> {
        *self.syncs.lock().unwrap() += 1;
        Ok(())
    }
}

/// A cache with `fs` installed as `INO`'s target and `n` uptodate pages in it,
/// filled from the target's own medium the way a read would fill them.
fn cache_with(fs: &Arc<FsTarget>, n: u64) -> PageCache {
    let pc = PageCache::new();
    pc.set_writeback(INO, fs.clone());
    for i in 0..n {
        let off = i * PAGE_BYTES as u64;
        let seed = fs.medium_page(off).unwrap_or_else(|| page(0));
        pc.read_page_with(INO, off, || Ok(seed)).unwrap();
    }
    pc
}

/// Put `bytes` into a resident page and mark it dirty, which is what a
/// filesystem's `write_end` does.
fn dirty(pc: &PageCache, off: u64, bytes: &[u8]) -> KResult<bool> {
    let p = pc.lookup(INO, off).expect("resident");
    p.data.lock().copy_from_slice(bytes);
    pc.mark_dirty(INO, off)
}

#[test]
fn a_whole_batch_reaches_the_target_in_one_visit() {
    let _m = fresh_machine();
    let fs = FsTarget::new();
    let pc = cache_with(&fs, 3);
    for i in 0..3u64 { dirty(&pc, i * PAGE_BYTES as u64, &page(0xA0 + i as u8)).unwrap(); }
    assert_eq!(fs.visits(), Vec::<usize>::new(), "dirtying alone reaches no target");
    pc.sync(INO).unwrap();
    assert_eq!(fs.visits(), vec![3], "one visit, three pages — not three visits");
    assert_eq!(fs.syncs(), 1);
}

#[test]
fn marking_dirty_never_enters_the_writeback_target() {
    // The deadlock property. A filesystem dirties a page holding the lock its
    // own target needs; if the mark wrote back, that call would re-enter the
    // target and take the lock its caller already holds.
    let _m = fresh_machine();
    install_totalram_pages(4); // limit = 20% of 4 = 0, so every ladder rung fires
    let fs = FsTarget::new();
    let pc = cache_with(&fs, 3);
    for i in 0..3u64 { dirty(&pc, i * PAGE_BYTES as u64, &page(0xB0)).unwrap(); }
    assert_eq!(fs.visits(), Vec::<usize>::new(), "over the limit and still not entered");
    assert_eq!(nr_dirty(), 3);
    // The writer balances for itself, once its own locks are gone.
    pc.balance_dirty(INO);
    assert!(fs.pages_written() > 0, "the balance is what enters the target");
}

#[test]
fn a_mapping_with_no_target_cannot_be_dirtied() {
    // A dirty page with nowhere to go is un-flushable: `sync` would report
    // success having written nothing, and reclaim could never evict it.
    let _m = fresh_machine();
    let pc = PageCache::new();
    pc.read_page_with(INO, 0, || Ok(page(1))).unwrap();
    assert_eq!(pc.mark_dirty(INO, 0), Err(BlockError::Einval));
    assert_eq!(pc.dirty_count(INO), 0);
    assert_eq!(nr_dirty(), 0);
    assert!(!pc.lookup(INO, 0).unwrap().is_dirty());
}

#[test]
fn a_page_the_target_does_not_report_stays_dirty_and_keeps_its_bytes() {
    // A target that returns having written only part of the batch must leave
    // the rest dirty. Assuming success for an unreported page throws away the
    // only copy of a write the caller was told had succeeded.
    let _m = fresh_machine();
    let fs = FsTarget::new();
    let pc = cache_with(&fs, 3);
    for i in 0..3u64 { dirty(&pc, i * PAGE_BYTES as u64, &page(0xC0 + i as u8)).unwrap(); }
    *fs.report.lock().unwrap() = 1;
    let (n, r) = pc.writeback(INO, usize::MAX);
    assert_eq!(n, 1);
    assert!(r.is_err(), "the unreported pages are a failure, not a silence");
    assert_eq!(pc.dirty_count(INO), 2, "the two it never spoke of are still dirty");
    assert_eq!(nr_dirty(), 2);
    for i in 1..3u64 {
        let off = i * PAGE_BYTES as u64;
        assert_eq!(*pc.lookup(INO, off).unwrap().data.lock(), page(0xC0 + i as u8));
    }
    // And a later pass, with the target behaving, finishes the job.
    *fs.report.lock().unwrap() = usize::MAX;
    pc.sync(INO).unwrap();
    assert_eq!(pc.dirty_count(INO), 0);
    for i in 0..3u64 {
        assert_eq!(fs.medium_page(i * PAGE_BYTES as u64).unwrap(), page(0xC0 + i as u8));
    }
}

#[test]
fn a_write_not_yet_written_back_is_still_what_a_reader_gets() {
    let _m = fresh_machine();
    let fs = FsTarget::new();
    fs.medium.lock().unwrap().insert(0, page(0x11));
    let pc = cache_with(&fs, 1);
    dirty(&pc, 0, &page(0x22)).unwrap();
    assert_eq!(*pc.lookup(INO, 0).unwrap().data.lock(), page(0x22), "the reader sees the write");
    assert_eq!(fs.medium_page(0).unwrap(), page(0x11), "the medium does not, yet");
    pc.sync(INO).unwrap();
    assert_eq!(fs.medium_page(0).unwrap(), page(0x22));
}

#[test]
fn sync_puts_a_dirty_page_on_the_medium_exactly_once() {
    let _m = fresh_machine();
    let fs = FsTarget::new();
    let pc = cache_with(&fs, 1);
    dirty(&pc, 0, &page(0x33)).unwrap();
    pc.sync(INO).unwrap();
    assert_eq!(fs.pages_written(), 1);
    pc.sync(INO).unwrap();
    assert_eq!(fs.pages_written(), 1, "nothing dirty, nothing written");
    assert_eq!(fs.syncs(), 2, "the barrier is still asked for");
}

#[test]
fn eviction_cleans_a_dirty_page_rather_than_dropping_it() {
    let _m = fresh_machine();
    let fs = FsTarget::new();
    let pc = cache_with(&fs, 1);
    dirty(&pc, 0, &page(0x44)).unwrap();
    // Twice: the first pass clears the reference the fill left, the second
    // meets a dirty page and has to write it rather than free it.
    shrink(1);
    shrink(1);
    assert_eq!(fs.medium_page(0).unwrap(), page(0x44), "written, not lost");
    assert_eq!(pc.cached_count(), 1, "and not evicted in the same pass");
}

#[test]
fn a_stop_before_the_sync_loses_exactly_what_was_not_synced() {
    let _m = fresh_machine();
    let fs = FsTarget::new();
    let pc = cache_with(&fs, 2);
    dirty(&pc, 0, &page(0x55)).unwrap();
    pc.sync(INO).unwrap();
    dirty(&pc, PAGE_BYTES as u64, &page(0x66)).unwrap();
    drop(pc); // the machine stops here
    assert_eq!(fs.medium_page(0).unwrap(), page(0x55), "the synced page survived");
    assert_eq!(fs.medium_page(PAGE_BYTES as u64), None, "the unsynced one did not");
    assert_eq!(nr_dirty(), 0, "and the machine's dirty count went with the cache");
}

#[test]
fn a_failed_page_is_re_dirtied_and_reported() {
    let _m = fresh_machine();
    let fs = FsTarget::new();
    let pc = cache_with(&fs, 2);
    dirty(&pc, 0, &page(0x77)).unwrap();
    dirty(&pc, PAGE_BYTES as u64, &page(0x88)).unwrap();
    *fs.fail.lock().unwrap() = 1;
    assert_eq!(pc.sync(INO), Err(BlockError::Eio));
    assert_eq!(pc.dirty_count(INO), 1, "the failed page went back on the list");
    assert_eq!(nr_dirty(), 1);
    assert_eq!(*pc.lookup(INO, 0).unwrap().data.lock(), page(0x77), "with its bytes intact");
    *fs.fail.lock().unwrap() = 0;
    pc.sync(INO).unwrap();
    assert_eq!(fs.medium_page(0).unwrap(), page(0x77));
}

// ---------------------------------------------- one named page, chosen by the FS

/// A sink that records what it was handed and lands it in `fs`'s medium — what
/// a filesystem already inside its own flush point passes, rather than letting
/// the cache enter the installed target and take a lock it is holding.
fn into_medium<'a>(fs: &'a Arc<FsTarget>, fail: bool)
    -> impl FnMut(InodeId, &[PageOut<'_>], &mut [KResult<()>]) + 'a {
    move |ino, pages, results| {
        if fail { return; } // slots arrive prefilled with a failure
        fs.writepages(ino, pages, results);
    }
}

#[test]
fn a_single_named_page_written_back_stays_resident_and_clean() {
    // The property a log-structured filesystem's ordered flush needs: it names
    // ONE page, that page's dirty state ends, and the page itself is still
    // here — so the next read of it costs nothing. Invalidating instead is
    // correct and colder, and is what this asserts against.
    let _m = fresh_machine();
    let fs = FsTarget::new();
    let pc = cache_with(&fs, 2);
    dirty(&pc, 0, &page(0x91)).unwrap();
    dirty(&pc, PAGE_BYTES as u64, &page(0x92)).unwrap();

    let (n, out) = pc.writeback_page_with(INO, 0, &mut into_medium(&fs, false));
    assert_eq!((n, out), (1, Ok(())));
    assert_eq!(fs.visits(), vec![1], "the batch was not the one page named");
    assert_eq!(fs.medium_page(0).unwrap(), page(0x91));
    assert_eq!(fs.medium_page(PAGE_BYTES as u64), None, "the unnamed page was written too");

    let held = pc.lookup(INO, 0).expect("the placed page was dropped, not cleaned");
    assert!(!held.is_dirty(), "the placed page is still dirty");
    assert_eq!(*held.data.lock(), page(0x91), "the placed page lost its bytes");
    assert_eq!(pc.dirty_count(INO), 1, "the unnamed page did not stay dirty");
    assert_eq!(nr_dirty(), 1);
}

#[test]
fn a_single_named_page_the_sink_did_not_report_is_re_dirtied() {
    // The same rule the batch path follows: an unreported page keeps the only
    // copy of the bytes and stays on the dirty list for the next flush.
    let _m = fresh_machine();
    let fs = FsTarget::new();
    let pc = cache_with(&fs, 1);
    dirty(&pc, 0, &page(0x93)).unwrap();
    let (n, out) = pc.writeback_page_with(INO, 0, &mut into_medium(&fs, true));
    assert_eq!(n, 0);
    assert_eq!(out, Err(BlockError::Eio));
    assert_eq!(pc.dirty_count(INO), 1, "the unwritten page went clean");
    assert_eq!(*pc.lookup(INO, 0).unwrap().data.lock(), page(0x93));
}

#[test]
fn a_single_named_page_that_is_already_clean_is_written_nowhere() {
    // Someone else wrote it. Not this caller's error, and not a second write
    // of a block the log has already handed out.
    let _m = fresh_machine();
    let fs = FsTarget::new();
    let pc = cache_with(&fs, 1);
    let (n, out) = pc.writeback_page_with(INO, 0, &mut into_medium(&fs, false));
    assert_eq!((n, out), (0, Ok(())));
    assert_eq!(fs.visits(), Vec::<usize>::new(), "a clean page reached the sink");
}
