//! Block-device page cache contract.
//!
//! What these pin: a raw device write is CACHED (not passed straight to the
//! driver), `sync(2)`'s submit half actually writes those pages back, the wait
//! half waits for the driver and keeps the error for a later `fsync`, and a
//! filesystem's own I/O through the published device handle can never see a
//! different block than a raw open of the same disk.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, Ordering};

use sync::{Inode as InodeClass, Spinlock};

use crate::blockdev::{BlockCompletion, BlockDevice, BlockRequest, MemDisk};
use crate::types::{BlockError, KResult, PAGE_BYTES};

use super::coherence::page_span;
use super::mapping::BdevMapping;

const BS: u32 = 512;
const PG: u64 = PAGE_BYTES as u64;

/// A disk plus a handle that reaches the MEDIUM directly, so a test can ask
/// "what is actually on the device" without going through the cache.
fn medium(blocks: u64) -> Arc<MemDisk<InodeClass>> { MemDisk::<InodeClass>::new(BS, blocks) }

fn mapping_over(dev: Arc<dyn BlockDevice>) -> Arc<BdevMapping> { BdevMapping::new(dev) }

/// Bytes physically at `off` on the medium (never via the cache).
fn on_medium(dev: &dyn BlockDevice, off: u64, len: usize) -> Vec<u8> {
    let first = off / BS as u64;
    let last_excl = (off + len as u64 + BS as u64 - 1) / BS as u64;
    let mut req = BlockRequest::new_read(first, (last_excl - first) as u32, BS);
    dev.submit_sync(&mut req).unwrap();
    let inner = (off - first * BS as u64) as usize;
    req.buffer[inner..inner + len].to_vec()
}

// ---- the cache itself -----------------------------------------------------

// The core of the ledger row: a raw block-device write must land in a page and
// be tagged dirty, NOT go straight to the driver — otherwise the device pass
// of `sync(2)` has nothing to submit.
#[test]
fn raw_write_is_cached_and_dirty_until_writeback() {
    let disk = medium(64);
    let m = mapping_over(disk.clone());
    assert_eq!(m.write_at(1000, &[0xAB; 300]).unwrap(), 300);
    assert_eq!(m.dirty_pages(), 1, "the write dirtied exactly one page");
    assert_eq!(m.nrpages(), 1);
    assert!(on_medium(disk.as_ref(), 1000, 300).iter().all(|&b| b == 0),
        "nothing reached the medium at write(2) time");

    // A read of the same bytes is served from the cache.
    let mut buf = [0u8; 300];
    assert_eq!(m.read_at(1000, &mut buf).unwrap(), 300);
    assert!(buf.iter().all(|&b| b == 0xAB));

    // Submit half, then wait half.
    m.fdatawrite();
    assert_eq!(m.fdatawait_keep_errors(), 0);
    assert_eq!(m.dirty_pages(), 0, "writeback cleared the dirty tags");
    assert!(on_medium(disk.as_ref(), 1000, 300).iter().all(|&b| b == 0xAB));
}

// A write spanning a page boundary dirties both pages, and both are written.
#[test]
fn write_across_a_page_boundary_dirties_both_pages() {
    let disk = medium(64);
    let m = mapping_over(disk.clone());
    m.write_at(PG - 8, &[0x5A; 16]).unwrap();
    assert_eq!(m.dirty_pages(), 2);
    m.fdatawrite();
    m.fdatawait_keep_errors();
    assert_eq!(on_medium(disk.as_ref(), PG - 8, 16), vec![0x5A; 16]);
}

// Reads and writes past the end of the device are EOF/short, never an error —
// the behaviour a positioned block-device fd has at its end.
#[test]
fn io_past_end_of_device_is_short_not_an_error() {
    let disk = medium(2); // 1024 bytes
    let m = mapping_over(disk.clone());
    let mut buf = [0u8; 512];
    assert_eq!(m.read_at(1024, &mut buf).unwrap(), 0);
    assert_eq!(m.read_at(1000, &mut buf).unwrap(), 24);
    assert_eq!(m.write_at(1024, &[1u8; 8]).unwrap(), 0);
    assert_eq!(m.write_at(1020, &[1u8; 8]).unwrap(), 4, "clamped to capacity");
}

// A device whose capacity is not a page multiple must still write back its
// last, partial page — only the blocks that exist.
#[test]
fn writeback_of_a_partial_last_page_writes_only_real_blocks() {
    let disk = medium(9); // 4608 bytes: one full page + one 512 B block
    let m = mapping_over(disk.clone());
    m.write_at(PG, &[0x77; 512]).unwrap();
    m.fdatawrite();
    assert_eq!(m.fdatawait_keep_errors(), 0);
    assert_eq!(on_medium(disk.as_ref(), PG, 512), vec![0x77; 512]);
}

// ---- the two-pass shape ---------------------------------------------------

/// A driver that holds submitted requests until the test completes them — the
/// queued-driver case, where the wait half of `sync(2)` has real work to do.
struct DeferredDisk {
    inner: Arc<MemDisk<InodeClass>>,
    held: Spinlock<Vec<(BlockRequest, BlockCompletion)>, InodeClass>,
}

impl DeferredDisk {
    fn new(blocks: u64) -> Arc<Self> {
        Arc::new(Self { inner: MemDisk::<InodeClass>::new(BS, blocks), held: Spinlock::new(Vec::new()) })
    }
    fn complete_all(&self) {
        let held: Vec<(BlockRequest, BlockCompletion)> = core::mem::take(&mut *self.held.lock());
        for (mut req, done) in held {
            let r = self.inner.submit_sync(&mut req);
            done(req, r);
        }
    }
}

impl BlockDevice for DeferredDisk {
    fn block_size(&self) -> u32 { BS }
    fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }
    fn submit(&self, request: BlockRequest, completion: BlockCompletion) {
        self.held.lock().push((request, completion));
    }
    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> { self.inner.submit_sync(req) }
    fn flush(&self) -> KResult<()> { Ok(()) }
}

// The submit half starts I/O and returns; the page stays under writeback until
// the driver completes it, which is exactly what the wait half waits for.
#[test]
fn submit_half_starts_io_and_the_page_stays_under_writeback() {
    let dev = DeferredDisk::new(64);
    let m = mapping_over(dev.clone());
    m.write_at(0, &[0x11; 64]).unwrap();
    m.fdatawrite();
    assert_eq!(m.writeback_pages(), 1, "handed to the driver, not yet complete");
    assert_eq!(m.dirty_pages(), 0, "no longer dirty: it is under writeback");
    assert!(on_medium(dev.inner.as_ref(), 0, 64).iter().all(|&b| b == 0));
    dev.complete_all();
    assert_eq!(m.writeback_pages(), 0);
    assert_eq!(m.fdatawait_keep_errors(), 0);
    assert_eq!(on_medium(dev.inner.as_ref(), 0, 64), vec![0x11; 64]);
}

/// A device whose writes fail, for the error-latch contract.
struct FailingDisk { blocks: u64, fail: AtomicBool }
impl BlockDevice for FailingDisk {
    fn block_size(&self) -> u32 { BS }
    fn capacity_blocks(&self) -> u64 { self.blocks }
    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        if req.op == crate::BlockOp::Write && self.fail.load(Ordering::Acquire) { return Err(BlockError::Eio); }
        if req.op == crate::BlockOp::Read { for b in req.buffer.iter_mut() { *b = 0; } }
        Ok(())
    }
    fn flush(&self) -> KResult<()> { Ok(()) }
}

// A failed writeback re-dirties the page and latches the error. The wait half
// of `sync(2)` REPORTS it without consuming it, so the next `fsync` on that
// device still sees its own failure — the whole point of the keep-errors
// variant.
#[test]
fn failed_writeback_latches_an_error_the_wait_half_keeps() {
    let dev = Arc::new(FailingDisk { blocks: 64, fail: AtomicBool::new(true) });
    let m = mapping_over(dev.clone());
    m.write_at(0, &[0x22; 64]).unwrap();
    m.fdatawrite();
    assert_eq!(m.dirty_pages(), 1, "a failed page is re-dirtied for a later retry");
    assert_eq!(m.fdatawait_keep_errors(), BlockError::Eio as i32);
    assert_eq!(m.fdatawait_keep_errors(), BlockError::Eio as i32,
        "sync(2) does not consume the error");
    // fsync is the reporter of record: it sees the failure once.
    dev.fail.store(false, Ordering::Release);
    assert_eq!(m.write_and_wait(), Err(BlockError::Eio));
    assert_eq!(m.write_and_wait(), Ok(()), "and only once");
}

// ---- coherency ------------------------------------------------------------

/// The published stack a registered disk exposes: cache underneath, coherence
/// decorator on top, medium at the bottom.
fn coherent_stack(blocks: u64) -> (Arc<MemDisk<InodeClass>>, Arc<BdevMapping>, Arc<dyn BlockDevice>) {
    let disk = medium(blocks);
    let m = mapping_over(disk.clone());
    let published = super::CoherentDev::wrap(disk.clone(), Arc::downgrade(&m));
    (disk, m, published)
}

/// One whole-block write submitted the way a filesystem submits its own I/O.
fn fs_write(dev: &dyn BlockDevice, block: u64, byte: u8) {
    let mut req = BlockRequest::new_write(block, 1, vec![byte; BS as usize]);
    dev.submit_sync(&mut req).unwrap();
}

// A filesystem write to a block a raw open has cached must be visible to the
// next raw read: the cached page is dropped, so it refetches.
#[test]
fn filesystem_write_is_visible_to_a_raw_read_of_the_same_block() {
    let (disk, m, published) = coherent_stack(64);
    let mut buf = [0u8; 8];
    m.read_at(0, &mut buf).unwrap();              // caches page 0
    assert!(m.is_resident(0));
    fs_write(published.as_ref(), 0, 0x33);
    m.read_at(0, &mut buf).unwrap();
    assert_eq!(buf, [0x33; 8], "raw read sees what the filesystem wrote");

    // POSITIVE CONTROL: the SAME write submitted below the decorator (straight
    // at the medium, as a driver's internal I/O would be) leaves the cached
    // page stale — the decorator is what provides the guarantee above.
    fs_write(disk.as_ref(), 0, 0x44);
    m.read_at(0, &mut buf).unwrap();
    assert_eq!(buf, [0x33; 8], "uncoordinated I/O below the handle is stale");
}

// The other direction: a raw write still dirty in the cache must be visible to
// a filesystem read of the same block.
#[test]
fn raw_write_is_visible_to_a_filesystem_read_of_the_same_block() {
    let (_disk, m, published) = coherent_stack(64);
    m.write_at(0, &[0x55; 16]).unwrap();
    assert_eq!(m.dirty_pages(), 1);
    let mut req = BlockRequest::new_read(0, 1, BS);
    published.submit_sync(&mut req).unwrap();
    assert_eq!(&req.buffer[..16], &[0x55; 16], "the dirty page was flushed first");
}

// A filesystem write over a DIRTY cached page: the older cached bytes reach
// the medium first, then the newer filesystem write lands on top of them —
// chronological order, and no cached byte is silently dropped.
#[test]
fn filesystem_write_over_a_dirty_page_orders_the_cached_write_first() {
    let (disk, m, published) = coherent_stack(64);
    m.write_at(0, &[0x66; 16]).unwrap();
    m.write_at(BS as u64, &[0x99; 16]).unwrap();  // same page, different block
    fs_write(published.as_ref(), 0, 0x77);
    assert_eq!(on_medium(disk.as_ref(), 0, 4), vec![0x77; 4], "the newer write wins");
    assert_eq!(on_medium(disk.as_ref(), BS as u64, 16), vec![0x99; 16],
        "the cached bytes outside the written block were not lost");
}

// The coherence check costs nothing on a disk nobody has opened raw.
#[test]
fn a_disk_with_no_cached_pages_is_not_reconciled() {
    let (_disk, m, published) = coherent_stack(64);
    assert_eq!(m.nrpages(), 0);
    fs_write(published.as_ref(), 0, 0x88);
    assert_eq!(m.nrpages(), 0, "no page was faulted in by a filesystem write");
}

// `invalidate_bdev`: clean pages go, dirty ones stay (dropping them would lose
// data the medium has not got).
#[test]
fn invalidate_drops_clean_pages_and_keeps_dirty_ones() {
    let disk = medium(64);
    let m = mapping_over(disk.clone());
    let mut buf = [0u8; 8];
    m.read_at(0, &mut buf).unwrap();          // clean page 0
    m.write_at(PG, &[0x2A; 8]).unwrap();      // dirty page 1
    assert_eq!(m.nrpages(), 2);
    assert_eq!(m.invalidate_clean(), 1);
    assert!(!m.is_resident(0));
    assert!(m.is_resident(PG));
    assert_eq!(m.nrpages(), 1);
}

// ---- the device pass of sync(2) -------------------------------------------

// The submit half must actually write dirty device pages back. Before this
// mechanism existed there was no device page cache, so this pass had nothing
// to submit and the medium stayed stale until something else flushed it.
#[test]
fn sync_bdevs_submit_half_writes_dirty_device_pages_back() {
    let raw = medium(8);
    let idx = crate::registry::register("vdx", raw.clone());
    let devt = crate::registry::dev_t_of("vdx", idx).unwrap();
    assert!(crate::registry::open_by_dev(devt), "a raw open holds the disk");
    let disk = crate::registry::by_dev(devt).unwrap();

    disk.mapping.write_at(0, &[0xE1; 128]).unwrap();
    assert!(on_medium(raw.as_ref(), 0, 128).iter().all(|&b| b == 0));

    super::sync_bdevs(false);
    assert_eq!(on_medium(raw.as_ref(), 0, 128), vec![0xE1; 128], "submit half is real");
    super::sync_bdevs(true);
    assert_eq!(disk.mapping.writeback_pages(), 0, "wait half drained writeback");

    crate::registry::close_by_dev(devt);
    crate::registry::unregister("vdx");
}

// A disk with no resident device pages, and a disk nobody has open, are both
// skipped — the reference's own two skip conditions.
#[test]
fn sync_bdevs_skips_a_disk_with_no_pages_or_no_opener() {
    let raw = medium(8);
    let idx = crate::registry::register("vdy", raw.clone());
    let devt = crate::registry::dev_t_of("vdy", idx).unwrap();
    let disk = crate::registry::by_dev(devt).unwrap();
    assert_eq!(disk.mapping.nrpages(), 0);
    super::sync_bdevs(false);                       // no pages: nothing to do
    super::sync_bdevs(true);

    // Pages, but no opener: the pass leaves them alone (final close is what
    // reconciles a closed device).
    disk.mapping.write_at(0, &[0xE2; 16]).unwrap();
    assert_eq!(disk.opener_count(), 0);
    super::sync_bdevs(false);
    assert_eq!(disk.mapping.dirty_pages(), 1, "skipped: nobody has it open");

    // With an opener the same pass writes it back.
    assert!(crate::registry::open_by_dev(devt));
    super::sync_bdevs(false);
    assert_eq!(disk.mapping.dirty_pages(), 0);
    crate::registry::close_by_dev(devt);
    crate::registry::unregister("vdy");
}

// Removing a disk writes its cache back while the driver is still there, and
// drops what remains — a page surviving into a re-registration of the same
// device number would serve the previous medium's bytes.
#[test]
fn disk_removal_writes_the_cache_back_and_drops_it() {
    let raw = medium(8);
    let idx = crate::registry::register("vdz", raw.clone());
    let devt = crate::registry::dev_t_of("vdz", idx).unwrap();
    let disk = crate::registry::by_dev(devt).unwrap();
    disk.mapping.write_at(0, &[0xF0; 32]).unwrap();
    assert!(crate::registry::unregister("vdz"));
    assert_eq!(on_medium(raw.as_ref(), 0, 32), vec![0xF0; 32]);
    assert_eq!(disk.mapping.nrpages(), 0, "no page survives the removal");
}

// ---- pure range arithmetic ------------------------------------------------

#[test]
fn page_span_covers_every_intersecting_page() {
    assert_eq!(page_span(0, 1), (0, 1));
    assert_eq!(page_span(0, PG), (0, 1));
    assert_eq!(page_span(0, PG + 1), (0, 2));
    assert_eq!(page_span(PG - 1, PG + 1), (0, 2));
    assert_eq!(page_span(PG, u64::MAX), (1, u64::MAX));
    assert_eq!(page_span(3 * PG, 3 * PG), (3, 3), "an empty range spans nothing");
}
