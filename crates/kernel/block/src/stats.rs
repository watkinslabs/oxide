//! Per-disk I/O accounting (Linux `struct disk_stats` / `gendisk`). Every
//! block device registered via `registry` is wrapped in a `StatsDev`
//! decorator that counts completed reads/writes + 512-byte sectors + flushes
//! + in-flight depth as I/O flows through `submit_sync`. `/proc/diskstats`
//! reads these. Counters are monotonic atomics (deltas computed by readers).

use core::sync::atomic::{AtomicU64, Ordering};

use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::blockdev::{BlockCompletion, BlockDevice, BlockRequest};
use crate::queue_limits::QueueLimits;
use crate::types::{BlockOp, KResult};

/// Live per-disk I/O counters. # C: O(1) per field.
#[derive(Default)]
pub struct DiskStats {
    /// Completed read requests.
    pub reads: AtomicU64,
    /// 512-byte sectors read.
    pub sectors_read: AtomicU64,
    /// Completed write requests.
    pub writes: AtomicU64,
    /// 512-byte sectors written.
    pub sectors_written: AtomicU64,
    /// Completed flush requests.
    pub flushes: AtomicU64,
    /// Completed discard requests.
    pub discards: AtomicU64,
    /// 512-byte sectors discarded.
    pub sectors_discarded: AtomicU64,
    /// Requests currently in flight (incremented on submit, decremented on
    /// completion) — `/proc/diskstats` field 9.
    pub in_flight: AtomicU64,
}

impl DiskStats {
    /// `(reads, sectors_read, writes, sectors_written, in_flight)`. # C: O(1)
    pub fn snapshot(&self) -> (u64, u64, u64, u64, u64) {
        (self.reads.load(Ordering::Relaxed),
         self.sectors_read.load(Ordering::Relaxed),
         self.writes.load(Ordering::Relaxed),
         self.sectors_written.load(Ordering::Relaxed),
         self.in_flight.load(Ordering::Relaxed))
    }
}

/// Stats-counting `BlockDevice` decorator. Holds the real driver device +
/// shared `DiskStats`; delegates every op and accounts completed I/O. The
/// registry stores this as the disk's `dev`, so ALL I/O via the registry is
/// counted at one central point (Linux blk-mq `blk_account_io_done`).
pub struct StatsDev {
    inner: Arc<dyn BlockDevice>,
    stats: Arc<DiskStats>,
}

impl StatsDev {
    /// Wrap `inner`, returning the decorator + its shared stats handle.
    /// # C: O(1)
    pub fn wrap(inner: Arc<dyn BlockDevice>) -> (Arc<dyn BlockDevice>, Arc<DiskStats>) {
        let stats = Arc::new(DiskStats::default());
        let dev: Arc<dyn BlockDevice> = Arc::new(StatsDev { inner, stats: Arc::clone(&stats) });
        (dev, stats)
    }

    fn account_done(stats: &DiskStats, block_size: u32, req: &BlockRequest, result: &KResult<()>) {
        if result.is_err() { return; }
        // Convert the request's block_size-sized run to 512-byte sectors.
        let secs = (req.len_blocks as u64) * (block_size as u64) / 512;
        match req.op {
            BlockOp::Read => {
                stats.reads.fetch_add(1, Ordering::Relaxed);
                stats.sectors_read.fetch_add(secs, Ordering::Relaxed);
            }
            BlockOp::Write | BlockOp::WriteZeroes { .. } => {
                stats.writes.fetch_add(1, Ordering::Relaxed);
                stats.sectors_written.fetch_add(secs, Ordering::Relaxed);
            }
            BlockOp::Flush => { stats.flushes.fetch_add(1, Ordering::Relaxed); }
            BlockOp::Discard => {
                stats.discards.fetch_add(1, Ordering::Relaxed);
                stats.sectors_discarded.fetch_add(secs, Ordering::Relaxed);
            }
        }
    }
}

impl BlockDevice for StatsDev {
    fn block_size(&self) -> u32 { self.inner.block_size() }
    fn queue_limits(&self) -> KResult<QueueLimits> { self.inner.queue_limits() }
    fn supports_discard(&self) -> bool { self.inner.supports_discard() }
    fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }

    fn submit(&self, request: BlockRequest, completion: BlockCompletion) {
        self.stats.in_flight.fetch_add(1, Ordering::Relaxed);
        let stats = Arc::clone(&self.stats);
        let block_size = self.inner.block_size();
        self.inner.submit(request, Box::new(move |request, result| {
            stats.in_flight.fetch_sub(1, Ordering::Relaxed);
            Self::account_done(&stats, block_size, &request, &result);
            completion(request, result);
        }));
    }

    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        self.stats.in_flight.fetch_add(1, Ordering::Relaxed);
        let r = self.inner.submit_sync(req);
        self.stats.in_flight.fetch_sub(1, Ordering::Relaxed);
        Self::account_done(&self.stats, self.inner.block_size(), req, &r);
        r
    }

    fn flush(&self) -> KResult<()> { self.inner.flush() }

    fn swap_slot_free_notify(&self, start_block: u64, len_blocks: u32) -> KResult<()> {
        self.inner.swap_slot_free_notify(start_block, len_blocks)
    }
}
