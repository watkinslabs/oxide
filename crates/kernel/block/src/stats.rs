//! Per-disk I/O accounting (Linux `struct disk_stats` / `gendisk`). Every
//! block device registered via `registry` is wrapped in a `StatsDev`
//! decorator that counts completed reads/writes + 512-byte sectors + flushes
//! + in-flight depth as I/O flows through `submit_sync`. `/proc/diskstats`
//! reads these. Counters are monotonic atomics (deltas computed by readers).

use core::sync::atomic::{AtomicU64, Ordering};

use alloc::sync::Arc;

use crate::blockdev::{BlockDevice, BlockRequest};
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
}

impl BlockDevice for StatsDev {
    fn block_size(&self) -> u32 { self.inner.block_size() }
    fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }

    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        self.stats.in_flight.fetch_add(1, Ordering::Relaxed);
        let r = self.inner.submit_sync(req);
        self.stats.in_flight.fetch_sub(1, Ordering::Relaxed);
        if r.is_ok() {
            // Convert the request's block_size-sized run to 512-byte sectors.
            let secs = (req.len_blocks as u64) * (self.inner.block_size() as u64) / 512;
            match req.op {
                BlockOp::Read => {
                    self.stats.reads.fetch_add(1, Ordering::Relaxed);
                    self.stats.sectors_read.fetch_add(secs, Ordering::Relaxed);
                }
                BlockOp::Write => {
                    self.stats.writes.fetch_add(1, Ordering::Relaxed);
                    self.stats.sectors_written.fetch_add(secs, Ordering::Relaxed);
                }
                BlockOp::Flush => { self.stats.flushes.fetch_add(1, Ordering::Relaxed); }
                BlockOp::Discard => {
                    self.stats.discards.fetch_add(1, Ordering::Relaxed);
                    self.stats.sectors_discarded.fetch_add(secs, Ordering::Relaxed);
                }
            }
        }
        r
    }

    fn flush(&self) -> KResult<()> { self.inner.flush() }
}
