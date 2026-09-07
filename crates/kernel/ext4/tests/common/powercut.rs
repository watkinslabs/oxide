//! Unconditional power-cut disk: the harness-kill model.
//!
//! `crash::CrashDisk` cuts power at named JBD2 boundaries, which only exist on
//! a journalled filesystem. Killing QEMU is cruder than that and is what the
//! boot harness used to do on every run: the machine stops between two
//! arbitrary block writes, whatever reached the platter stays, everything
//! after it is lost, and no flush completes. `PowerCutDisk` models exactly
//! that, so an image with a journal and one without can be measured against
//! the same event.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use block::types::KResult;
use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

/// `cut_after` value meaning "count writes, never cut".
const NEVER: u64 = u64::MAX;

pub struct PowerCutDisk {
    inner: Arc<MemDisk<TaskList>>,
    writes: AtomicU64,
    cut_after: AtomicU64,
    crashed: AtomicBool,
}

impl PowerCutDisk {
    /// Device seeded with `image`, powered on, counting writes but not cutting.
    pub fn new(image: &[u8], sector: u32) -> Arc<Self> {
        let cap = (image.len() as u64) / (sector as u64);
        let inner: Arc<MemDisk<TaskList>> = MemDisk::new(sector, cap);
        let mut req = BlockRequest {
            op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
            buffer: image.to_vec(), ..Default::default() };
        inner.submit_sync(&mut req).expect("seed power-cut disk");
        Arc::new(Self {
            inner,
            writes: AtomicU64::new(0),
            cut_after: AtomicU64::new(NEVER),
            crashed: AtomicBool::new(false),
        })
    }

    /// Lose power once `n` further write requests have reached the media.
    pub fn cut_after(&self, n: u64) {
        self.writes.store(0, Ordering::Release);
        self.crashed.store(false, Ordering::Release);
        self.cut_after.store(n, Ordering::Release);
    }

    /// Count writes without ever cutting, to size a later cut point.
    pub fn watch(&self) {
        self.writes.store(0, Ordering::Release);
        self.crashed.store(false, Ordering::Release);
        self.cut_after.store(NEVER, Ordering::Release);
    }

    /// Write requests accepted since the last `cut_after`/`watch`.
    pub fn writes(&self) -> u64 { self.writes.load(Ordering::Acquire) }

    /// Whether power was actually cut, so a cycle cannot pass having simulated
    /// nothing at all.
    pub fn crashed(&self) -> bool { self.crashed.load(Ordering::Acquire) }

    /// The bytes that actually reached the media.
    pub fn snapshot(&self) -> Vec<u8> {
        let cap = self.inner.capacity_blocks();
        let sector = self.inner.block_size();
        let mut req = BlockRequest::new_read(0, cap as u32, sector);
        self.inner.submit_sync(&mut req).expect("snapshot read");
        req.buffer
    }
}

impl BlockDevice for PowerCutDisk {
    fn block_size(&self) -> u32 { self.inner.block_size() }
    fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }
    fn queue_limits(&self) -> KResult<block::QueueLimits> { self.inner.queue_limits() }
    fn supports_discard(&self) -> bool { self.inner.supports_discard() }

    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        if req.op == BlockOp::Read { return self.inner.submit_sync(req); }
        if self.crashed() { return Ok(()); }
        let seen = self.writes.fetch_add(1, Ordering::AcqRel) + 1;
        if seen > self.cut_after.load(Ordering::Acquire) {
            self.crashed.store(true, Ordering::Release);
            return Ok(());
        }
        self.inner.submit_sync(req)
    }

    fn flush(&self) -> KResult<()> {
        if self.crashed() { return Ok(()); }
        self.inner.flush()
    }
}
