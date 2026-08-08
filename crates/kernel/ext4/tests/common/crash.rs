//! Power-cut simulator for journal/replay tests.
//!
//! `CrashDisk` forwards to a real in-memory disk until the moment the
//! filesystem publishes a transaction in the journal superblock, then behaves
//! like media that lost power: every later write is silently discarded and
//! flushes are no-ops, while reads keep serving what actually reached the
//! platter. Re-opening the resulting image is exactly what a machine does after
//! a crash, so a test can assert what recovery must and must not restore.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use block::types::KResult;
use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

/// Byte offset of `s_start` inside a JBD2 journal superblock block. A write
/// carrying a non-zero value here is the write-ahead publish: "recovery must
/// replay from this block".
const JSB_OFF_START: usize = 0x1C;

/// Where power is cut, relative to the write-ahead publish of the FIRST
/// transaction committed after arming.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CrashPoint {
    /// The publish itself never reaches media: the journal holds a complete
    /// transaction body that recovery must NOT replay.
    BeforePublish,
    /// The publish reaches media, nothing after it does: the transaction is
    /// committed and recovery MUST replay it, even though not one of its target
    /// blocks was checkpointed.
    AfterPublish,
}

pub struct CrashDisk {
    inner: Arc<MemDisk<TaskList>>,
    /// Device sector at which the journal superblock lives; `u64::MAX` = unarmed.
    jsb_sector: AtomicU64,
    point: AtomicU64,
    crashed: AtomicBool,
    publishes: AtomicU64,
}

const UNARMED: u64 = u64::MAX;
const POINT_BEFORE: u64 = 0;
const POINT_AFTER: u64 = 1;
/// Watch-only: count publishes, never cut power.
const POINT_NEVER: u64 = 2;

impl CrashDisk {
    /// Build a device seeded with `image`, powered on and not yet armed.
    pub fn new(image: &[u8], sector: u32) -> Arc<Self> {
        let cap = (image.len() as u64) / (sector as u64);
        let inner: Arc<MemDisk<TaskList>> = MemDisk::new(sector, cap);
        let mut req = BlockRequest {
            op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
            buffer: image.to_vec(), ..Default::default() };
        inner.submit_sync(&mut req).expect("seed crash disk");
        Arc::new(Self {
            inner,
            jsb_sector: AtomicU64::new(UNARMED),
            point: AtomicU64::new(POINT_BEFORE),
            crashed: AtomicBool::new(false),
            publishes: AtomicU64::new(0),
        })
    }

    /// Cut power at `point` of the next transaction publish. `jsb_sector` is the
    /// device sector holding the journal superblock.
    pub fn arm(&self, jsb_sector: u64, point: CrashPoint) {
        self.crashed.store(false, Ordering::Release);
        self.publishes.store(0, Ordering::Release);
        self.point.store(match point {
            CrashPoint::BeforePublish => POINT_BEFORE,
            CrashPoint::AfterPublish => POINT_AFTER,
        }, Ordering::Release);
        self.jsb_sector.store(jsb_sector, Ordering::Release);
    }

    /// Count transaction publishes from here on without ever cutting power.
    pub fn watch(&self, jsb_sector: u64) {
        self.publishes.store(0, Ordering::Release);
        self.point.store(POINT_NEVER, Ordering::Release);
        self.jsb_sector.store(jsb_sector, Ordering::Release);
    }

    /// Transactions published since `watch`/`arm`.
    pub fn publishes(&self) -> u64 { self.publishes.load(Ordering::Acquire) }

    /// Whether power has been cut — a test asserts this so it can never pass by
    /// having simulated nothing at all.
    pub fn crashed(&self) -> bool { self.crashed.load(Ordering::Acquire) }

    /// The bytes that actually reached the media.
    pub fn snapshot(&self) -> Vec<u8> {
        let cap = self.inner.capacity_blocks();
        let sector = self.inner.block_size();
        let mut req = BlockRequest::new_read(0, cap as u32, sector);
        self.inner.submit_sync(&mut req).expect("snapshot read");
        req.buffer
    }

    /// True when `req` is the write-ahead publish of a transaction.
    fn is_publish(&self, req: &BlockRequest) -> bool {
        let armed = self.jsb_sector.load(Ordering::Acquire);
        if armed == UNARMED || req.start_block != armed { return false; }
        if req.buffer.len() < JSB_OFF_START + 4 { return false; }
        let start = u32::from_be_bytes([
            req.buffer[JSB_OFF_START],     req.buffer[JSB_OFF_START + 1],
            req.buffer[JSB_OFF_START + 2], req.buffer[JSB_OFF_START + 3]]);
        start != 0
    }
}

impl BlockDevice for CrashDisk {
    fn block_size(&self) -> u32 { self.inner.block_size() }
    fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }
    fn queue_limits(&self) -> KResult<block::QueueLimits> { self.inner.queue_limits() }
    fn supports_discard(&self) -> bool { self.inner.supports_discard() }

    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        if req.op == BlockOp::Read { return self.inner.submit_sync(req); }
        if self.crashed() { return Ok(()); }
        if self.is_publish(req) {
            self.publishes.fetch_add(1, Ordering::AcqRel);
            match self.point.load(Ordering::Acquire) {
                POINT_NEVER => return self.inner.submit_sync(req),
                POINT_BEFORE => { self.crashed.store(true, Ordering::Release); return Ok(()); }
                _ => {
                    let r = self.inner.submit_sync(req);
                    self.crashed.store(true, Ordering::Release);
                    return r;
                }
            }
        }
        self.inner.submit_sync(req)
    }

    fn flush(&self) -> KResult<()> {
        if self.crashed() { return Ok(()); }
        self.inner.flush()
    }
}
