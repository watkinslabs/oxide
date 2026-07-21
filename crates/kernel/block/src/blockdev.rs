// `BlockDevice` trait + a `MemDisk` test backing per `17§2`.
//
// `submit` owns a request and completion continuation. Drivers that have not
// yet exposed a hardware queue use its synchronous compatibility default;
// queued drivers override the same canonical entry point and complete later.

extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{LockClass, Spinlock};

use crate::queue_limits::QueueLimits;
use crate::types::{BlockError, BlockOp, KResult};

/// In-flight I/O block-list. v1 uses a single Vec for the entire
/// transfer; the spec's `SmallVec<[BufferRef; 4]>` scatter-gather
/// shape lands once io_uring fixed buffers do.
pub struct BlockRequest {
    pub op:           BlockOp,
    pub start_block:  u64,
    pub len_blocks:   u32,
    pub buffer:       Vec<u8>,
}

/// Completion ownership for one submitted request. The request returns to its
/// caller only through this continuation, after device completion has fixed
/// the final read buffer and status.
pub type BlockCompletion = Box<dyn FnOnce(BlockRequest, KResult<()>) + Send>;

impl BlockRequest {
    /// Construct a Read request whose `buffer` length pre-sized to
    /// `len_blocks * block_size` zeros — the device fills it.
    /// # C: O(len_blocks * block_size)
    pub fn new_read(start_block: u64, len_blocks: u32, block_size: u32) -> Self {
        let bytes = (len_blocks as usize) * (block_size as usize);
        Self {
            op: BlockOp::Read,
            start_block, len_blocks,
            buffer: alloc::vec![0u8; bytes],
        }
    }

    /// Construct a Write request whose `buffer` carries the data the
    /// caller wants on disk.
    /// # C: O(1)
    pub fn new_write(start_block: u64, len_blocks: u32, buffer: Vec<u8>) -> Self {
        Self { op: BlockOp::Write, start_block, len_blocks, buffer }
    }

    /// Construct a Linux `WRITE_ZEROES` request. The operation has no data
    /// payload; `no_unmap` forbids a device from implementing zeroing through
    /// deallocation.
    /// # C: O(1)
    pub fn new_write_zeroes(start_block: u64, len_blocks: u32, no_unmap: bool) -> Self {
        Self { op: BlockOp::WriteZeroes { no_unmap }, start_block, len_blocks, buffer: Vec::new() }
    }

    /// Construct a Discard request. Discard carries no write payload; the
    /// target releases or zeroes the specified logical block range.
    /// # C: O(1)
    pub fn new_discard(start_block: u64, len_blocks: u32) -> Self {
        Self { op: BlockOp::Discard, start_block, len_blocks, buffer: Vec::new() }
    }

    /// Construct a Flush request — empty buffer, transfer length 0.
    /// # C: O(1)
    pub fn new_flush() -> Self {
        Self { op: BlockOp::Flush, start_block: 0, len_blocks: 0, buffer: Vec::new() }
    }
}

/// `17§2` trait — what each driver implements.
pub trait BlockDevice: Send + Sync {
    /// Sector size in bytes — 512 or 4096.
    /// # C: O(1)
    fn block_size(&self) -> u32;

    /// Canonical queue topology exposed to userspace. Existing devices which
    /// only know their logical addressing size use a truthful conservative
    /// topology; drivers with real media or virtual-device geometry override
    /// this method with their immutable queue facts.
    /// # C: O(1)
    fn queue_limits(&self) -> KResult<QueueLimits> {
        QueueLimits::for_logical_block_size(self.block_size())
    }

    /// Whether this device advertises a nonzero Linux discard limit.  Callers
    /// may issue `BlockOp::Discard` only when this is true; an unsupported
    /// operation is not a capability probe. # C: O(1)
    fn supports_discard(&self) -> bool { false }

    /// Capacity in `block_size`-sized sectors.
    /// # C: O(1)
    fn capacity_blocks(&self) -> u64;

    /// Submit one owned request. A queued driver returns after posting to its
    /// hardware queue and invokes `completion` from its completion path. The
    /// default preserves correctness for legacy synchronous drivers by
    /// completing inline; callers never need a parallel I/O interface.
    /// # C: depends on driver
    fn submit(&self, mut request: BlockRequest, completion: BlockCompletion) {
        let result = self.submit_sync(&mut request);
        completion(request, result);
    }

    /// Compatibility wait path. New callers submit through [`Self::submit`];
    /// existing drivers retain this required method until their queue engines
    /// move to the canonical owned-request completion path.
    /// # C: depends on driver
    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()>;

    /// Force pending writes to durable media per `17§2`. Returns once
    /// the device acknowledges.
    /// # C: depends on driver
    fn flush(&self) -> KResult<()>;

    /// Notify a swap-capable device that the indicated page-sized backing
    /// extent has no remaining swap PTE references. Most block devices have
    /// no in-memory slot to release, so the default is deliberately inert;
    /// zram overrides it to free its compressed object immediately.
    /// # C: O(1) default
    fn swap_slot_free_notify(&self, _start_block: u64, _len_blocks: u32) -> KResult<()> { Ok(()) }
}

/// In-memory block device for tests + future tmpfs backing. Exposes
/// `Arc<MemDisk>` so multiple consumers can share one backing store.
pub struct MemDisk<C: LockClass> {
    block_size: u32,
    blocks:     Spinlock<Vec<u8>, C>,
}

impl<C: LockClass> MemDisk<C> {
    /// # C: O(capacity_blocks * block_size)
    pub fn new(block_size: u32, capacity_blocks: u64) -> Arc<Self> {
        let bytes = (capacity_blocks as usize) * (block_size as usize);
        Arc::new(Self {
            block_size,
            blocks: Spinlock::new(alloc::vec![0u8; bytes]),
        })
    }
}

impl<C: LockClass> BlockDevice for MemDisk<C> {
    fn block_size(&self) -> u32 { self.block_size }
    fn queue_limits(&self) -> KResult<QueueLimits> {
        QueueLimits::for_logical_block_size(self.block_size)?
            .with_discard(crate::MAX_DISCARD_SECTORS, crate::MAX_DISCARD_SECTORS, self.block_size)
    }
    fn supports_discard(&self) -> bool { true }

    fn capacity_blocks(&self) -> u64 {
        let g = self.blocks.lock();
        (g.len() as u64) / (self.block_size as u64)
    }

    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        let bs = self.block_size as usize;
        let off = (req.start_block as usize).checked_mul(bs).ok_or(BlockError::Einval)?;
        let len = (req.len_blocks as usize).checked_mul(bs).ok_or(BlockError::Einval)?;

        match req.op {
            BlockOp::Read => {
                if req.buffer.len() != len { return Err(BlockError::Einval); }
                let g = self.blocks.lock();
                let end = off.checked_add(len).ok_or(BlockError::Einval)?;
                if end > g.len() { return Err(BlockError::Eio); }
                req.buffer.copy_from_slice(&g[off..end]);
                Ok(())
            }
            BlockOp::Write => {
                if req.buffer.len() != len { return Err(BlockError::Einval); }
                let mut g = self.blocks.lock();
                let end = off.checked_add(len).ok_or(BlockError::Einval)?;
                if end > g.len() { return Err(BlockError::Eio); }
                g[off..end].copy_from_slice(&req.buffer);
                Ok(())
            }
            BlockOp::WriteZeroes { .. } => {
                if !req.buffer.is_empty() { return Err(BlockError::Einval); }
                let mut g = self.blocks.lock();
                let end = off.checked_add(len).ok_or(BlockError::Einval)?;
                if end > g.len() { return Err(BlockError::Eio); }
                g[off..end].fill(0);
                Ok(())
            }
            BlockOp::Flush   => Ok(()),
            BlockOp::Discard => {
                let mut g = self.blocks.lock();
                let end = off.checked_add(len).ok_or(BlockError::Einval)?;
                if end > g.len() { return Err(BlockError::Eio); }
                for b in &mut g[off..end] { *b = 0; }
                Ok(())
            }
        }
    }

    fn flush(&self) -> KResult<()> { Ok(()) }
}
