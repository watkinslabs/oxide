// `BlockDevice` trait + a `MemDisk` test backing per `17§2`.
//
// v1 surface is synchronous: `submit_sync(&mut req)` reads/writes
// in-place and returns. The async submit-ring + soft-IRQ completion
// path (`17§3`) lands once IrqOps + soft-IRQ infra exist; the trait
// stays the same, gaining a `submit_async` sibling later.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{LockClass, Spinlock};

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

    /// Capacity in `block_size`-sized sectors.
    /// # C: O(1)
    fn capacity_blocks(&self) -> u64;

    /// Synchronous request submission. Mutates `req.buffer` in place
    /// for `Read`. Async / completion-callback variant lands with
    /// soft-IRQ infra.
    /// # C: depends on driver
    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()>;

    /// Force pending writes to durable media per `17§2`. Returns once
    /// the device acknowledges.
    /// # C: depends on driver
    fn flush(&self) -> KResult<()>;
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
