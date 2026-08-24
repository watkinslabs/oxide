//! Direct block I/O over a pinned f2fs swapfile.

use alloc::sync::Arc;

use block::{BlockCompletion, BlockDevice, BlockError, BlockOp, BlockRequest, KResult};

use super::SwapMap;
use crate::mount::F2fs;
use crate::uapi::BLKSIZE;

/// A swapfile's global f2fs block map presented as one logical block device.
/// The volume remains pinned for this object's lifetime, so the map cannot be
/// invalidated by the cleaner or an ordinary write path.
pub struct F2fsSwapDevice {
    fs: Arc<F2fs>,
    ino: u32,
    map: SwapMap,
    capacity: u64,
}

impl F2fsSwapDevice {
    pub fn new(fs: Arc<F2fs>, ino: u32, map: SwapMap) -> Result<Self, BlockError> {
        if map.max == 0 || map.pages + 1 != map.max || fs.swap_devices().is_empty() {
            return Err(BlockError::Einval);
        }
        Ok(Self { fs, ino, capacity: map.max, map })
    }

    fn transfer(&self, request: &mut BlockRequest) -> KResult<()> {
        let end = request.start_block.checked_add(request.len_blocks as u64)
            .ok_or(BlockError::Einval)?;
        if end > self.capacity { return Err(BlockError::Eio); }
        let bytes = (request.len_blocks as usize).checked_mul(BLKSIZE)
            .ok_or(BlockError::Einval)?;
        if matches!(request.op, BlockOp::Read | BlockOp::Write)
            && request.buffer.len() != bytes { return Err(BlockError::Einval); }

        for logical in request.start_block..end {
            let physical = self.map.resolve(logical).ok_or(BlockError::Eio)?;
            let pieces = {
                let volume = self.fs.volume.lock();
                crate::devices::route::split_at(volume.devices(), u64::from(physical), BLKSIZE)
                    .map_err(|_| BlockError::Eio)?
            };
            if pieces.len() != 1 || pieces[0].len != BLKSIZE { return Err(BlockError::Eio); }
            let piece = pieces[0];
            let device = self.fs.swap_devices().get(piece.member).ok_or(BlockError::Eio)?;
            let device_block = device.block_size();
            if device_block == 0 || BLKSIZE as u32 % device_block != 0
                || piece.local % (u64::from(BLKSIZE as u32 / device_block)) != 0 {
                return Err(BlockError::Einval);
            }
            let per_fs = BLKSIZE as u32 / device_block;
            let start = piece.local.checked_mul(u64::from(per_fs)).ok_or(BlockError::Eio)?;
            let at = (logical - request.start_block) as usize * BLKSIZE;
            let mut part = match request.op {
                BlockOp::Read => BlockRequest::new_read(start, per_fs, device_block),
                BlockOp::Write => BlockRequest::new_write(start, per_fs,
                    request.buffer[at..at + BLKSIZE].to_vec()),
                BlockOp::WriteZeroes { no_unmap } => BlockRequest::new_write_zeroes(start, per_fs, no_unmap),
                BlockOp::Discard => BlockRequest::new_discard(start, per_fs),
                BlockOp::Flush => return Err(BlockError::Einval),
            };
            device.submit_sync(&mut part)?;
            if request.op == BlockOp::Read {
                request.buffer[at..at + BLKSIZE].copy_from_slice(&part.buffer);
            }
        }
        Ok(())
    }
}

impl Drop for F2fsSwapDevice {
    fn drop(&mut self) {
        let _ = self.fs.volume_now().swap_deactivate(self.ino);
    }
}

impl BlockDevice for F2fsSwapDevice {
    fn block_size(&self) -> u32 { BLKSIZE as u32 }
    fn capacity_blocks(&self) -> u64 { self.capacity }
    fn supports_discard(&self) -> bool { self.fs.swap_devices().iter().all(|d| d.supports_discard()) }
    fn submit(&self, request: BlockRequest, completion: BlockCompletion) {
        let mut request = request;
        let result = self.submit_sync(&mut request);
        completion(request, result);
    }
    fn submit_sync(&self, request: &mut BlockRequest) -> KResult<()> {
        if request.op == BlockOp::Flush {
            if request.len_blocks != 0 || !request.buffer.is_empty() { return Err(BlockError::Einval); }
            return self.flush();
        }
        self.transfer(request)
    }
    fn flush(&self) -> KResult<()> {
        for device in self.fs.swap_devices() { device.flush()?; }
        Ok(())
    }
}
