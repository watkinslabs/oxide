//! Direct block I/O over one pinned, fully mapped ext4 regular file.

use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use block::{BlockCompletion, BlockDevice, BlockError, BlockOp, BlockRequest, KResult};
use vfs::{Inode, VfsError};

use super::inode::Ext4FileData;

struct Extent { logical: u64, physical: u64, blocks: u64 }
const SWAP_PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;
const ZERO_BLOCKS: u32 = 0;

/// Direct block-device view of an active ext4 swapfile. The final drop clears
/// the file mutation pin after the PMM has removed the swap area.
pub struct SwapFileDevice {
    device: Arc<dyn BlockDevice>,
    extents: Vec<Extent>,
    capacity: u64,
    pin: Arc<AtomicBool>,
}

/// Stable identity plus the direct block-device view owned by one active
/// ext4 swapfile. The identity is inode-based, so hard links and path aliases
/// resolve to the same PMM swap area.
pub struct SwapFileBacking { pub name: String, pub device: Arc<dyn BlockDevice> }

/// Return the inode-stable PMM area identity for an ext4 regular file.
/// # C: O(1)
pub fn swapfile_name(inode: &Inode) -> Option<String> {
    let file = inode.private::<Ext4FileData>()?;
    Some(alloc::format!("ext4:{}:{}", file.st.fsid(), file.ino))
}

impl Drop for SwapFileDevice {
    fn drop(&mut self) { self.pin.store(false, Ordering::Release); }
}

/// Build a direct-I/O backing only for a page-aligned regular file whose real
/// ext4 extents cover every byte and contain no unwritten range. # C: O(extents)
pub fn swapfile_backing(inode: &Inode) -> Result<SwapFileBacking, VfsError> {
    let file = inode.private::<Ext4FileData>().ok_or(VfsError::Einval)?;
    let size = inode.size();
    if size == 0 || size % SWAP_PAGE_BYTES != 0 { return Err(VfsError::Einval); }
    file.begin_swap_activation()?;
    // mkswap normally used buffered write(2). Drain its data and journaled
    // metadata before reading the swap header through the raw device view;
    // after activation the direct backing, not the ext4 page cache, owns I/O.
    if file.frames.writeback().is_err() || file.st.mount.commit_batch().is_err() {
        file.swap_active.store(false, Ordering::Release);
        return Err(VfsError::Eio);
    }
    match SwapFileDevice::new(file, size) {
        Ok(device) => Ok(SwapFileBacking {
            name: swapfile_name(inode).ok_or(VfsError::Einval)?, device: Arc::new(device),
        }),
        Err(error) => { file.swap_active.store(false, Ordering::Release); Err(error) }
    }
}

impl SwapFileDevice {
    fn new(file: &Ext4FileData, size: u64) -> Result<Self, VfsError> {
        let device = file.st.mount.dev.clone();
        let device_block = device.block_size() as u64;
        let fs_block = file.st.mount.sb.block_size.max(1) as u64;
        if device_block == 0 || fs_block % device_block != 0 || size % device_block != 0 { return Err(VfsError::Einval); }
        let per_fs_block = fs_block / device_block;
        let file_blocks = size / fs_block;
        let mut extents = Vec::new();
        let mut expected = 0u64;
        for (logical, physical, blocks, unwritten) in file.st.mount.extent_map(file.ino).map_err(|_| VfsError::Eio)? {
            let logical = logical as u64;
            let blocks = blocks as u64;
            let end = logical.checked_add(blocks).ok_or(VfsError::Eio)?;
            if logical != expected || unwritten || logical >= file_blocks { return Err(VfsError::Einval); }
            let used = end.min(file_blocks).checked_sub(logical).ok_or(VfsError::Eio)?;
            extents.push(Extent {
                logical: logical.checked_mul(per_fs_block).ok_or(VfsError::Eio)?,
                physical: physical.checked_mul(per_fs_block).ok_or(VfsError::Eio)?,
                blocks: used.checked_mul(per_fs_block).ok_or(VfsError::Eio)?,
            });
            expected = end;
            if expected >= file_blocks { break; }
        }
        if expected != file_blocks { return Err(VfsError::Einval); }
        Ok(Self { device, extents, capacity: size / device_block, pin: file.swap_active.clone() })
    }

    fn extent_at(&self, block: u64) -> Option<&Extent> {
        self.extents.iter().find(|extent| extent.logical.checked_add(extent.blocks)
            .is_some_and(|end| block >= extent.logical && block < end))
    }

    fn transfer(&self, request: &mut BlockRequest) -> KResult<()> {
        let end = request.start_block.checked_add(request.len_blocks as u64).ok_or(BlockError::Einval)?;
        if end > self.capacity { return Err(BlockError::Eio); }
        let block_size = self.block_size() as usize;
        let bytes = (request.len_blocks as usize).checked_mul(block_size).ok_or(BlockError::Einval)?;
        if matches!(request.op, BlockOp::Read | BlockOp::Write) && request.buffer.len() != bytes { return Err(BlockError::Einval); }
        let mut logical = request.start_block;
        let mut offset = 0usize;
        while logical < end {
            let extent = self.extent_at(logical).ok_or(BlockError::Eio)?;
            let extent_end = extent.logical.checked_add(extent.blocks).ok_or(BlockError::Eio)?;
            let part_end = end.min(extent_end);
            let part_blocks = u32::try_from(part_end - logical).map_err(|_| BlockError::Einval)?;
            let physical = extent.physical.checked_add(logical - extent.logical).ok_or(BlockError::Eio)?;
            let part_bytes = (part_blocks as usize).checked_mul(block_size).ok_or(BlockError::Einval)?;
            let mut part = match request.op {
                BlockOp::Read => BlockRequest::new_read(physical, part_blocks, self.block_size()),
                BlockOp::Write => BlockRequest::new_write(physical, part_blocks, request.buffer[offset..offset + part_bytes].to_vec()),
                BlockOp::WriteZeroes { no_unmap } => BlockRequest::new_write_zeroes(physical, part_blocks, no_unmap),
                BlockOp::Discard => BlockRequest::new_discard(physical, part_blocks),
                BlockOp::Flush => return Err(BlockError::Eopnotsupp),
            };
            self.device.submit_sync(&mut part)?;
            if request.op == BlockOp::Read { request.buffer[offset..offset + part_bytes].copy_from_slice(&part.buffer); }
            logical = part_end;
            offset = offset.checked_add(part_bytes).ok_or(BlockError::Eio)?;
        }
        Ok(())
    }
}

impl BlockDevice for SwapFileDevice {
    fn block_size(&self) -> u32 { self.device.block_size() }
    fn queue_limits(&self) -> KResult<block::QueueLimits> { self.device.queue_limits() }
    fn supports_discard(&self) -> bool { self.device.supports_discard() }
    fn capacity_blocks(&self) -> u64 { self.capacity }
    fn submit(&self, request: BlockRequest, completion: BlockCompletion) {
        let mut request = request;
        let result = self.submit_sync(&mut request);
        completion(request, result);
    }
    fn submit_sync(&self, request: &mut BlockRequest) -> KResult<()> {
        if request.op == BlockOp::Flush {
            if request.len_blocks != ZERO_BLOCKS || !request.buffer.is_empty() { return Err(BlockError::Einval); }
            return self.device.flush();
        }
        self.transfer(request)
    }
    fn flush(&self) -> KResult<()> { self.device.flush() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use block::MemDisk;
    use sync::TaskList;

    const DEVICE_BLOCK_BYTES: u32 = 512;
    const DEVICE_BLOCK_COUNT: u64 = 32;
    const FILE_BLOCK_COUNT: u64 = 4;
    const FIRST_FILE_BLOCK: u64 = 0;
    const FIRST_PHYSICAL_RUN: u64 = 4;
    const SECOND_PHYSICAL_RUN: u64 = 12;
    const FIRST_RUN_BLOCKS: u64 = 2;
    const SECOND_RUN_BLOCKS: u64 = FILE_BLOCK_COUNT - FIRST_RUN_BLOCKS;
    const FIRST_WRITE_BLOCK: u64 = 1;
    const WRITE_BLOCK_COUNT: u32 = 3;
    const WRITE_BYTE: u8 = 0x5a;
    const INITIAL_PIN: bool = true;

    fn fixture() -> (Arc<MemDisk<TaskList>>, SwapFileDevice, Arc<AtomicBool>) {
        let backing = MemDisk::<TaskList>::new(DEVICE_BLOCK_BYTES, DEVICE_BLOCK_COUNT);
        let pin = Arc::new(AtomicBool::new(INITIAL_PIN));
        let device = SwapFileDevice {
            device: backing.clone(),
            extents: alloc::vec![
                Extent { logical: FIRST_FILE_BLOCK, physical: FIRST_PHYSICAL_RUN, blocks: FIRST_RUN_BLOCKS },
                Extent { logical: FIRST_RUN_BLOCKS, physical: SECOND_PHYSICAL_RUN, blocks: SECOND_RUN_BLOCKS },
            ],
            capacity: FILE_BLOCK_COUNT,
            pin: pin.clone(),
        };
        (backing, device, pin)
    }

    #[test]
    fn transfer_crosses_real_extent_boundary() {
        let (backing, device, _pin) = fixture();
        let bytes = WRITE_BLOCK_COUNT as usize * DEVICE_BLOCK_BYTES as usize;
        let mut request = BlockRequest::new_write(FIRST_WRITE_BLOCK, WRITE_BLOCK_COUNT, alloc::vec![WRITE_BYTE; bytes]);
        device.submit_sync(&mut request).unwrap();
        let mut first = BlockRequest::new_read(FIRST_PHYSICAL_RUN + FIRST_WRITE_BLOCK, 1, DEVICE_BLOCK_BYTES);
        backing.submit_sync(&mut first).unwrap();
        assert_eq!(first.buffer, alloc::vec![WRITE_BYTE; DEVICE_BLOCK_BYTES as usize]);
        let mut second = BlockRequest::new_read(SECOND_PHYSICAL_RUN, SECOND_RUN_BLOCKS as u32, DEVICE_BLOCK_BYTES);
        backing.submit_sync(&mut second).unwrap();
        assert_eq!(second.buffer, alloc::vec![WRITE_BYTE; SECOND_RUN_BLOCKS as usize * DEVICE_BLOCK_BYTES as usize]);
        let mut read = BlockRequest::new_read(FIRST_WRITE_BLOCK, WRITE_BLOCK_COUNT, DEVICE_BLOCK_BYTES);
        device.submit_sync(&mut read).unwrap();
        assert_eq!(read.buffer, alloc::vec![WRITE_BYTE; bytes]);
    }

    #[test]
    fn discard_crosses_real_extent_boundary() {
        let (backing, device, _pin) = fixture();
        let bytes = WRITE_BLOCK_COUNT as usize * DEVICE_BLOCK_BYTES as usize;
        let mut write = BlockRequest::new_write(FIRST_WRITE_BLOCK, WRITE_BLOCK_COUNT,
            alloc::vec![WRITE_BYTE; bytes]);
        device.submit_sync(&mut write).unwrap();
        assert!(device.supports_discard());
        device.submit_sync(&mut BlockRequest::new_discard(FIRST_WRITE_BLOCK, WRITE_BLOCK_COUNT)).unwrap();
        let mut first = BlockRequest::new_read(FIRST_PHYSICAL_RUN + FIRST_WRITE_BLOCK, 1, DEVICE_BLOCK_BYTES);
        backing.submit_sync(&mut first).unwrap();
        assert!(first.buffer.iter().all(|byte| *byte == 0));
        let mut second = BlockRequest::new_read(SECOND_PHYSICAL_RUN, SECOND_RUN_BLOCKS as u32, DEVICE_BLOCK_BYTES);
        backing.submit_sync(&mut second).unwrap();
        assert!(second.buffer.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn final_device_drop_releases_mutation_pin() {
        let (_backing, device, pin) = fixture();
        assert!(pin.load(Ordering::Acquire));
        drop(device);
        assert!(!pin.load(Ordering::Acquire));
    }
}
