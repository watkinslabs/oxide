//! Checked fixed-page I/O and durability over one block backend.

extern crate alloc;
use alloc::sync::Arc;

use crate::{BlockDevice, BlockError, BlockRequest};

/// One page-addressed view over a canonical block backend.
pub struct PageIo {
    dev: Arc<dyn BlockDevice>,
    base_block: u64,
    blocks_per_page: u32,
    page_bytes: usize,
    page_count: u64,
}

impl PageIo {
    /// Build a page view beginning at raw device page `base_page`. # C: O(1)
    pub fn new(dev: Arc<dyn BlockDevice>, base_page: u64, page_bytes: usize) -> Result<Self, BlockError> {
        Self::new_bounded(dev, base_page, page_bytes, None)
    }

    /// Build a page view capped below the backing capacity. # C: O(1)
    pub fn new_bounded(dev: Arc<dyn BlockDevice>, base_page: u64, page_bytes: usize,
                       limit: Option<u64>) -> Result<Self, BlockError> {
        let bs = dev.block_size() as usize;
        if bs == 0 || page_bytes == 0 || page_bytes % bs != 0 { return Err(BlockError::Einval); }
        let blocks_per_page = u32::try_from(page_bytes / bs).map_err(|_| BlockError::Einval)?;
        let base_block = base_page.checked_mul(blocks_per_page as u64).ok_or(BlockError::Einval)?;
        if base_block > dev.capacity_blocks() { return Err(BlockError::Einval); }
        let capacity = (dev.capacity_blocks() - base_block) / blocks_per_page as u64;
        let page_count = limit.unwrap_or(capacity);
        if page_count > capacity { return Err(BlockError::Einval); }
        Ok(Self { dev, base_block, blocks_per_page, page_bytes, page_count })
    }

    /// Addressable pages after the selected base. # C: O(1)
    pub const fn page_count(&self) -> u64 { self.page_count }

    fn block(&self, page: u64) -> Result<u64, BlockError> {
        if page >= self.page_count { return Err(BlockError::Einval); }
        self.base_block.checked_add(page.checked_mul(self.blocks_per_page as u64)
            .ok_or(BlockError::Einval)?).ok_or(BlockError::Einval)
    }

    /// Read one complete page. # C: one device read
    pub fn read_page(&self, page: u64, out: &mut [u8]) -> Result<(), BlockError> {
        if out.len() != self.page_bytes { return Err(BlockError::Einval); }
        let mut req = BlockRequest::new_read(self.block(page)?, self.blocks_per_page, self.dev.block_size());
        self.dev.submit_sync(&mut req)?;
        if req.buffer.len() != out.len() { return Err(BlockError::Eio); }
        out.copy_from_slice(&req.buffer);
        Ok(())
    }

    /// Write one complete page without adding durability. # C: one device write
    pub fn write_page(&self, page: u64, data: &[u8]) -> Result<(), BlockError> {
        if data.len() != self.page_bytes { return Err(BlockError::Einval); }
        let mut req = BlockRequest::new_write(self.block(page)?, self.blocks_per_page, data.to_vec());
        self.dev.submit_sync(&mut req)
    }

    /// Make all preceding writes durable. # C: one device flush
    pub fn flush(&self) -> Result<(), BlockError> {
        crate::durability::submit::issue_flush(self.dev.as_ref())
    }

    /// Durably replace one page after a preflush. # C: one durable write
    pub fn commit_page(&self, page: u64, data: &[u8]) -> Result<(), BlockError> {
        if data.len() != self.page_bytes { return Err(BlockError::Einval); }
        let mut req = BlockRequest::new_write(self.block(page)?, self.blocks_per_page, data.to_vec())
            .with_durability(crate::durability::PREFLUSH | crate::durability::FUA);
        crate::durability::submit::submit_durable(self.dev.as_ref(), &mut req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemDisk;
    use sync::TaskList;

    #[test]
    fn base_and_bounds_have_one_checked_conversion() {
        let disk = MemDisk::<TaskList>::new(512, 32);
        let io = PageIo::new(disk.clone(), 1, 4096).unwrap();
        assert_eq!(io.page_count(), 3);
        let page = [0x5a; 4096];
        io.write_page(0, &page).unwrap();
        let mut raw = BlockRequest::new_read(8, 8, 512);
        disk.submit_sync(&mut raw).unwrap();
        assert_eq!(raw.buffer, page);
        assert_eq!(io.write_page(3, &page), Err(BlockError::Einval));
    }
}
