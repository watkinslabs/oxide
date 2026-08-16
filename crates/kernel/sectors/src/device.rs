//! Reading and writing a volume's sectors through a registered block device.
//!
//! A volume's sector and a device's block need not be the same size, in either
//! direction, so every request is expressed in the DEVICE's unit and the bytes
//! wanted are taken out of what comes back. A write that does not begin and
//! end on a device-block boundary is a read-modify-write: the blocks either
//! side hold bytes this write must not disturb, and a device writes whole
//! blocks or nothing.

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::source::SectorSource;

/// The sector size every volume's first sector is at least as large as.
pub const PROBE_SECTOR: u32 = 512;

/// Reads a volume's sectors through a registered block device.
pub struct BlockSource {
    dev: Arc<dyn block::BlockDevice>,
    /// Sector size the VOLUME uses, which need not be the device's.
    sector_size: u32,
    /// Whether this mount may write at all.
    writable: bool,
}

impl BlockSource {
    /// # C: O(1)
    pub fn new(dev: Arc<dyn block::BlockDevice>) -> Self {
        Self { dev, sector_size: PROBE_SECTOR, writable: false }
    }

    /// Allow writes through this source. # C: O(1)
    pub fn writable(mut self, writable: bool) -> Self { self.writable = writable; self }

    /// Re-aim at the volume's own sector size once the boot sector has named
    /// it. # C: O(1)
    pub fn with_sector_size(mut self, sector_size: u32) -> Self {
        self.sector_size = sector_size;
        self
    }

    /// The unit this source addresses in. # C: O(1)
    pub fn sector_size(&self) -> u32 { self.sector_size }

    /// Byte offset and device-block span one volume-sector request covers.
    /// # C: O(1)
    fn span(&self, sector: u64, len: usize) -> Result<(u64, usize, u32), Errno> {
        let dev_block = u64::from(self.dev.block_size().max(1));
        let byte_off = sector.checked_mul(u64::from(self.sector_size)).ok_or(Errno::Eio)?;
        let first = byte_off / dev_block;
        let skew = usize::try_from(byte_off % dev_block).map_err(|_| Errno::Eio)?;
        let span = skew + len;
        let blocks = u32::try_from(span.div_ceil(dev_block as usize)).map_err(|_| Errno::Eio)?;
        Ok((first, skew, blocks))
    }
}

impl SectorSource for BlockSource {
    fn read_sectors(&self, sector: u64, buf: &mut [u8]) -> Result<(), Errno> {
        let (first, skew, blocks) = self.span(sector, buf.len())?;
        let span = skew + buf.len();
        let mut req = block::BlockRequest::new_read(first, blocks, self.dev.block_size());
        self.dev.submit_sync(&mut req).map_err(|_| Errno::Eio)?;
        if req.buffer.len() < span { return Err(Errno::Eio); }
        buf.copy_from_slice(&req.buffer[skew..span]);
        Ok(())
    }

    fn write_sectors(&self, sector: u64, buf: &[u8]) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let (first, skew, blocks) = self.span(sector, buf.len())?;
        let span = skew + buf.len();
        let whole = blocks as usize * self.dev.block_size().max(1) as usize;
        let mut payload = if skew == 0 && span == whole {
            alloc::vec![0u8; whole]
        } else {
            let mut req = block::BlockRequest::new_read(first, blocks, self.dev.block_size());
            self.dev.submit_sync(&mut req).map_err(|_| Errno::Eio)?;
            if req.buffer.len() < whole { return Err(Errno::Eio); }
            req.buffer
        };
        payload[skew..span].copy_from_slice(buf);
        let mut req = block::BlockRequest::new_write(first, blocks, payload);
        self.dev.submit_sync(&mut req).map_err(|_| Errno::Eio)?;
        Ok(())
    }

    fn discard_sectors(&self, sector: u64, count: u64) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        if !self.dev.supports_discard() { return Err(Errno::Eopnotsupp); }
        let dev_block = u64::from(self.dev.block_size().max(1));
        let byte = sector.checked_mul(u64::from(self.sector_size)).ok_or(Errno::Eio)?;
        let bytes = count.checked_mul(u64::from(self.sector_size)).ok_or(Errno::Eio)?;
        // A device erases whole blocks or nothing. Rounding a partial request
        // outward would erase sectors either side that are still in use, and
        // rounding it inward would report an erase the caller did not get.
        if byte % dev_block != 0 || bytes % dev_block != 0 { return Err(Errno::Einval); }
        let blocks = u32::try_from(bytes / dev_block).map_err(|_| Errno::Eio)?;
        let mut req = block::BlockRequest::new_discard(byte / dev_block, blocks);
        self.dev.submit_sync(&mut req).map_err(|_| Errno::Eio)
    }

    fn supports_discard(&self) -> bool { self.writable && self.dev.supports_discard() }

    fn writable(&self) -> bool { self.writable }

    fn flush(&self) -> Result<(), Errno> { self.dev.flush().map_err(|_| Errno::Eio) }
}
