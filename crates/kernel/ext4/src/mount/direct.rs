//! The synchronous ext4 `O_DIRECT` data path.
//!
//! Linux's ext4 direct path is an extent-mapped device transfer, not the
//! queued polled-transfer API.  Keep this owner beside the mount's extent and
//! block I/O code so it cannot accidentally become a second page-cache path.

use crate::inode::{self, InodeError};

use super::{Mount, MountError};

impl Mount {
    /// Read file data directly from mapped extents, serving holes and
    /// unwritten extents as zeroes.  The caller has already selected the
    /// synchronous `O_DIRECT` operation; this function therefore rejects a
    /// misaligned request instead of silently falling back to the page cache,
    /// matching ext4's `iomap_dio_rw` alignment contract.
    /// # C: O(extents in range) + O(device requests)
    pub(crate) fn direct_read(&self, inode: &inode::Inode, off: u64, dst: &mut [u8])
        -> Result<usize, MountError>
    {
        if dst.is_empty() { return Ok(0); }
        let bs = self.sb.block_size as u64;
        if bs == 0 || off % bs != 0 || (dst.len() as u64) % bs != 0 {
            return Err(MountError::Inode(InodeError::BadLen));
        }
        let size = inode.size;
        if off >= size { return Ok(0); }
        let count = core::cmp::min(dst.len() as u64, size - off) as usize;
        let blocks = (count as u64).saturating_add(bs - 1) / bs;
        if blocks > u32::MAX as u64 { return Err(MountError::Inode(InodeError::BadLen)); }
        let data = self.read_file_range(inode, (off / bs) as u32, blocks as u32)?;
        dst[..count].copy_from_slice(&data[..count]);
        Ok(count)
    }

    /// Write file data directly through ext4's extent allocator and the
    /// block device.  Allocation and size publication remain journal-owned by
    /// `write_at`; no page-cache frame is used for the data transfer.
    /// # C: O(extents + allocation) + O(device requests)
    pub(crate) fn direct_write(&self, ino: u32, off: u64, src: &[u8])
        -> Result<usize, MountError>
    {
        if src.is_empty() { return Ok(0); }
        let bs = self.sb.block_size as u64;
        if bs == 0 || off % bs != 0 || (src.len() as u64) % bs != 0 {
            return Err(MountError::Inode(InodeError::BadLen));
        }
        off.checked_add(src.len() as u64)
            .ok_or(MountError::Inode(InodeError::BadLen))?;
        self.write_at(ino, off, src)?;
        Ok(src.len())
    }
}
