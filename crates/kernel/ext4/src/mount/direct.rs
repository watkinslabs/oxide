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

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec;
    use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
    use sync::TaskList;

    use super::*;

    const IMAGE: &[u8] = include_bytes!("../../tests/mini.img");
    const SECTOR: u32 = 512;

    fn disk() -> Arc<MemDisk<TaskList>> {
        let cap = IMAGE.len() as u64 / SECTOR as u64;
        let disk = MemDisk::new(SECTOR, cap);
        let mut req = BlockRequest {
            op: BlockOp::Write,
            start_block: 0,
            len_blocks: cap as u32,
            buffer: IMAGE.to_vec(),
            ..Default::default()
        };
        disk.submit_sync(&mut req).unwrap();
        disk
    }

    #[test]
    fn direct_read_uses_extent_data_and_rejects_unaligned_requests() {
        let m = Mount::open(disk()).unwrap();
        let ino = m.lookup_path(b"/hello.txt").unwrap();
        let inode = m.read_inode(ino).unwrap();
        let bs = m.sb.block_size as usize;
        let mut got = vec![0; bs];
        let n = m.direct_read(&inode, 0, &mut got).unwrap();
        assert_eq!(n, inode.size as usize);
        assert_eq!(&got[..n], &m.read_file_block(&inode, 0).unwrap()[..n]);
        assert_eq!(m.direct_read(&inode, 1, &mut got),
            Err(MountError::Inode(InodeError::BadLen)));
    }

    #[test]
    fn direct_read_uses_legacy_indirect_mapping() {
        let m = Mount::open(disk()).unwrap();
        let extent_inode = m.read_inode(m.lookup_path(b"/hello.txt").unwrap()).unwrap();
        let extent = inode::parse_inline_extent(&extent_inode.i_block,
            &inode::parse_extent_header(&extent_inode.i_block).unwrap(), 0).unwrap();
        let mut legacy = extent_inode;
        legacy.i_flags &= !inode::EXT4_EXTENTS_FL;
        legacy.i_block = [0; inode::I_BLOCK_LEN];
        legacy.i_block[..4].copy_from_slice(&(extent.start_lba() as u32).to_le_bytes());
        legacy.size = m.sb.block_size as u64;
        let mut got = vec![0; m.sb.block_size as usize];
        assert_eq!(m.direct_read(&legacy, 0, &mut got).unwrap(), got.len());
        assert_eq!(got, m.read_file_block(&legacy, 0).unwrap());
    }

    #[test]
    fn direct_write_uses_legacy_indirect_mapping() {
        let m = Mount::open(disk()).unwrap();
        let ino = m.lookup_path(b"/hello.txt").unwrap();
        let (mut raw, _) = m.read_inode_bytes(ino).unwrap();
        raw[0x20..0x24].copy_from_slice(&0u32.to_le_bytes());
        let first = m.read_inode(ino).unwrap().i_block;
        raw[0x28..0x28 + inode::I_BLOCK_LEN].fill(0);
        raw[0x28..0x2c].copy_from_slice(&inode::parse_inline_extent(
            &first, &inode::parse_extent_header(&first).unwrap(), 0).unwrap()
            .start_lba().to_le_bytes()[..4]);
        m.write_inode_bytes_data(ino, &raw).unwrap();
        let data = vec![0xC3u8; 1024];
        assert_eq!(m.direct_write(ino, 0, &data).unwrap(), data.len());
        let mut got = vec![0u8; 1024];
        assert_eq!(m.direct_read(&m.read_inode(ino).unwrap(), 0, &mut got).unwrap(), got.len());
        assert_eq!(got, data);
    }

    #[test]
    fn direct_write_survives_remount() {
        let disk = disk();
        let ino;
        let bs;
        {
            let m = Mount::open(disk.clone()).unwrap();
            ino = m.lookup_path(b"/hello.txt").unwrap();
            bs = m.sb.block_size as usize;
            let data = vec![0xD3; bs];
            assert_eq!(m.direct_write(ino, 0, &data).unwrap(), bs);
            assert_eq!(m.read_file_block(&m.read_inode(ino).unwrap(), 0).unwrap(), data);
            assert_eq!(m.direct_write(ino, 1, &[0xAA; 1]),
                Err(MountError::Inode(InodeError::BadLen)));
        }
        let m = Mount::open(disk).unwrap();
        let inode = m.read_inode(ino).unwrap();
        assert_eq!(m.read_file_block(&inode, 0).unwrap(), vec![0xD3; bs]);
    }

    #[test]
    fn direct_read_treats_unwritten_extent_as_zero_until_written() {
        let m = Mount::open(disk()).unwrap();
        let ino = m.lookup_path(b"/hello.txt").unwrap();
        let bs = m.sb.block_size as usize;
        m.fallocate_inode(ino, (2 * bs) as u64, bs as u64, false).unwrap();
        let inode = m.read_inode(ino).unwrap();
        let mut got = vec![0xFF; bs];
        assert_eq!(m.direct_read(&inode, (2 * bs) as u64, &mut got).unwrap(), bs);
        assert_eq!(got, vec![0; bs], "unwritten extents must read as zero");
        let data = vec![0x5A; bs];
        assert_eq!(m.direct_write(ino, (2 * bs) as u64, &data).unwrap(), bs);
        let inode = m.read_inode(ino).unwrap();
        let mut got = vec![0; bs];
        assert_eq!(m.direct_read(&inode, (2 * bs) as u64, &mut got).unwrap(), bs);
        assert_eq!(got, data, "a direct write converts the unwritten range");
    }
}
