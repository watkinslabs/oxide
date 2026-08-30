//! The synchronous ext4 `O_DIRECT` data path.
//!
//! Linux's ext4 direct path is an extent-mapped device transfer, not the
//! queued polled-transfer API.  Keep this owner beside the mount's extent and
//! block I/O code so it cannot accidentally become a second page-cache path.

use alloc::vec::Vec;

use crate::inode::{self, InodeError};
use crate::extent_rw::PhysRun;

use super::{Mount, MountError};

impl Mount {
    /// Read file data directly from mapped blocks, serving holes and unwritten
    /// extents as zeroes. The caller has already selected synchronous
    /// `O_DIRECT`; requests must satisfy the device alignment contract, while
    /// the block mapper handles sub-filesystem-block offsets like Linux iomap.
    /// # C: O(extents in range) + O(device requests)
    pub(crate) fn direct_read(&self, inode: &inode::Inode, off: u64, dst: &mut [u8])
        -> Result<usize, MountError>
    {
        if dst.is_empty() { return Ok(0); }
        let bs = self.sb.block_size as u64;
        let dev_bs = self.dev.block_size() as u64;
        if bs == 0 || dev_bs == 0 || off % dev_bs != 0 || (dst.len() as u64) % dev_bs != 0 {
            return Err(MountError::Inode(InodeError::BadLen));
        }
        let size = inode.size;
        if off >= size { return Ok(0); }
        let count = core::cmp::min(dst.len() as u64, size - off) as usize;
        let start_in_block = off % bs;
        let blocks = (start_in_block + count as u64).saturating_add(bs - 1) / bs;
        if blocks > u32::MAX as u64 { return Err(MountError::Inode(InodeError::BadLen)); }
        let data = self.read_file_range(inode, (off / bs) as u32, blocks as u32)?;
        let start = start_in_block as usize;
        dst[..count].copy_from_slice(&data[start..start + count]);
        Ok(count)
    }

    /// Write file data directly through ext4's mapper and the block device.
    /// Allocation and size publication remain journal-owned by `write_at`; no
    /// page-cache frame is used for the data transfer.
    /// # C: O(extents + allocation) + O(device requests)
    pub(crate) fn direct_write(&self, ino: u32, off: u64, src: &[u8])
        -> Result<usize, MountError>
    {
        if src.is_empty() { return Ok(0); }
        let dev_bs = self.dev.block_size() as u64;
        if dev_bs == 0 || off % dev_bs != 0 || (src.len() as u64) % dev_bs != 0 {
            return Err(MountError::Inode(InodeError::BadLen));
        }
        let end = off.checked_add(src.len() as u64)
            .ok_or(MountError::Inode(InodeError::BadLen))?;
        let inode = self.read_inode(ino)?;
        let fs_bs = self.sb.block_size as u64;
        // Linux's iomap DIO overwrite path does not start a transaction for
        // an initialized, in-file range: the extent map is already stable and
        // the device owns the data transfer. Keep the allocation/journal
        // fallback below for holes, unwritten extents, extension, partial
        // filesystem blocks, and inline files, where metadata really changes.
        let runs = match self.collect_inode_phys_extents(&inode) {
            Ok(runs) => runs,
            Err(MountError::NotExtents) => Vec::new(),
            Err(error) => return Err(error),
        };
        if let Some(plan) = direct_overwrite_plan(&runs, off, end, inode.size, fs_bs)
        {
            for (source, physical, length) in plan {
                let byte_off = physical.checked_mul(fs_bs)
                    .ok_or(MountError::Inode(InodeError::BadLen))?;
                self.write_data_byte_range(byte_off, &src[source .. source + length])?;
            }
            return Ok(src.len());
        }
        self.write_at(ino, off, src)?;
        Ok(src.len())
    }
}

/// Build the no-metadata-change DIO overwrite plan. Every byte in the request
/// must be covered by initialized physical runs, and the request must cover
/// complete filesystem blocks. The returned source offsets remain in logical
/// request order, while each device span follows the inode's physical extent
/// geometry. # C: O(N_extents)
fn direct_overwrite_plan(runs: &[PhysRun], off: u64, end: u64, size: u64, bs: u64)
    -> Option<Vec<(usize, u64, usize)>>
{
    if bs == 0 || off % bs != 0 || end % bs != 0 || end > size { return None; }
    let mut covered = off;
    let mut plan = Vec::new();
    for run in runs {
        if run.unwritten { continue; }
        let run_start = u64::from(run.logical).checked_mul(bs)?;
        let run_end = run_start.checked_add(u64::from(run.len).checked_mul(bs)?)?;
        let start = core::cmp::max(off, run_start);
        let finish = core::cmp::min(end, run_end);
        if start >= finish { continue; }
        if start != covered || start % bs != 0 || finish % bs != 0 { return None; }
        let logical_blocks = (start - run_start) / bs;
        let physical = run.phys.checked_add(logical_blocks)?;
        let length = usize::try_from(finish - start).ok()?;
        plan.push(((start - off) as usize, physical, length));
        covered = finish;
        if covered == end { break; }
    }
    (covered == end).then_some(plan)
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
        let mut partial = vec![0; 512];
        assert_eq!(m.direct_read(&legacy, 512, &mut partial).unwrap(), partial.len());
        assert_eq!(partial, got[512..1024].to_vec());
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
        let expected;
        {
            let m = Mount::open(disk.clone()).unwrap();
            ino = m.lookup_path(b"/hello.txt").unwrap();
            bs = m.sb.block_size as usize;
        let data = vec![0xD3; bs];
        assert_eq!(m.direct_write(ino, 0, &data).unwrap(), bs);
        let partial = vec![0xAA; 512];
        assert_eq!(m.direct_write(ino, 512, &partial).unwrap(), partial.len());
        let mut final_data = data;
        final_data[512..1024].copy_from_slice(&partial);
        expected = final_data;
        assert_eq!(m.read_file_block(&m.read_inode(ino).unwrap(), 0).unwrap(), expected);
            assert_eq!(m.direct_write(ino, 1, &[0xAA; 1]),
                Err(MountError::Inode(InodeError::BadLen)));
        }
        let m = Mount::open(disk).unwrap();
        let inode = m.read_inode(ino).unwrap();
        assert_eq!(m.read_file_block(&inode, 0).unwrap(), expected);
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

    #[test]
    fn overwrite_plan_only_accepts_initialized_full_filesystem_blocks() {
        let runs = vec![PhysRun { logical: 4, phys: 100, len: 3, unwritten: false }];
        assert_eq!(direct_overwrite_plan(&runs, 4 * 4096, 6 * 4096, 7 * 4096, 4096),
            Some(vec![(0, 100, 2 * 4096)]));
        assert_eq!(direct_overwrite_plan(&runs, 4 * 4096 + 512, 6 * 4096, 7 * 4096, 4096), None);
        assert_eq!(direct_overwrite_plan(&runs, 4 * 4096, 8 * 4096, 7 * 4096, 4096), None);
    }

    #[test]
    fn overwrite_plan_defers_unwritten_and_hole_ranges_to_mapping_owner() {
        let unwritten = vec![PhysRun { logical: 0, phys: 100, len: 2, unwritten: true }];
        assert_eq!(direct_overwrite_plan(&unwritten, 0, 4096, 8192, 4096), None);
        let split = vec![
            PhysRun { logical: 0, phys: 100, len: 1, unwritten: false },
            PhysRun { logical: 2, phys: 102, len: 1, unwritten: false },
        ];
        assert_eq!(direct_overwrite_plan(&split, 0, 3 * 4096, 3 * 4096, 4096), None);
    }
}
