use crate::inode::{self, Inode};
use super::{Mount, MountError};

impl Mount {
    /// Resolve a legacy ext2/3-style inode's direct, single-, double-, or
    /// triple-indirect block pointer. Linux keeps this path for ext4 inodes
    /// that predate extent conversion; it is a read owner only here because
    /// allocation, truncate, and metadata publication still belong to the
    /// extent writer. Inline-data inodes are rejected before this decoder so
    /// their payload is never mistaken for block numbers. # C: O(depth)
    pub(super) fn resolve_indirect_pblock(&self, inode: &Inode, file_blk: u32)
        -> Result<u64, MountError>
    {
        if inode.i_flags & inode::EXT4_INLINE_DATA_FL != 0 {
            return Err(MountError::NotExtents);
        }
        let ptrs = (self.sb.block_size / 4) as u64;
        if ptrs == 0 { return Err(MountError::BlockIo); }
        let logical = file_blk as u64;
        let (root, indexes): (u32, [u64; 3]) = if logical < 12 {
            let off = (logical as usize) * 4;
            (u32::from_le_bytes([inode.i_block[off], inode.i_block[off + 1],
                                  inode.i_block[off + 2], inode.i_block[off + 3]]),
             [u64::MAX; 3])
        } else {
            let mut n = logical - 12;
            if n < ptrs {
                (Self::inline_block_pointer(inode, 12), [n, u64::MAX, u64::MAX])
            } else {
                n -= ptrs;
                let square = ptrs.checked_mul(ptrs).ok_or(MountError::BadBlock)?;
                if n < square {
                    (Self::inline_block_pointer(inode, 13), [n / ptrs, n % ptrs, u64::MAX])
                } else {
                    n -= square;
                    let cube = square.checked_mul(ptrs).ok_or(MountError::BadBlock)?;
                    if n >= cube { return Err(MountError::NotFound); }
                    (Self::inline_block_pointer(inode, 14),
                     [n / square, (n / ptrs) % ptrs, n % ptrs])
                }
            }
        };
        if root == 0 { return Err(MountError::NotFound); }
        self.check_inode_blocks(root as u64, 1)?;
        let mut block = root as u64;
        for index in indexes {
            if index == u64::MAX { return Ok(block); }
            let table = self.read_metadata_block(block)?;
            let off = index.checked_mul(4).ok_or(MountError::BadBlock)? as usize;
            if off.checked_add(4).is_none() || off + 4 > table.len() {
                return Err(MountError::BadBlock);
            }
            block = u32::from_le_bytes([table[off], table[off + 1], table[off + 2], table[off + 3]]) as u64;
            if block == 0 { return Err(MountError::NotFound); }
            self.check_inode_blocks(block, 1)?;
        }
        Ok(block)
    }

    fn inline_block_pointer(inode: &Inode, index: usize) -> u32 {
        let off = index * 4;
        u32::from_le_bytes([inode.i_block[off], inode.i_block[off + 1],
                            inode.i_block[off + 2], inode.i_block[off + 3]])
    }
}
