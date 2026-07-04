use crate::inode;
use crate::mount::{Mount, MountError};

impl Mount {
    /// Patch the on-disk inode `i_size` field directly.
    /// # C: O(1) I/O
    pub fn set_inode_size(&self, ino: u32, size: u64) -> Result<(), MountError> {
        let (mut bytes, _off) = self.read_inode_bytes(ino)?;
        bytes[0x04..0x08].copy_from_slice(&((size & 0xFFFF_FFFF) as u32).to_le_bytes());
        bytes[0x6C..0x70].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
        self.write_inode_bytes(ino, &bytes)
    }

    /// Random-access write: `data` lands at byte offset `off` in
    /// the file at `ino`, extending the file (with zero-filled
    /// blocks if needed) when `off + data.len() > i_size`. Existing
    /// blocks touched by the write are RMW'd in-place. The trailing
    /// `i_size` is set to `max(prev_size, off + data.len())`.
    /// Caller invalidates any page cache.
    /// # C: O(file growth + N_blocks_in_range) I/O
    pub fn write_at(&self, ino: u32, off: u64, data: &[u8]) -> Result<(), MountError> {
        self.run_journaled(|m| m.write_at_inner(ino, off, data))
    }

    /// Allocate backing blocks through `offset + len`. With `keep_size`, the
    /// original `i_size` is restored after allocation without freeing extents.
    /// # C: O(file growth)
    pub fn fallocate_inode(&self, ino: u32, offset: u64, len: u64, keep_size: bool) -> Result<(), MountError> {
        let end = offset.checked_add(len).ok_or(MountError::Inode(inode::InodeError::BadLen))?;
        if len == 0 { return Ok(()); }
        self.run_journaled(|m| {
            let old_size = m.read_inode(ino)?.size;
            let bs = m.sb.block_size as u64;
            let first_lb64 = offset / bs;
            let last_lb64 = (end - 1) / bs;
            if first_lb64 > u32::MAX as u64 || last_lb64 > u32::MAX as u64 {
                return Err(MountError::Inode(inode::InodeError::BadLen));
            }
            let first_lb = first_lb64 as u32;
            let last_lb = last_lb64 as u32;
            let final_size = if keep_size { old_size } else { core::cmp::max(old_size, end) };
            let zero_blk = alloc::vec![0u8; bs as usize];

            for lb in first_lb..=last_lb {
                let inode = m.read_inode(ino)?;
                let visible_size = core::cmp::max(inode.size, (lb as u64 + 1) * bs);
                m.append_logical_block_inner(ino, lb, &zero_blk, visible_size)?;
            }
            m.set_inode_size(ino, final_size)?;
            Ok(())
        })
    }

    pub(super) fn write_at_inner(&self, ino: u32, off: u64, data: &[u8]) -> Result<(), MountError> {
        let bs = self.sb.block_size as u64;
        let bs_us = bs as usize;
        if data.is_empty() { return Ok(()); }
        let inode = self.read_inode(ino)?;
        let cur_size = inode.size;
        let end = off + data.len() as u64;
        let new_size = core::cmp::max(cur_size, end);
        let cur_blocks = (cur_size + bs - 1) / bs;
        let new_blocks = (new_size + bs - 1) / bs;
        // Phase 1: zero-extend file to new_blocks worth of blocks.
        let zero_blk = alloc::vec![0u8; bs_us];
        for _ in cur_blocks..new_blocks {
            self.append_block(ino, &zero_blk)?;
        }
        // Phase 2: RMW each touched block. Re-read inode (extents
        // changed during phase 1).
        let inode2 = self.read_inode(ino)?;
        let first_lb = (off / bs) as u32;
        let last_lb  = ((end - 1) / bs) as u32;
        let mut written = 0usize;
        for lb in first_lb..=last_lb {
            let blk_start_byte = (lb as u64) * bs;
            let in_blk_off = if blk_start_byte >= off { 0usize }
                             else { (off - blk_start_byte) as usize };
            let blk_end_byte = blk_start_byte + bs;
            let copy_end_in_blk = if end >= blk_end_byte { bs_us }
                                  else { (end - blk_start_byte) as usize };
            let copy_len = copy_end_in_blk - in_blk_off;
            let mut blk = self.read_file_block(&inode2, lb)?;
            if blk.len() < bs_us { blk.resize(bs_us, 0); }
            blk[in_blk_off..in_blk_off + copy_len]
                .copy_from_slice(&data[written .. written + copy_len]);
            self.write_file_block(&inode2, lb, &blk)?;
            written += copy_len;
        }
        // Phase 3: persist the (potentially partial-block) i_size.
        self.set_inode_size(ino, new_size)?;
        Ok(())
    }
}
