// File-data RW path: append one filesystem block of data to a
// regular file by allocating a fresh data block, writing it, and
// either growing the trailing extent (when the new block is
// contiguous with the previous tail's `start_lba + len`) or
// adding a new inline extent leaf.
//
// Inline-only (depth=0). When the inline leaf array (4 slots)
// is full + the trailing extent isn't contiguous, surfaces
// `MountError::ExtentTreeFull`. External index nodes are a
// follow-up arc; v1 does not need them for the userspace write
// surface (every user file in our images fits in 4 extents).

use crate::inode::{self, Extent, I_BLOCK_LEN};
use crate::mount::{Mount, MountError, write_byte_range, read_byte_range_pub};

extern crate alloc;
use alloc::vec::Vec;

impl Mount {
    /// Append `data` to the file at `ino`. `data.len()` must equal
    /// `sb.block_size` (the FS-block-granular interface). Allocates
    /// one fresh block, writes the bytes, and either extends the
    /// trailing extent or adds a new inline leaf. Updates inode
    /// `i_size` + writes the mutated inode bytes back to disk.
    ///
    /// Returns the file-relative logical block index that was
    /// just appended (== prior `(i_size + bs - 1) / bs`).
    /// # C: O(N_extents) + 1 alloc + 2 block I/Os (data + inode)
    pub fn append_block(&self, ino: u32, data: &[u8]) -> Result<u32, MountError> {
        self.run_journaled(|m| m.append_block_inner(ino, data))
    }

    fn append_block_inner(&self, ino: u32, data: &[u8]) -> Result<u32, MountError> {
        let bs = self.sb.block_size as usize;
        if data.len() != bs {
            return Err(MountError::Inode(inode::InodeError::BadLen));
        }
        let (mut ino_bytes, ino_byte_off) = self.read_inode_bytes(ino)?;
        let mut i_block: [u8; I_BLOCK_LEN] = {
            let mut b = [0u8; I_BLOCK_LEN];
            b.copy_from_slice(&ino_bytes[0x28..0x28 + I_BLOCK_LEN]);
            b
        };
        let mut hdr = inode::parse_extent_header(&i_block)?;
        if hdr.depth != 0 { return Err(MountError::DepthUnsupported); }

        // Logical block we'll occupy = total existing logical blocks.
        let cur_size = u32::from_le_bytes([ino_bytes[0x04], ino_bytes[0x05], ino_bytes[0x06], ino_bytes[0x07]]) as u64
            | ((u32::from_le_bytes([ino_bytes[0x6C], ino_bytes[0x6D], ino_bytes[0x6E], ino_bytes[0x6F]]) as u64) << 32);
        let new_logical = ((cur_size + bs as u64 - 1) / bs as u64) as u32;

        // Pick allocation hint: trailing extent's group, else 0.
        let hint_group = if hdr.entries > 0 {
            let last = inode::parse_inline_extent(&i_block, &hdr, hdr.entries - 1).unwrap();
            self.group_of_block(last.start_lba())
        } else { 0 };
        let phys = self.alloc_block(hint_group)?;

        // Write the data block. Regular file content is NOT
        // journaled (ordered mode: data goes direct, metadata is
        // journaled). Directory data writes use write_file_block_meta.
        let byte_off = phys * (self.sb.block_size as u64);
        write_byte_range(&*self.dev, byte_off, data)?;

        // Either extend the trailing extent or add a new leaf.
        let mut grew_existing = false;
        if hdr.entries > 0 {
            let mut last = inode::parse_inline_extent(&i_block, &hdr, hdr.entries - 1).unwrap();
            // Contiguous physical, contiguous logical, room in 16-bit len.
            if last.start_lba() + last.len as u64 == phys
                && last.block + last.len as u32 == new_logical
                && last.len < EXTENT_LEN_MAX
            {
                last.len += 1;
                inode::write_inline_extent(&mut i_block, hdr.entries - 1, &last);
                grew_existing = true;
            }
        }
        if !grew_existing {
            if hdr.entries >= 4 { return Err(MountError::ExtentTreeFull); }
            let new_leaf = Extent {
                block: new_logical,
                len: 1,
                start_hi: (phys >> 32) as u16,
                start_lo: (phys & 0xFFFF_FFFF) as u32,
            };
            inode::write_inline_extent(&mut i_block, hdr.entries, &new_leaf);
            hdr.entries += 1;
            inode::write_extent_header(&mut i_block, &hdr);
        }

        // Splice the mutated extent tree + new size back into the
        // raw inode buffer, then write the inode slot.
        ino_bytes[0x28..0x28 + I_BLOCK_LEN].copy_from_slice(&i_block);
        let new_size = cur_size + bs as u64;
        ino_bytes[0x04..0x08].copy_from_slice(&((new_size & 0xFFFF_FFFF) as u32).to_le_bytes());
        ino_bytes[0x6C..0x70].copy_from_slice(&((new_size >> 32) as u32).to_le_bytes());
        // i_blocks (in 512-byte sectors). For correctness we update
        // it; ext4 readers use this for stat(). One fs block = bs/512
        // 512-byte sectors.
        let prev_i_blocks = u32::from_le_bytes([ino_bytes[0x1C], ino_bytes[0x1D], ino_bytes[0x1E], ino_bytes[0x1F]]);
        let added_sectors = (self.sb.block_size / 512) as u32;
        let new_i_blocks = prev_i_blocks.saturating_add(added_sectors);
        ino_bytes[0x1C..0x20].copy_from_slice(&new_i_blocks.to_le_bytes());

        // Inode bytes are metadata.
        self.metadata_write(ino_byte_off, &ino_bytes)?;
        Ok(new_logical)
    }

    /// Read the raw on-disk inode slot bytes for `ino`. Returns the
    /// bytes + the byte offset they were read from (so the caller
    /// can write the mutated buffer back to the same slot).
    /// # C: O(1) I/O
    pub fn read_inode_bytes(&self, ino: u32) -> Result<(Vec<u8>, u64), MountError> {
        let (group, idx) = crate::gdt::locate_inode(&self.sb, ino)?;
        let gd = self.group_desc(group)?;
        let off_in_table = (idx as u64) * (self.sb.inode_size as u64);
        let byte_off = gd.inode_table * (self.sb.block_size as u64) + off_in_table;
        let bytes = read_byte_range_pub(&*self.dev, byte_off, self.sb.inode_size as usize)?;
        Ok((bytes, byte_off))
    }

    /// Write a freshly-mutated inode-bytes slot back to disk.
    /// # C: O(1) I/O
    pub fn write_inode_bytes(&self, ino: u32, bytes: &[u8]) -> Result<(), MountError> {
        let (group, idx) = crate::gdt::locate_inode(&self.sb, ino)?;
        let gd = self.group_desc(group)?;
        let off_in_table = (idx as u64) * (self.sb.inode_size as u64);
        let byte_off = gd.inode_table * (self.sb.block_size as u64) + off_in_table;
        if bytes.len() != self.sb.inode_size as usize {
            return Err(MountError::Inode(inode::InodeError::BadLen));
        }
        // Inode bytes are metadata — route through journaled path.
        self.metadata_write(byte_off, bytes)
    }

    /// Group containing a given physical block. Inverse of
    /// `group_first_block`.
    /// # C: O(1)
    pub fn group_of_block(&self, phys: u64) -> u32 {
        let bpg = self.sb.blocks_per_group as u64;
        if bpg == 0 { return 0; }
        let rel = phys.saturating_sub(self.sb.first_data_block as u64);
        (rel / bpg) as u32
    }
}

/// Cap per ext4 spec: an extent's `ee_len` is 16 bits, but the
/// top bit signals "uninitialized"; usable max is 0x8000.
pub const EXTENT_LEN_MAX: u16 = 0x8000;

impl Mount {
    /// Patch the on-disk inode `i_size` field directly, without
    /// touching extents or block counters. Used after a partial-
    /// final-block append to reflect the true byte length.
    /// # C: O(1) I/O
    pub fn set_inode_size(&self, ino: u32, size: u64) -> Result<(), MountError> {
        let (mut bytes, off) = self.read_inode_bytes(ino)?;
        bytes[0x04..0x08].copy_from_slice(&((size & 0xFFFF_FFFF) as u32).to_le_bytes());
        bytes[0x6C..0x70].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
        self.metadata_write(off, &bytes)
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

    fn write_at_inner(&self, ino: u32, off: u64, data: &[u8]) -> Result<(), MountError> {
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

    /// Truncate `ino` to `new_len` bytes. Frees trailing whole
    /// blocks; updates the trailing extent's `len` (or removes
    /// extent leaves) when `new_len` falls before its current end.
    /// Inline-only (depth=0). Larger files (multi-leaf) are
    /// handled by walking + freeing leaves from the tail.
    /// # C: O(N_extents) + N_blocks_freed I/O
    pub fn truncate_inode(&self, ino: u32, new_len: u64) -> Result<(), MountError> {
        self.run_journaled(|m| m.truncate_inode_inner(ino, new_len))
    }

    fn truncate_inode_inner(&self, ino: u32, new_len: u64) -> Result<(), MountError> {
        let bs = self.sb.block_size as u64;
        let inode = self.read_inode(ino)?;
        let cur_size = inode.size;
        if new_len > cur_size {
            // Extend by writing 0 bytes at new_len-1 (zero-fills).
            let z = [0u8; 1];
            return self.write_at(ino, new_len - 1, &z);
        }
        // Shrink path. For each extent (last to first), free blocks
        // wholly past new_len; update extent.len for partial-keep.
        let blocks_keep = (new_len + bs - 1) / bs;
        let (mut bytes, off_inode) = self.read_inode_bytes(ino)?;
        let mut i_block = [0u8; I_BLOCK_LEN];
        i_block.copy_from_slice(&bytes[0x28..0x28 + I_BLOCK_LEN]);
        let hdr0 = inode::parse_extent_header(&i_block)?;
        if hdr0.depth != 0 { return Err(MountError::DepthUnsupported); }
        let mut new_entries = hdr0.entries;
        // Walk leaves last → first.
        for i in (0..hdr0.entries).rev() {
            let e = inode::parse_inline_extent(&i_block, &hdr0, i).unwrap();
            let ext_first_lb = e.block as u64;
            let ext_last_lb_excl = ext_first_lb + e.len as u64;
            if ext_first_lb >= blocks_keep {
                // Whole extent past EOF — free all blocks.
                for k in 0..e.len as u64 {
                    let _ = self.free_block(e.start_lba() + k);
                }
                new_entries -= 1;
            } else if ext_last_lb_excl > blocks_keep {
                // Partial keep: shrink len.
                let keep = (blocks_keep - ext_first_lb) as u16;
                for k in keep as u64..e.len as u64 {
                    let _ = self.free_block(e.start_lba() + k);
                }
                let mut e2 = e; e2.len = keep;
                inode::write_inline_extent(&mut i_block, i, &e2);
            }
        }
        let mut new_hdr = hdr0;
        new_hdr.entries = new_entries;
        inode::write_extent_header(&mut i_block, &new_hdr);
        bytes[0x28..0x28 + I_BLOCK_LEN].copy_from_slice(&i_block);
        // i_blocks (in 512-byte sectors). Recompute from extents.
        let mut sectors: u32 = 0;
        for i in 0..new_entries {
            if let Some(e) = inode::parse_inline_extent(&i_block, &new_hdr, i) {
                sectors = sectors.saturating_add((e.len as u32) * (self.sb.block_size / 512));
            }
        }
        bytes[0x1C..0x20].copy_from_slice(&sectors.to_le_bytes());
        // Set new size.
        bytes[0x04..0x08].copy_from_slice(&((new_len & 0xFFFF_FFFF) as u32).to_le_bytes());
        bytes[0x6C..0x70].copy_from_slice(&((new_len >> 32) as u32).to_le_bytes());
        self.metadata_write(off_inode, &bytes)?;
        Ok(())
    }

    /// Bump (or decrement) the link count of an inode by `delta`.
    /// Saturating; never goes negative — caller is responsible for
    /// only freeing the inode when the count reaches 0 via
    /// `unlink`.
    /// # C: O(1) I/O
    pub fn adjust_nlink(&self, ino: u32, delta: i32) -> Result<u16, MountError> {
        let (mut bytes, off) = self.read_inode_bytes(ino)?;
        let cur = u16::from_le_bytes([bytes[0x1A], bytes[0x1B]]);
        let new = if delta >= 0 {
            cur.saturating_add(delta as u16)
        } else {
            cur.saturating_sub((-delta) as u16)
        };
        bytes[0x1A..0x1C].copy_from_slice(&new.to_le_bytes());
        self.metadata_write(off, &bytes)?;
        Ok(new)
    }
}
