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

        // Write the data block.
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

        write_byte_range(&*self.dev, ino_byte_off, &ino_bytes)?;
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
        write_byte_range(&*self.dev, byte_off, bytes)
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
