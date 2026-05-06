// ext4 inode bitmap allocator + create/unlink. Structurally
// parallel to `balloc.rs`: scan group inode-bitmaps for first
// clear bit, set it, persist bitmap + GDT free-inodes counter +
// SB free-inodes counter.
//
// Allocates a 1-indexed inode number. On `free`, also walks the
// target inode's extent tree and frees each data block first
// (caller is `unlink` after nlink → 0).

use crate::balloc::find_first_clear;
use crate::dir;
use crate::gdt;
use crate::inode::{
    self, ExtentHeader, EXT4_EXT_MAGIC, I_BLOCK_LEN, S_IFDIR, S_IFREG,
};
use crate::mount::{Mount, MountError, read_byte_range_pub};
use crate::superblock::SB_OFF_FREE_INODES;

extern crate alloc;
use alloc::vec;

impl Mount {
    /// Allocate one previously-free inode. Searches groups from
    /// `hint` forward. Returns the 1-indexed inode number with
    /// the on-disk bitmap + counters mutated.
    /// # C: O(N_groups * block_size) worst-case
    pub fn alloc_inode(&self, hint: u32) -> Result<u32, MountError> {
        self.run_journaled(|m| {
            let groups = m.sb.group_count();
            if groups == 0 { return Err(MountError::NoSpace); }
            for off in 0..groups {
                let g = (hint + off) % groups;
                if let Some(ino) = m.try_alloc_inode_in_group(g)? {
                    return Ok(ino);
                }
            }
            Err(MountError::NoSpace)
        })
    }

    fn try_alloc_inode_in_group(&self, group: u32) -> Result<Option<u32>, MountError> {
        let gd_orig = {
            let s = self.state.lock();
            gdt::parse_descriptor(&s.gdt_buf, group, &self.sb)?
        };
        if gd_orig.free_inodes_count == 0 { return Ok(None); }
        let ibm_byte_off = gd_orig.inode_bitmap * (self.sb.block_size as u64);
        let mut bitmap = read_byte_range_pub(&*self.dev, ibm_byte_off, self.sb.block_size as usize)?;
        let bit = match find_first_clear(&bitmap, self.sb.inodes_per_group) {
            Some(b) => b,
            None    => return Ok(None),
        };
        let final_bit = if group == 0 && bit < 10 {
            let mut b = 10usize;
            while b < self.sb.inodes_per_group as usize {
                if (bitmap[b >> 3] & (1u8 << (b & 7))) == 0 { break; }
                b += 1;
            }
            if b >= self.sb.inodes_per_group as usize { return Ok(None); }
            b
        } else {
            bit
        };
        bitmap[final_bit >> 3] |= 1u8 << (final_bit & 7);
        let mut gd = gd_orig;
        gd.free_inodes_count = gd.free_inodes_count.saturating_sub(1);
        {
            let mut s = self.state.lock();
            gdt::write_descriptor_counters(&mut s.gdt_buf, group, &self.sb, &gd)?;
            s.sb_free_inodes = s.sb_free_inodes.saturating_sub(1);
        }
        self.metadata_write(ibm_byte_off, &bitmap)?;
        self.persist_gdt_slot_meta(group)?;
        self.persist_sb_free_inodes_meta()?;
        self.flush_pending_tx()?;
        let ino = group * self.sb.inodes_per_group + final_bit as u32 + 1;
        Ok(Some(ino))
    }

    /// Mark `ino` free in its group's inode bitmap. Caller must
    /// already have freed the file's data blocks.
    /// # C: O(1) bitmap I/O
    pub fn free_inode(&self, ino: u32) -> Result<(), MountError> {
        if ino == 0 || ino > self.sb.inodes_count {
            return Err(MountError::Inode(inode::InodeError::BadLen));
        }
        self.run_journaled(|m| {
            let group = (ino - 1) / m.sb.inodes_per_group;
            let bit   = (ino - 1) % m.sb.inodes_per_group;
            let gd_orig = {
                let s = m.state.lock();
                gdt::parse_descriptor(&s.gdt_buf, group, &m.sb)?
            };
            let ibm_byte_off = gd_orig.inode_bitmap * (m.sb.block_size as u64);
            let mut bitmap = read_byte_range_pub(&*m.dev, ibm_byte_off, m.sb.block_size as usize)?;
            let bidx = bit as usize;
            let mask = 1u8 << (bidx & 7);
            if (bitmap[bidx >> 3] & mask) == 0 { return Err(MountError::DoubleFree); }
            bitmap[bidx >> 3] &= !mask;
            let mut gd = gd_orig;
            gd.free_inodes_count = gd.free_inodes_count.saturating_add(1);
            {
                let mut s = m.state.lock();
                gdt::write_descriptor_counters(&mut s.gdt_buf, group, &m.sb, &gd)?;
                s.sb_free_inodes = s.sb_free_inodes.saturating_add(1);
            }
            m.metadata_write(ibm_byte_off, &bitmap)?;
            m.persist_gdt_slot_meta(group)?;
            m.persist_sb_free_inodes_meta()?;
            m.flush_pending_tx()?;
            Ok(())
        })
    }

    pub(crate) fn persist_sb_free_inodes_meta(&self) -> Result<(), MountError> {
        let count = self.state.lock().sb_free_inodes;
        let mut sb_buf = read_byte_range_pub(
            &*self.dev,
            crate::superblock::SUPERBLOCK_OFFSET,
            crate::superblock::SUPERBLOCK_LEN,
        )?;
        sb_buf[SB_OFF_FREE_INODES..SB_OFF_FREE_INODES+4]
            .copy_from_slice(&count.to_le_bytes());
        self.metadata_write(crate::superblock::SUPERBLOCK_OFFSET, &sb_buf)
    }

    /// Create a regular file `name` under directory `parent_ino`.
    /// Allocates an inode, writes a fresh on-disk inode (mode
    /// `S_IFREG | mode_perm`, nlink=1, empty extent tree, size 0),
    /// and adds a directory entry. Returns the new inode number.
    /// # C: O(N parent entries) + 1 inode-alloc + 2 block I/Os
    pub fn create_file(&self, parent_ino: u32, name: &[u8], mode_perm: u16)
        -> Result<u32, MountError>
    {
        self.run_journaled(|m| {
            let parent_group = (parent_ino - 1) / m.sb.inodes_per_group;
            let new_ino = m.alloc_inode(parent_group)?;
            m.init_inode(new_ino, S_IFREG | (mode_perm & 0x0FFF), 1)?;
            m.dir_link(parent_ino, name, new_ino, dir::DT_REG)?;
            Ok(new_ino)
        })
    }

    /// Unlink `name` from `parent_ino`. Decrements target's
    /// link count; on reaching 0 frees data blocks + inode.
    /// # C: O(N parent entries) + (link>1 ? 1 inode write : N_extents block frees + 1 inode-free)
    pub fn unlink(&self, parent_ino: u32, name: &[u8]) -> Result<(), MountError> {
        self.run_journaled(|m| {
            let target_ino = m.dir_unlink(parent_ino, name)?;
            let (mut bytes, off) = m.read_inode_bytes(target_ino)?;
            let mut links = u16::from_le_bytes([bytes[0x1A], bytes[0x1B]]);
            links = links.saturating_sub(1);
            bytes[0x1A..0x1C].copy_from_slice(&links.to_le_bytes());
            if links == 0 {
                let mut i_block = [0u8; I_BLOCK_LEN];
                i_block.copy_from_slice(&bytes[0x28..0x28 + I_BLOCK_LEN]);
                if let Ok(hdr) = inode::parse_extent_header(&i_block) {
                    if hdr.depth == 0 {
                        for i in 0..hdr.entries {
                            if let Some(e) = inode::parse_inline_extent(&i_block, &hdr, i) {
                                for k in 0..e.len as u64 {
                                    let _ = m.free_block(e.start_lba() + k);
                                }
                            }
                        }
                    }
                }
                bytes[0x04..0x08].copy_from_slice(&0u32.to_le_bytes());
                bytes[0x6C..0x70].copy_from_slice(&0u32.to_le_bytes());
                bytes[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes());
                for b in &mut bytes[0x28..0x28 + I_BLOCK_LEN] { *b = 0; }
                m.metadata_write(off, &bytes)?;
                m.free_inode(target_ino)?;
            } else {
                m.metadata_write(off, &bytes)?;
            }
            Ok(())
        })
    }

    /// Write a fresh inode struct (mode + nlink + empty extent
    /// tree, size=0, blocks=0). Other timestamps/uid/gid stay 0.
    /// # C: O(1) I/O
    pub fn init_inode(&self, ino: u32, mode: u16, nlink: u16) -> Result<(), MountError> {
        let mut bytes = vec![0u8; self.sb.inode_size as usize];
        bytes[0x00..0x02].copy_from_slice(&mode.to_le_bytes());
        bytes[0x1A..0x1C].copy_from_slice(&nlink.to_le_bytes());
        let hdr = ExtentHeader { magic: EXT4_EXT_MAGIC, entries: 0, max: 4, depth: 0, generation: 0 };
        let mut i_block = [0u8; I_BLOCK_LEN];
        inode::write_extent_header(&mut i_block, &hdr);
        bytes[0x28..0x28 + I_BLOCK_LEN].copy_from_slice(&i_block);
        // Goes through write_inode_bytes → metadata_write (after refactor below).
        self.write_inode_bytes(ino, &bytes)
    }

    /// Create an empty subdirectory `name` under `parent_ino`.
    /// Allocates a fresh inode, initializes mode `S_IFDIR | perm`,
    /// nlink=2 (the implicit `.` self-link), then `dir_link`s the
    /// name into the parent. The new directory has no `.` / `..`
    /// data block yet — callers that need to populate it should
    /// follow with `append_block`.
    /// # C: O(parent entries) + 1 inode alloc + 2 I/Os
    pub fn create_dir(&self, parent_ino: u32, name: &[u8], mode_perm: u16)
        -> Result<u32, MountError>
    {
        self.run_journaled(|m| {
            let parent_group = (parent_ino - 1) / m.sb.inodes_per_group;
            let new_ino = m.alloc_inode(parent_group)?;
            m.init_inode(new_ino, S_IFDIR | (mode_perm & 0x0FFF), 2)?;
            m.dir_link(parent_ino, name, new_ino, dir::DT_DIR)?;
            Ok(new_ino)
        })
    }
}
