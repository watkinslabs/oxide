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
    self, ExtentHeader, EXT4_EXT_MAGIC, I_BLOCK_LEN, S_IFBLK, S_IFCHR, S_IFDIR,
    S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK,
};
use crate::mount::{Mount, MountError};
use crate::superblock::SB_OFF_FREE_INODES;

extern crate alloc;
use alloc::vec;

/// `i_dtime` stamped on a freed inode. e2fsck requires a deleted
/// (links_count==0) inode to carry a deletion time that looks like a
/// timestamp — specifically `>= s_inodes_count`, otherwise it is
/// mistaken for an orphan-list "next inode" pointer. Without an
/// in-crate wall clock we use a fixed plausible Unix time (2023-11-14);
/// the exact value is immaterial to validity as long as it is large.
const DELETED_DTIME: u32 = 1_700_000_000;

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
        let mut bitmap = self.read_meta_byte_range(ibm_byte_off, self.sb.block_size as usize)?;
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
            crate::csum::set_inode_bitmap_csum(&self.sb, &mut s.gdt_buf, group, &bitmap);
            // Maintain bg_itable_unused (clamp to the new high-water) and
            // clear EXT4_BG_INODE_UNINIT — exactly as Linux ext4_new_inode.
            gdt::on_inode_allocated(&mut s.gdt_buf, group, &self.sb, final_bit as u32);
            crate::csum::stamp_group_desc_csum(&self.sb, &mut s.gdt_buf, group);
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
            let mut bitmap = m.read_meta_byte_range(ibm_byte_off, m.sb.block_size as usize)?;
            let bidx = bit as usize;
            let mask = 1u8 << (bidx & 7);
            if (bitmap[bidx >> 3] & mask) == 0 { return Err(MountError::DoubleFree); }
            bitmap[bidx >> 3] &= !mask;
            let mut gd = gd_orig;
            gd.free_inodes_count = gd.free_inodes_count.saturating_add(1);
            {
                let mut s = m.state.lock();
                gdt::write_descriptor_counters(&mut s.gdt_buf, group, &m.sb, &gd)?;
                crate::csum::set_inode_bitmap_csum(&m.sb, &mut s.gdt_buf, group, &bitmap);
                crate::csum::stamp_group_desc_csum(&m.sb, &mut s.gdt_buf, group);
                s.sb_free_inodes = s.sb_free_inodes.saturating_add(1);
            }
            m.metadata_write(ibm_byte_off, &bitmap)?;
            m.persist_gdt_slot_meta(group)?;
            m.persist_sb_free_inodes_meta()?;
            m.flush_pending_tx()?;
            Ok(())
        })
    }

    /// # C: O(1)
    pub(crate) fn persist_sb_free_inodes_meta(&self) -> Result<(), MountError> {
        let count = self.state.lock().sb_free_inodes;
        let mut sb_buf = self.read_meta_byte_range(
            crate::superblock::SUPERBLOCK_OFFSET,
            crate::superblock::SUPERBLOCK_LEN,
        )?;
        sb_buf[SB_OFF_FREE_INODES..SB_OFF_FREE_INODES+4]
            .copy_from_slice(&count.to_le_bytes());
        crate::csum::stamp_superblock_csum(&self.sb, &mut sb_buf);
        self.metadata_write(crate::superblock::SUPERBLOCK_OFFSET, &sb_buf)
    }

    /// Create an anonymous (O_TMPFILE) regular file in directory
    /// `parent_ino`. Allocates an inode with `nlink=0` and the empty
    /// extent tree, but does NOT add a directory entry — the inode
    /// is "orphan" until a subsequent `linkat(AT_EMPTY_PATH)` adds
    /// a name + bumps `nlink` to 1. If the last fd closes with
    /// `nlink` still 0, `free_orphan_inode` frees the data blocks
    /// and the inode itself.
    /// # C: O(1) — one inode alloc + one inode I/O
    pub fn create_anonymous(&self, parent_ino: u32, mode_perm: u16)
        -> Result<u32, MountError>
    {
        self.run_journaled(|m| {
            let parent_group = (parent_ino - 1) / m.sb.inodes_per_group;
            let new_ino = m.alloc_inode(parent_group)?;
            m.init_inode(new_ino, S_IFREG | (mode_perm & 0x0FFF), 0)?;
            Ok(new_ino)
        })
    }

    /// Free an orphan inode (one with `nlink==0`, e.g. an O_TMPFILE
    /// file whose last fd is being closed). Walks the extent tree
    /// and frees each data block, then frees the inode bitmap slot.
    /// Errors if the inode's recorded `nlink` is non-zero (the caller
    /// would otherwise be unlinking a still-named file).
    /// # C: O(N_extents) block frees + 1 inode-free
    pub fn free_orphan_inode(&self, ino: u32) -> Result<(), MountError> {
        self.run_journaled(|m| {
            let (mut bytes, off) = m.read_inode_bytes(ino)?;
            let links = u16::from_le_bytes([bytes[0x1A], bytes[0x1B]]);
            if links != 0 {
                // Caller raced with a linkat; nothing to do.
                return Ok(());
            }
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
            bytes[0x14..0x18].copy_from_slice(&DELETED_DTIME.to_le_bytes()); // i_dtime != 0
            for b in &mut bytes[0x28..0x28 + I_BLOCK_LEN] { *b = 0; }
            let _ = off;
            m.write_inode_bytes(ino, &bytes)?;
            m.free_inode(ino)?;
            Ok(())
        })
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
            let (mut bytes, _off) = m.read_inode_bytes(target_ino)?;
            let is_dir = (u16::from_le_bytes([bytes[0x00], bytes[0x01]]) & S_IFMT) == S_IFDIR;
            let mut links = u16::from_le_bytes([bytes[0x1A], bytes[0x1B]]);
            links = links.saturating_sub(1);
            bytes[0x1A..0x1C].copy_from_slice(&links.to_le_bytes());
            if links == 0 {
                // Freeing a directory inode → it no longer counts toward
                // its group's bg_used_dirs_count.
                if is_dir {
                    let g = (target_ino - 1) / m.sb.inodes_per_group;
                    { let mut s = m.state.lock(); gdt::adjust_used_dirs(&mut s.gdt_buf, g, &m.sb, -1)?; }
                    m.persist_gdt_slot_meta(g)?;
                }
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
                bytes[0x14..0x18].copy_from_slice(&DELETED_DTIME.to_le_bytes()); // i_dtime != 0
                for b in &mut bytes[0x28..0x28 + I_BLOCK_LEN] { *b = 0; }
                m.write_inode_bytes(target_ino, &bytes)?;
                m.free_inode(target_ino)?;
            } else {
                m.write_inode_bytes(target_ino, &bytes)?;
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
        // i_extra_isize: required when inode_size > 128 (the fs advertises
        // EXTRA_ISIZE). 32 is the universal value for 256-byte inodes and
        // is what mke2fs writes; it also makes i_checksum_hi covered.
        if self.sb.inode_size as usize > crate::csum::EXT4_GOOD_OLD_INODE_SIZE {
            bytes[0x80..0x82].copy_from_slice(&32u16.to_le_bytes());
        }
        // EXT4_EXTENTS_FL (0x80000): set only for regular files and
        // directories — they map data via the extent tree rooted in
        // i_block. Fast symlinks + device nodes store data inline and
        // must NOT carry the flag (create_symlink sets it on the slow
        // path; create_mknod never does).
        let ftype = mode & S_IFMT;
        if ftype == S_IFREG || ftype == S_IFDIR {
            bytes[0x20..0x24].copy_from_slice(&0x0008_0000u32.to_le_bytes());
        }
        let hdr = ExtentHeader { magic: EXT4_EXT_MAGIC, entries: 0, max: 4, depth: 0, generation: 0 };
        let mut i_block = [0u8; I_BLOCK_LEN];
        inode::write_extent_header(&mut i_block, &hdr);
        bytes[0x28..0x28 + I_BLOCK_LEN].copy_from_slice(&i_block);
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
            let bs = m.sb.block_size as usize;
            let parent_group = (parent_ino - 1) / m.sb.inodes_per_group;
            let new_ino = m.alloc_inode(parent_group)?;
            m.init_inode(new_ino, S_IFDIR | (mode_perm & 0x0FFF), 2)?;
            // A freshly created directory MUST have a data block holding
            // "." (→ self) and ".." (→ parent); the ".." entry's rec_len
            // spans the rest of the block as the free slot for future
            // entries. Without this the dir has no block 0 and any later
            // dir_link into it fails NotFound (systemd's enable symlink
            // into a runtime-mkdir'd <target>.wants/ dir hit exactly this).
            // The ".." entry's rec_len spans to the end of the *usable*
            // area; under metadata_csum the trailing 12 bytes hold the
            // dir_entry_tail (stamped below), so ".." must stop short of
            // it. Without csum, usable == bs.
            let usable = crate::csum::dir_usable_len(&m.sb, bs);
            let mut blk = alloc::vec![0u8; bs];
            // "." — inode | rec_len=12 | name_len=1 | DT_DIR | "."
            blk[0..4].copy_from_slice(&new_ino.to_le_bytes());
            blk[4..6].copy_from_slice(&12u16.to_le_bytes());
            blk[6] = 1; blk[7] = dir::DT_DIR; blk[8] = b'.';
            // ".." — inode | rec_len=usable-12 | name_len=2 | DT_DIR | ".."
            blk[12..16].copy_from_slice(&parent_ino.to_le_bytes());
            blk[16..18].copy_from_slice(&((usable - 12) as u16).to_le_bytes());
            blk[18] = 2; blk[19] = dir::DT_DIR; blk[20] = b'.'; blk[21] = b'.';
            let (_pf, ngen) = m.inode_flags_gen(new_ino)?;
            crate::csum::stamp_dirent_tail(&m.sb, new_ino, ngen, &mut blk);
            m.append_block(new_ino, &blk)?;
            m.set_inode_size(new_ino, bs as u64)?;
            m.dir_link(parent_ino, name, new_ino, dir::DT_DIR)?;
            // The new directory counts toward its group's bg_used_dirs_count.
            let ng = (new_ino - 1) / m.sb.inodes_per_group;
            {
                let mut s = m.state.lock();
                gdt::adjust_used_dirs(&mut s.gdt_buf, ng, &m.sb, 1)?;
            }
            m.persist_gdt_slot_meta(ng)?;
            // Parent gains a subdirectory ".." backref → bump its
            // i_links_count (inode offset 0x1A, u16), per Linux mkdir.
            let (mut pb, _poff) = m.read_inode_bytes(parent_ino)?;
            let pl = u16::from_le_bytes([pb[0x1A], pb[0x1B]]).saturating_add(1);
            pb[0x1A..0x1C].copy_from_slice(&pl.to_le_bytes());
            m.write_inode_bytes(parent_ino, &pb)?;
            Ok(new_ino)
        })
    }

    /// Create a symlink `name` under `parent_ino` whose target is
    /// `target`. Fast-symlink path (target ≤ 60 B) writes target
    /// directly into `i_block`; slow path allocates one data block.
    /// `target` must be non-empty and ≤ one filesystem block.
    /// # C: O(N parent entries) + 1 inode-alloc + (target>60 ? 1 block-alloc + 2 block I/Os : 1 inode I/O)
    pub fn create_symlink(&self, parent_ino: u32, name: &[u8], target: &[u8])
        -> Result<u32, MountError>
    {
        let bs = self.sb.block_size as usize;
        if target.is_empty() || target.len() > bs {
            return Err(MountError::Inode(inode::InodeError::BadLen));
        }
        self.run_journaled(|m| {
            let parent_group = (parent_ino - 1) / m.sb.inodes_per_group;
            let new_ino = m.alloc_inode(parent_group)?;
            m.init_inode(new_ino, S_IFLNK | 0o777, 1)?;
            if target.len() <= I_BLOCK_LEN {
                let (mut bytes, _off) = m.read_inode_bytes(new_ino)?;
                for b in &mut bytes[0x28..0x28 + I_BLOCK_LEN] { *b = 0; }
                bytes[0x28..0x28 + target.len()].copy_from_slice(target);
                let n = target.len() as u64;
                bytes[0x04..0x08].copy_from_slice(&((n & 0xFFFF_FFFF) as u32).to_le_bytes());
                bytes[0x6C..0x70].copy_from_slice(&((n >> 32) as u32).to_le_bytes());
                m.write_inode_bytes(new_ino, &bytes)?;
            } else {
                // Slow symlink: target lives in one data block mapped by
                // the extent tree → the inode needs EXT4_EXTENTS_FL.
                let (mut b, _o) = m.read_inode_bytes(new_ino)?;
                let fl = u32::from_le_bytes([b[0x20], b[0x21], b[0x22], b[0x23]]) | 0x0008_0000;
                b[0x20..0x24].copy_from_slice(&fl.to_le_bytes());
                m.write_inode_bytes(new_ino, &b)?;
                let mut buf = vec![0u8; bs];
                buf[..target.len()].copy_from_slice(target);
                m.append_block(new_ino, &buf)?;
                m.set_inode_size(new_ino, target.len() as u64)?;
            }
            m.dir_link(parent_ino, name, new_ino, dir::DT_LNK)?;
            Ok(new_ino)
        })
    }

    /// Create a device/FIFO/socket node `name` under `parent_ino`.
    /// `mode` must encode one of `S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK`
    /// in its file-type bits; `rdev` is stored verbatim in
    /// `i_block[0..4]` for CHR/BLK (Linux "small dev" layout) and
    /// ignored for FIFO/SOCK.
    /// # C: O(N parent entries) + 1 inode-alloc + 1 inode I/O
    pub fn create_mknod(&self, parent_ino: u32, name: &[u8], mode: u16, rdev: u32)
        -> Result<u32, MountError>
    {
        let ftype = mode & S_IFMT;
        let dirent_dt = match ftype {
            S_IFCHR  => dir::DT_CHR,
            S_IFBLK  => dir::DT_BLK,
            S_IFIFO  => dir::DT_FIFO,
            S_IFSOCK => dir::DT_SOCK,
            _        => return Err(MountError::Inode(inode::InodeError::BadLen)),
        };
        self.run_journaled(|m| {
            let parent_group = (parent_ino - 1) / m.sb.inodes_per_group;
            let new_ino = m.alloc_inode(parent_group)?;
            let mut bytes = vec![0u8; m.sb.inode_size as usize];
            bytes[0x00..0x02].copy_from_slice(&mode.to_le_bytes());
            bytes[0x1A..0x1C].copy_from_slice(&1u16.to_le_bytes());
            if m.sb.inode_size as usize > crate::csum::EXT4_GOOD_OLD_INODE_SIZE {
                bytes[0x80..0x82].copy_from_slice(&32u16.to_le_bytes());
            }
            if matches!(ftype, S_IFCHR | S_IFBLK) {
                bytes[0x28..0x2C].copy_from_slice(&rdev.to_le_bytes());
            }
            m.write_inode_bytes(new_ino, &bytes)?;
            m.dir_link(parent_ino, name, new_ino, dirent_dt)?;
            Ok(new_ino)
        })
    }
}
