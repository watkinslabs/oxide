// ext4 inode bitmap allocator + create/unlink. Structurally
// parallel to `balloc.rs`: scan group inode-bitmaps for first
// clear bit, set it, persist bitmap + GDT free-inodes counter +
// SB free-inodes counter.
//
// Allocates a 1-indexed inode number. On `free`, also walks the
// target inode's extent tree and frees each data block first
// (caller is `unlink` after nlink → 0).

use crate::balloc::find_first_clear;
use crate::gdt;
use crate::inode::{
    self, ExtentHeader, EXT4_EXT_MAGIC, I_BLOCK_LEN, S_IFDIR, S_IFMT, S_IFREG,
};
use crate::mount::{Mount, MountError};
use crate::superblock::{SB_OFF_FREE_INODES, SB_OFF_LAST_ORPHAN, SUPERBLOCK_LEN, SUPERBLOCK_OFFSET};

mod create;

/// On-disk inode byte offset of `NEXT_ORPHAN` — Linux overloads `i_dtime`
/// (@0x14) as the "next orphan inode number" pointer while an inode sits on
/// the superblock orphan list. A small value (< `s_inodes_count`) is a list
/// link; a large value is a genuine deletion timestamp (see `DELETED_DTIME`).
const I_OFF_DTIME: usize = 0x14;

extern crate alloc;
use alloc::vec;

/// `i_dtime` stamped on a freed inode. e2fsck requires a deleted
/// (links_count==0) inode to carry a deletion time that looks like a
/// timestamp — specifically `>= s_inodes_count`, otherwise it is
/// mistaken for an orphan-list "next inode" pointer. Without an
/// in-crate wall clock we use a fixed plausible Unix time (2023-11-14);
/// the exact value is immaterial to validity as long as it is large.
const DELETED_DTIME: u32 = 1_700_000_000;

/// Stamp owner ids into a fresh on-disk inode buffer: low u16 into `i_uid`
/// @0x02 / `i_gid` @0x18, high u16 into osd2 `l_i_uid_high` @0x78 /
/// `l_i_gid_high` @0x7A (matching `Inode::parse`). `bytes` must be a full
/// inode (≥128 B; 0x7A..0x7C is in range for every inode size). # C: O(1)
fn stamp_owner(bytes: &mut [u8], uid: u32, gid: u32) {
    bytes[0x02..0x04].copy_from_slice(&((uid & 0xFFFF) as u16).to_le_bytes());
    bytes[0x18..0x1A].copy_from_slice(&((gid & 0xFFFF) as u16).to_le_bytes());
    bytes[0x78..0x7A].copy_from_slice(&((uid >> 16) as u16).to_le_bytes());
    bytes[0x7A..0x7C].copy_from_slice(&((gid >> 16) as u16).to_le_bytes());
}

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
            m.init_inode(new_ino, S_IFREG | (mode_perm & 0x0FFF), 0, 0, 0)?;
            // Persist on the on-disk orphan list: a crash before a name is
            // linked (or before the last fd closes) leaves the inode + its
            // blocks recoverable by `orphan_cleanup` on the next mount,
            // instead of leaking (Linux `ext4_orphan_add`).
            m.orphan_add(new_ino)?;
            Ok(new_ino)
        })
    }

    /// `ext4_orphan_add`: push `ino` onto the head of the on-disk orphan list.
    /// Sets the inode's `NEXT_ORPHAN` (`i_dtime`) to the previous head, then
    /// points `s_last_orphan` at `ino`. The complementary in-memory set
    /// (`RootfsState.orphans`) drives the fast last-close free path; this is
    /// the crash-durable backing.
    /// # C: O(1) — 1 SB read + 1 inode RW + 1 SB write
    pub fn orphan_add(&self, ino: u32) -> Result<(), MountError> {
        self.run_journaled(|m| {
            let head = m.read_sb_last_orphan()?;
            if head == ino { return Ok(()); } // already the list head
            let (mut bytes, _off) = m.read_inode_bytes(ino)?;
            bytes[I_OFF_DTIME..I_OFF_DTIME + 4].copy_from_slice(&head.to_le_bytes());
            m.write_inode_bytes(ino, &bytes)?;
            m.set_sb_last_orphan(ino)?;
            Ok(())
        })
    }

    /// `ext4_orphan_del`: splice `ino` out of the on-disk orphan list. If it
    /// is the head, `s_last_orphan` is advanced to its `NEXT_ORPHAN`; otherwise
    /// the chain is walked to find the predecessor and relink it past `ino`.
    /// The inode's own `NEXT_ORPHAN` (`i_dtime`) is then cleared to 0 (the
    /// caller — link or free — overwrites it appropriately). Idempotent: a
    /// no-longer-listed inode is left untouched apart from the cleared link.
    /// # C: O(N_orphans) worst-case chain walk
    pub fn orphan_del(&self, ino: u32) -> Result<(), MountError> {
        self.run_journaled(|m| {
            let head = m.read_sb_last_orphan()?;
            let (bytes, _off) = m.read_inode_bytes(ino)?;
            let next = u32::from_le_bytes([
                bytes[I_OFF_DTIME], bytes[I_OFF_DTIME + 1],
                bytes[I_OFF_DTIME + 2], bytes[I_OFF_DTIME + 3],
            ]);
            if head == ino {
                m.set_sb_last_orphan(next)?;
            } else if head != 0 {
                let mut cur = head;
                let mut guard = m.sb.inodes_count;
                while cur != 0 && cur != ino && guard > 0 {
                    guard -= 1;
                    let (mut cbytes, _o) = m.read_inode_bytes(cur)?;
                    let cnext = u32::from_le_bytes([
                        cbytes[I_OFF_DTIME], cbytes[I_OFF_DTIME + 1],
                        cbytes[I_OFF_DTIME + 2], cbytes[I_OFF_DTIME + 3],
                    ]);
                    if cnext == ino {
                        cbytes[I_OFF_DTIME..I_OFF_DTIME + 4].copy_from_slice(&next.to_le_bytes());
                        m.write_inode_bytes(cur, &cbytes)?;
                        break;
                    }
                    cur = cnext;
                }
            }
            // Clear this inode's link field.
            let (mut bytes2, _o2) = m.read_inode_bytes(ino)?;
            bytes2[I_OFF_DTIME..I_OFF_DTIME + 4].copy_from_slice(&0u32.to_le_bytes());
            m.write_inode_bytes(ino, &bytes2)?;
            Ok(())
        })
    }

    /// Read the on-disk `s_last_orphan` head. # C: O(1) SB read
    pub fn read_sb_last_orphan(&self) -> Result<u32, MountError> {
        let buf = self.read_meta_byte_range(SUPERBLOCK_OFFSET, SUPERBLOCK_LEN)?;
        Ok(u32::from_le_bytes([
            buf[SB_OFF_LAST_ORPHAN], buf[SB_OFF_LAST_ORPHAN + 1],
            buf[SB_OFF_LAST_ORPHAN + 2], buf[SB_OFF_LAST_ORPHAN + 3],
        ]))
    }

    /// Persist a new `s_last_orphan` value (re-stamps the SB csum).
    /// # C: O(1) SB RW
    pub(crate) fn set_sb_last_orphan(&self, val: u32) -> Result<(), MountError> {
        let mut sb_buf = self.read_meta_byte_range(SUPERBLOCK_OFFSET, SUPERBLOCK_LEN)?;
        sb_buf[SB_OFF_LAST_ORPHAN..SB_OFF_LAST_ORPHAN + 4].copy_from_slice(&val.to_le_bytes());
        crate::csum::stamp_superblock_csum(&self.sb, &mut sb_buf);
        self.metadata_write(SUPERBLOCK_OFFSET, &sb_buf)
    }

    /// `ext4_orphan_cleanup`: walk the on-disk orphan list at mount time,
    /// reclaiming inodes left over from a crash. An inode with `nlink == 0`
    /// (a never-named O_TMPFILE or a fully-unlinked-but-was-open file) is
    /// freed (its data blocks + inode slot); one with `nlink > 0` (interrupted
    /// truncate) is just removed from the list. Bounded by `s_inodes_count` to
    /// defuse a corrupt cycle. Idempotent; a no-op when `s_last_orphan == 0`.
    /// # C: O(N_orphans × N_extents)
    pub fn orphan_cleanup(&self) -> Result<(), MountError> {
        let mut head = self.read_sb_last_orphan()?;
        let mut guard = self.sb.inodes_count;
        while head != 0 && head <= self.sb.inodes_count && guard > 0 {
            guard -= 1;
            let (bytes, _off) = self.read_inode_bytes(head)?;
            let next = u32::from_le_bytes([
                bytes[I_OFF_DTIME], bytes[I_OFF_DTIME + 1],
                bytes[I_OFF_DTIME + 2], bytes[I_OFF_DTIME + 3],
            ]);
            let links = u16::from_le_bytes([bytes[0x1A], bytes[0x1B]]);
            if links == 0 {
                // Frees blocks + inode AND advances s_last_orphan past `head`
                // (its internal `orphan_del`), so the list shrinks as we go.
                let _ = self.free_orphan_inode(head);
            } else {
                let _ = self.orphan_del(head);
            }
            head = next;
        }
        Ok(())
    }

    /// Free an orphan inode (one with `nlink==0`, e.g. an O_TMPFILE
    /// file whose last fd is being closed). Walks the extent tree
    /// and frees each data block, then frees the inode bitmap slot.
    /// Errors if the inode's recorded `nlink` is non-zero (the caller
    /// would otherwise be unlinking a still-named file).
    /// # C: O(N_extents) block frees + 1 inode-free
    pub fn free_orphan_inode(&self, ino: u32) -> Result<(), MountError> {
        self.run_journaled(|m| {
            let links = {
                let (b, _o) = m.read_inode_bytes(ino)?;
                u16::from_le_bytes([b[0x1A], b[0x1B]])
            };
            if links != 0 {
                // Caller raced with a linkat; nothing to do.
                return Ok(());
            }
            // Detach from the on-disk orphan list before freeing — advances
            // `s_last_orphan` / relinks the chain so it never dangles at a
            // freed slot (Linux `ext4_orphan_del` precedes the truncate+free).
            // This also clears `i_dtime`; the genuine deletion timestamp is
            // re-stamped below.
            m.orphan_del(ino)?;
            // Re-read after orphan_del rewrote the slot's i_dtime field.
            let (mut bytes, off) = m.read_inode_bytes(ino)?;
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

    /// Write a fresh inode struct (mode + nlink + owner + empty extent
    /// tree, size=0, blocks=0). `uid`/`gid` are the fs-domain owner ids
    /// (Linux `ext4_new_inode` stamps `current_fsuid`/`current_fsgid` mapped
    /// through the mount idmap) — split into the low u16 (0x02/0x18) and the
    /// osd2 high u16 (0x78/0x7A). Other timestamps stay 0.
    /// # C: O(1) I/O
    pub fn init_inode(&self, ino: u32, mode: u16, nlink: u16, uid: u32, gid: u32)
        -> Result<(), MountError>
    {
        let mut bytes = vec![0u8; self.sb.inode_size as usize];
        bytes[0x00..0x02].copy_from_slice(&mode.to_le_bytes());
        bytes[0x1A..0x1C].copy_from_slice(&nlink.to_le_bytes());
        stamp_owner(&mut bytes, uid, gid);
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

}
