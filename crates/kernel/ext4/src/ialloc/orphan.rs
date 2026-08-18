//! Crash-durable orphan-list operations and final orphan eviction.

use crate::gdt;
use crate::inode::{I_BLOCK_LEN, S_IFDIR, S_IFMT};
use crate::mount::{Mount, MountError};
use crate::superblock::{SB_OFF_LAST_ORPHAN, SUPERBLOCK_LEN, SUPERBLOCK_OFFSET};

const I_OFF_DTIME: usize = 0x14;

impl Mount {
    /// Add `ino` to the persistent orphan list. # C: O(1) metadata transaction
    pub fn orphan_add(&self, ino: u32) -> Result<(), MountError> {
        self.run_journaled(|m| {
            let head = m.read_sb_last_orphan()?;
            if head == ino { return Ok(()); }
            let (mut bytes, _off) = m.read_inode_bytes(ino)?;
            bytes[I_OFF_DTIME..I_OFF_DTIME + 4].copy_from_slice(&head.to_le_bytes());
            m.write_inode_bytes(ino, &bytes)?;
            m.set_sb_last_orphan(ino)
        })
    }

    /// Remove `ino` from the persistent orphan list. # C: O(N_orphans)
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
                    let (mut bytes, _off) = m.read_inode_bytes(cur)?;
                    let following = u32::from_le_bytes([
                        bytes[I_OFF_DTIME], bytes[I_OFF_DTIME + 1],
                        bytes[I_OFF_DTIME + 2], bytes[I_OFF_DTIME + 3],
                    ]);
                    if following == ino {
                        bytes[I_OFF_DTIME..I_OFF_DTIME + 4].copy_from_slice(&next.to_le_bytes());
                        m.write_inode_bytes(cur, &bytes)?;
                        break;
                    }
                    cur = following;
                }
            }
            let (mut bytes, _off) = m.read_inode_bytes(ino)?;
            bytes[I_OFF_DTIME..I_OFF_DTIME + 4].copy_from_slice(&0u32.to_le_bytes());
            m.write_inode_bytes(ino, &bytes)
        })
    }

    /// Read the persistent orphan-list head. # C: O(1) metadata read
    pub fn read_sb_last_orphan(&self) -> Result<u32, MountError> {
        let buf = self.read_meta_byte_range(SUPERBLOCK_OFFSET, SUPERBLOCK_LEN)?;
        Ok(u32::from_le_bytes([
            buf[SB_OFF_LAST_ORPHAN], buf[SB_OFF_LAST_ORPHAN + 1],
            buf[SB_OFF_LAST_ORPHAN + 2], buf[SB_OFF_LAST_ORPHAN + 3],
        ]))
    }

    /// Store the persistent orphan-list head. # C: O(1) metadata write
    pub(crate) fn set_sb_last_orphan(&self, val: u32) -> Result<(), MountError> {
        let mut bytes = self.read_meta_byte_range(SUPERBLOCK_OFFSET, SUPERBLOCK_LEN)?;
        bytes[SB_OFF_LAST_ORPHAN..SB_OFF_LAST_ORPHAN + 4].copy_from_slice(&val.to_le_bytes());
        crate::csum::stamp_superblock_csum(&self.sb, &mut bytes);
        self.metadata_write(SUPERBLOCK_OFFSET, &bytes)
    }

    /// Reclaim every inode left on the orphan list by an interrupted update.
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
                let _ = self.free_orphan_inode(head);
            } else {
                let size = u32::from_le_bytes([bytes[0x04], bytes[0x05], bytes[0x06], bytes[0x07]]) as u64
                    | (u32::from_le_bytes([bytes[0x6C], bytes[0x6D], bytes[0x6E], bytes[0x6F]]) as u64) << 32;
                let _ = self.truncate_inode(head, size);
                let _ = self.orphan_del(head);
            }
            head = next;
        }
        Ok(())
    }

    /// Free an unlinked orphan after it leaves the persistent list.
    /// # C: O(N_extents) block frees + metadata transaction
    pub fn free_orphan_inode(&self, ino: u32) -> Result<(), MountError> {
        self.run_journaled(|m| {
            let (bytes, _off) = m.read_inode_bytes(ino)?;
            if u16::from_le_bytes([bytes[0x1A], bytes[0x1B]]) != 0 { return Ok(()); }
            m.orphan_del(ino)?;
            if (u16::from_le_bytes([bytes[0x00], bytes[0x01]]) & S_IFMT) == S_IFDIR {
                let group = (ino - 1) / m.sb.inodes_per_group;
                { let mut state = m.state.lock(); gdt::adjust_used_dirs(&mut state.gdt_buf, group, &m.sb, -1)?; }
                m.persist_gdt_slot_meta(group)?;
            }
            m.truncate_inode_for_deletion(ino)?;
            m.free_external_xattr_for_deletion(ino)?;
            let (mut bytes, _off) = m.read_inode_bytes(ino)?;
            bytes[0x04..0x08].copy_from_slice(&0u32.to_le_bytes());
            bytes[0x6C..0x70].copy_from_slice(&0u32.to_le_bytes());
            bytes[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes());
            bytes[I_OFF_DTIME..I_OFF_DTIME + 4].copy_from_slice(&super::DELETED_DTIME.to_le_bytes());
            for byte in &mut bytes[0x28..0x28 + I_BLOCK_LEN] { *byte = 0; }
            m.write_inode_bytes(ino, &bytes)?;
            m.free_inode(ino)
        })
    }
}
