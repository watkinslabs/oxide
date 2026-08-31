//! Crash-durable orphan-list operations and final orphan eviction.

use alloc::vec::Vec;
use crate::gdt;
use crate::inode::{Inode, I_BLOCK_LEN, S_IFDIR, S_IFMT};
use crate::mount::{Mount, MountError};
use crate::superblock::{SB_OFF_LAST_ORPHAN, SUPERBLOCK_LEN, SUPERBLOCK_OFFSET};

const I_OFF_DTIME: usize = 0x14;
const ORPHAN_FILE_MAGIC: u32 = 0x0B10_CA04;

impl Mount {
    /// Read the regular inode that owns Linux orphan-file slots. # C: O(1) I/O
    fn orphan_file_inode(&self) -> Result<Inode, MountError> {
        self.read_inode(self.sb.orphan_file_inum)
    }

    /// Validate an orphan-file block and return its usable slot count. # C: O(1)
    fn orphan_file_capacity(&self, inode: &Inode, phys: u64, data: &[u8])
        -> Result<usize, MountError>
    {
        if data.len() < 8 { return Err(MountError::BadBlock); }
        let tail = data.len() - 8;
        if u32::from_le_bytes([data[tail], data[tail+1], data[tail+2], data[tail+3]])
            != ORPHAN_FILE_MAGIC { return Err(MountError::BadBlock); }
        if self.sb.has_metadata_csum() {
            let want = crc_orphan(&self.sb, inode.ino, inode.generation, phys, &data[..tail]);
            let got = u32::from_le_bytes([data[tail+4], data[tail+5], data[tail+6], data[tail+7]]);
            if got != want { return Err(MountError::BadChecksum); }
        }
        Ok(tail / 4)
    }

    /// Add one inode to an empty orphan-file slot. # C: O(file blocks)
    fn orphan_file_add(&self, ino: u32) -> Result<bool, MountError> {
        let file = self.orphan_file_inode()?;
        let blocks = file.size.div_ceil(self.sb.block_size as u64) as u32;
        for logical in 0..blocks {
            let phys = self.resolve_pblock(&file, logical)?;
            let mut data = self.read_file_block_meta(&file, logical)?;
            let cap = self.orphan_file_capacity(&file, phys, &data)?;
            for slot in 0..cap {
                let off = slot * 4;
                if data[off..off+4] == [0; 4] {
                    data[off..off+4].copy_from_slice(&ino.to_le_bytes());
                    stamp_orphan(&self.sb, &file, phys, &mut data);
                    self.write_file_block_meta(&file, logical, &data)?;
                    self.set_orphan_present(true)?;
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Remove one inode from an orphan-file slot. # C: O(file blocks)
    fn orphan_file_del(&self, ino: u32) -> Result<bool, MountError> {
        let file = self.orphan_file_inode()?;
        let blocks = file.size.div_ceil(self.sb.block_size as u64) as u32;
        for logical in 0..blocks {
            let phys = self.resolve_pblock(&file, logical)?;
            let mut data = self.read_file_block_meta(&file, logical)?;
            let cap = self.orphan_file_capacity(&file, phys, &data)?;
            for slot in 0..cap {
                let off = slot * 4;
                if u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]) == ino {
                    data[off..off+4].fill(0);
                    stamp_orphan(&self.sb, &file, phys, &mut data);
                    self.write_file_block_meta(&file, logical, &data)?;
                    if self.orphan_file_entries()?.is_empty() { self.set_orphan_present(false)?; }
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Set the superblock's `ORPHAN_PRESENT` bit through its journal owner.
    /// # C: O(1024-byte read/write)
    fn set_orphan_present(&self, present: bool) -> Result<(), MountError> {
        let mut bytes = self.read_meta_byte_range(SUPERBLOCK_OFFSET, SUPERBLOCK_LEN)?;
        let off = 0x64;
        let mut bits = u32::from_le_bytes([bytes[off], bytes[off+1], bytes[off+2], bytes[off+3]]);
        if present { bits |= crate::superblock::RO_COMPAT_ORPHAN_PRESENT; }
        else { bits &= !crate::superblock::RO_COMPAT_ORPHAN_PRESENT; }
        bytes[off..off+4].copy_from_slice(&bits.to_le_bytes());
        crate::csum::stamp_superblock_csum(&self.sb, &mut bytes);
        self.metadata_write(SUPERBLOCK_OFFSET, &bytes)
    }

    /// Snapshot every non-zero orphan-file slot before recovery mutates it.
    /// # C: O(orphan-file blocks * slots)
    fn orphan_file_entries(&self) -> Result<Vec<u32>, MountError> {
        let file = self.orphan_file_inode()?;
        let blocks = file.size.div_ceil(self.sb.block_size as u64) as u32;
        let mut out = Vec::new();
        for logical in 0..blocks {
            let phys = self.resolve_pblock(&file, logical)?;
            let data = self.read_file_block_meta(&file, logical)?;
            let cap = self.orphan_file_capacity(&file, phys, &data)?;
            for slot in 0..cap {
                let off = slot * 4;
                let ino = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
                if ino != 0 { out.push(ino); }
            }
        }
        Ok(out)
    }
}

/// Linux ext4 orphan-file checksum: inode seed + physical block + slots. # C: O(block)
fn crc_orphan(sb: &crate::superblock::Superblock, ino: u32, generation: u32,
              phys: u64, slots: &[u8]) -> u32 {
    let mut c = crc::crc32c_update(crate::csum::inode_seed(sb, ino, generation), &phys.to_le_bytes());
    c = crc::crc32c_update(c, slots);
    c
}

/// Stamp the fixed tail after one orphan slot mutation. # C: O(block)
fn stamp_orphan(sb: &crate::superblock::Superblock, inode: &Inode, phys: u64, data: &mut [u8]) {
    let tail = data.len() - 8;
    data[tail..tail+4].copy_from_slice(&ORPHAN_FILE_MAGIC.to_le_bytes());
    if sb.has_metadata_csum() {
        let c = crc_orphan(sb, inode.ino, inode.generation, phys, &data[..tail]);
        data[tail+4..tail+8].copy_from_slice(&c.to_le_bytes());
    }
}

impl Mount {
    /// Add `ino` to the persistent orphan list. # C: O(1) metadata transaction
    pub fn orphan_add(&self, ino: u32) -> Result<(), MountError> {
        self.run_journaled(|m| {
            if m.sb.feature_compat & crate::superblock::COMPAT_ORPHAN_FILE != 0
                && m.orphan_file_add(ino)? { return Ok(()); }
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
            if m.sb.feature_compat & crate::superblock::COMPAT_ORPHAN_FILE != 0
                && m.orphan_file_del(ino)? { return Ok(()); }
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
        if self.sb.feature_compat & crate::superblock::COMPAT_ORPHAN_FILE != 0 {
            let entries = self.orphan_file_entries()?;
            for ino in entries {
                let (bytes, _off) = self.read_inode_bytes(ino)?;
                let links = u16::from_le_bytes([bytes[0x1A], bytes[0x1B]]);
                if links == 0 {
                    let _ = self.free_orphan_inode(ino);
                } else {
                    let size = u32::from_le_bytes([bytes[0x04], bytes[0x05], bytes[0x06], bytes[0x07]]) as u64
                        | (u32::from_le_bytes([bytes[0x6C], bytes[0x6D], bytes[0x6E], bytes[0x6F]]) as u64) << 32;
                    let _ = self.truncate_inode(ino, size);
                    let _ = self.orphan_del(ino);
                }
            }
        }
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
        // Linux ext4 evicts the inode's unused preallocation before reclaiming
        // the orphan.  Keep this at the filesystem deletion boundary so mount
        // recovery and direct Mount callers cannot leave an inode PA masked in
        // the allocator after the inode itself has been freed.
        let (bytes, _) = self.read_inode_bytes(ino)?;
        if u16::from_le_bytes([bytes[0x1A], bytes[0x1B]]) != 0 { return Ok(()); }
        self.release_inode_prealloc(ino)?;
        self.run_journaled(|m| {
            let (bytes, _off) = m.read_inode_bytes(ino)?;
            if u16::from_le_bytes([bytes[0x1A], bytes[0x1B]]) != 0 { return Ok(()); }
            m.orphan_del(ino)?;
            if (u16::from_le_bytes([bytes[0x00], bytes[0x01]]) & S_IFMT) == S_IFDIR {
                let group = (ino - 1) / m.sb.inodes_per_group;
                {
                    // SAFETY: process context, with no spinlock held.
                    let _gdt_guard = unsafe { m.gdt_lock.lock() };
                    let mut gdt_bytes = m.read_gdt_bytes()?;
                    gdt::adjust_used_dirs(&mut gdt_bytes, group, &m.sb, -1)?;
                    m.persist_gdt_slot_bytes_meta(group, &gdt_bytes)?;
                }
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
