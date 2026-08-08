// ext4 block bitmap allocator. Walks group bitmaps for the first
// clear bit, sets it, persists bitmap + group-descriptor counter
// + superblock counter back to the underlying `BlockDevice`.
//
// Bitmap layout per Linux: one bit per fs block in the group;
// LSB-first within each byte; bit 0 of byte 0 is the *first*
// physical block belonging to the group. Group N's first physical
// block = `sb.first_data_block + N * sb.blocks_per_group`.
//
// Caller acquires `Mount::state` lock; this module only performs
// disk RMW and counter updates.
//
// Module manifest:
// - scan: where a group walk starts, and whether it walks in free-space order.
// - reserve: who may consume the superblock's reserved blocks (`resuid=`,
//   `resgid=`, and the allocations that carry a claim of their own).
// - free: releasing a block, and `-o discard` handing it back to the device.

use crate::gdt;

pub mod scan;
pub mod reserve;
mod free;
use reserve::ReserveFlags;
use crate::mount::{Mount, MountError};
use crate::superblock::{Superblock, SB_OFF_FREE_BLOCKS_LO, SB_OFF_FREE_BLOCKS_HI};
#[cfg(not(target_os = "oxide-kernel"))]
use core::sync::atomic::Ordering;

extern crate alloc;
use alloc::vec::Vec;

impl Mount {
    /// Allocate one previously-free filesystem block for file data. Wraps in a
    /// journal scope so bitmap + GDT + SB counter writes commit
    /// atomically.
    /// # C: O(N_groups * block_size) worst-case
    pub fn alloc_block(&self, hint: u32) -> Result<u64, MountError> {
        self.alloc_block_flags(hint, ReserveFlags::DATA)
    }

    /// Allocate one block for metadata whose caller is already past the point
    /// of no return. An extent tree part-way through a rewrite cannot answer
    /// ENOSPC and leave a half-built tree behind, so its nodes come out of the
    /// reserve when nothing else is left.
    /// # C: same as [`Mount::alloc_block`]
    pub fn alloc_block_nofail(&self, hint: u32) -> Result<u64, MountError> {
        self.alloc_block_flags(hint, ReserveFlags::METADATA_NOFAIL)
    }

    /// The claim a data allocation for inode `ino` has on the reserve. A quota
    /// file's own blocks come out of it: quota accounting is what records that
    /// the disk filled up, so it cannot be the first thing a full filesystem
    /// stops being able to write.
    /// # C: O(1)
    pub(crate) fn data_reserve_flags(&self, ino: u32) -> ReserveFlags {
        if self.sb.is_quota_inode(ino) { ReserveFlags::QUOTA_FILE } else { ReserveFlags::DATA }
    }

    /// Allocate one previously-free filesystem block, stating what claim the
    /// allocation has on the superblock's reserved blocks.
    /// # C: O(N_groups * block_size) worst-case
    pub fn alloc_block_flags(&self, hint: u32, flags: ReserveFlags) -> Result<u64, MountError> {
        #[cfg(not(target_os = "oxide-kernel"))]
        if self.faults.next_alloc_block.swap(false, Ordering::AcqRel) { return Err(MountError::BlockIo); }
        #[cfg(not(target_os = "oxide-kernel"))]
        {
            let left = self.faults.alloc_block_after.load(Ordering::Acquire);
            if left != 0 && self.faults.alloc_block_after.fetch_sub(1, Ordering::AcqRel) == 1 {
                return Err(MountError::BlockIo);
            }
        }
        let optimize = self.optimize_scan();
        // Who is asking, and what claim their allocation has on the reserve.
        // Read before the journal scope: the credentials belong to the caller,
        // not to whichever context happens to drain the transaction.
        let may_dip = reserve::may_dip_into_reserve(&self.behaviour(), &self.alloc_cred(), flags);
        self.run_journaled(|m| {
            let groups = m.sb.group_count();
            if groups == 0 { return Err(MountError::NoSpace); }
            // The reserve gate, before any group is scanned: a caller with no
            // claim on the reserved blocks is out of space while they are all
            // that is left, exactly as if the bitmaps were full.
            let free = m.state.lock().sb_free_blocks;
            const ONE_BLOCK: u64 = 1;
            if !reserve::has_free_blocks(free, ONE_BLOCK, m.sb.r_blocks_count, may_dip) {
                return Err(MountError::NoSpace);
            }
            // `mb_optimize_scan=`: where the walk STARTS. It still visits every
            // group, so the answer never changes — only how many full groups
            // are read before it is reached.
            let freest = if optimize { m.freest_group(groups) } else { None };
            let start = scan::scan_start(hint, groups, optimize, freest);
            for off in 0..groups {
                let g = (start + off) % groups;
                if let Some(blk) = m.try_alloc_in_group(g)? {
                    return Ok(blk);
                }
            }
            Err(MountError::NoSpace)
        })
    }

    /// Whether this mount scans block groups in free-space order. The mount
    /// option decides it; a mount that named none gets the answer its own size
    /// implies. # C: O(1)
    fn optimize_scan(&self) -> bool {
        self.behaviour().mb_optimize_scan
            .unwrap_or_else(|| scan::optimize_scan_default(self.sb.group_count()))
    }

    /// The group with the most free blocks, from the cached group descriptors.
    ///
    /// Read straight off the counters the allocator already maintains rather
    /// than from a second index of its own: an index would be a parallel copy
    /// of this same truth, free to disagree with it after any allocation.
    /// # C: O(N_groups)
    fn freest_group(&self, groups: u32) -> Option<(u32, u64)> {
        let s = self.state.lock();
        let mut best: Option<(u32, u64)> = None;
        for g in 0..groups {
            let Ok(d) = gdt::parse_descriptor(&s.gdt_buf, g, &self.sb) else { continue };
            let free = d.free_blocks_count as u64;
            if best.is_none_or(|(_, b)| free > b) { best = Some((g, free)); }
        }
        best
    }

    /// Try to find a free bit in `group`. Returns Ok(Some(phys))
    /// on success, Ok(None) if the group is full per its descriptor.
    /// # C: O(block_size)
    fn try_alloc_in_group(&self, group: u32) -> Result<Option<u64>, MountError> {
        // NB: serialized by the caller holding `op_lock` across the whole create
        // operation (see create.rs) — concurrent creates can't pick same block.
        let gd_orig = {
            let s = self.state.lock();
            gdt::parse_descriptor(&s.gdt_buf, group, &self.sb)?
        };
        if gd_orig.free_blocks_count == 0 { return Ok(None); }
        let bbm_byte_off = gd_orig.block_bitmap * (self.sb.block_size as u64);
        let uninit = { let s = self.state.lock(); gdt::block_uninit(&s.gdt_buf, group, &self.sb) };
        let mut bitmap = if uninit {
            let s = self.state.lock();
            init_block_bitmap_for_group(&self.sb, &s.gdt_buf, group)?
        } else {
            let bitmap = self.read_meta_byte_range(bbm_byte_off, self.sb.block_size as usize)?;
            if !crate::csum::verify_block_bitmap_csum_at(&self.sb, &self.state.lock().gdt_buf, group, &bitmap) {
                return Err(MountError::BadChecksum);
            }
            bitmap
        };
        let blocks_in_group = self.blocks_in_group(group);
        let bit = match find_first_clear(&bitmap, blocks_in_group) {
            Some(b) => b,
            None    => return Ok(None),
        };
        bitmap[bit >> 3] |= 1u8 << (bit & 7);
        let mut gd = gd_orig;
        gd.free_blocks_count = gd.free_blocks_count.saturating_sub(1);
        {
            let mut s = self.state.lock();
            gdt::write_descriptor_counters(&mut s.gdt_buf, group, &self.sb, &gd)?;
            crate::csum::set_block_bitmap_csum(&self.sb, &mut s.gdt_buf, group, &bitmap);
            gdt::on_block_allocated(&mut s.gdt_buf, group, &self.sb);
            crate::csum::stamp_group_desc_csum(&self.sb, &mut s.gdt_buf, group);
            s.sb_free_blocks = s.sb_free_blocks.saturating_sub(1);
        }
        self.metadata_write(bbm_byte_off, &bitmap)?;
        self.persist_gdt_slot_meta(group)?;
        self.persist_sb_free_blocks_meta()?;
        // Force commit so the next alloc_block within the same
        // outer scope reads the updated bitmap from disk.
        self.flush_pending_tx()?;
        let phys = group_first_block(&self.sb, group) + bit as u64;
        Ok(Some(phys))
    }

    fn locate_block(&self, phys: u64) -> Result<(u32, u32), MountError> {
        let bpg = self.sb.blocks_per_group as u64;
        if bpg == 0 || phys < self.sb.first_data_block as u64 {
            return Err(MountError::BadBlock);
        }
        let rel = phys - self.sb.first_data_block as u64;
        let group = (rel / bpg) as u32;
        let bit   = (rel % bpg) as u32;
        if group >= self.sb.group_count() { return Err(MountError::BadBlock); }
        if bit >= self.blocks_in_group(group) { return Err(MountError::BadBlock); }
        Ok((group, bit))
    }

    fn blocks_in_group(&self, group: u32) -> u32 {
        let total = self.sb.blocks_count();
        let bpg   = self.sb.blocks_per_group as u64;
        let first = self.sb.first_data_block as u64 + group as u64 * bpg;
        let end   = core::cmp::min(first + bpg, total);
        end.saturating_sub(first) as u32
    }

    /// Persist one GDT slot to disk through `metadata_write` (so
    /// it's journaled when a scope is open). Briefly locks state
    /// to copy the slot's containing fs-block bytes; releases the
    /// lock before the write.
    /// # C: O(block_size)
    pub(crate) fn persist_gdt_slot_meta(&self, group: u32) -> Result<(), MountError> {
        let dsize = gdt::desc_size_for(&self.sb) as usize;
        let slot_byte = (group as usize) * dsize;
        let bs = self.sb.block_size as usize;
        let blk_idx = slot_byte / bs;
        let byte_off = self.gdt_byte_offset() + (blk_idx * bs) as u64;
        let payload = {
            let s = self.state.lock();
            let lo = blk_idx * bs;
            let hi = core::cmp::min(lo + bs, s.gdt_buf.len());
            s.gdt_buf[lo..hi].to_vec()
        };
        self.metadata_write(byte_off, &payload)
    }

    /// Persist `sb_free_blocks` to the on-disk superblock through
    /// `metadata_write`.
    /// # C: O(SB read + 1 block write)
    pub(crate) fn persist_sb_free_blocks_meta(&self) -> Result<(), MountError> {
        let (lo_v, hi_v) = {
            let s = self.state.lock();
            ((s.sb_free_blocks & 0xFFFF_FFFF) as u32, (s.sb_free_blocks >> 32) as u32)
        };
        let mut sb_buf = self.read_meta_byte_range(
            crate::superblock::SUPERBLOCK_OFFSET,
            crate::superblock::SUPERBLOCK_LEN,
        )?;
        sb_buf[SB_OFF_FREE_BLOCKS_LO..SB_OFF_FREE_BLOCKS_LO+4].copy_from_slice(&lo_v.to_le_bytes());
        sb_buf[SB_OFF_FREE_BLOCKS_HI..SB_OFF_FREE_BLOCKS_HI+4].copy_from_slice(&hi_v.to_le_bytes());
        crate::csum::stamp_superblock_csum(&self.sb, &mut sb_buf);
        self.metadata_write(crate::superblock::SUPERBLOCK_OFFSET, &sb_buf)
    }
}

/// Group N's first physical block on the FS.
/// # C: O(1)
pub fn group_first_block(sb: &Superblock, group: u32) -> u64 {
    sb.first_data_block as u64 + (group as u64) * (sb.blocks_per_group as u64)
}

fn init_block_bitmap_for_group(sb: &Superblock, gdt_buf: &[u8], group: u32) -> Result<Vec<u8>, MountError> {
    let bs = sb.block_size as usize;
    let mut bitmap = alloc::vec![0u8; bs];
    let blocks = blocks_in_group_sb(sb, group);
    mark_tail_used(&mut bitmap, blocks);
    mark_group_backups(sb, group, &mut bitmap);
    mark_descriptor_owned_metadata(sb, gdt_buf, group, &mut bitmap)?;
    Ok(bitmap)
}

fn blocks_in_group_sb(sb: &Superblock, group: u32) -> u32 {
    let bpg = sb.blocks_per_group as u64;
    let first = group_first_block(sb, group);
    let end = core::cmp::min(first + bpg, sb.blocks_count());
    end.saturating_sub(first) as u32
}

fn mark_tail_used(bitmap: &mut [u8], blocks: u32) {
    let max = bitmap.len() * 8;
    for bit in blocks as usize..max { set_bit(bitmap, bit); }
}

fn mark_group_backups(sb: &Superblock, group: u32, bitmap: &mut [u8]) {
    if !group_has_super(sb, group) { return; }
    let gdt_blocks = div_ceil_u64(sb.group_count() as u64 * gdt::desc_size_for(sb) as u64, sb.block_size as u64);
    let meta = 1 + gdt_blocks + sb.reserved_gdt_blocks as u64;
    let blocks = blocks_in_group_sb(sb, group) as u64;
    for bit in 0..core::cmp::min(meta, blocks) { set_bit(bitmap, bit as usize); }
}

fn mark_descriptor_owned_metadata(sb: &Superblock, gdt_buf: &[u8], group: u32, bitmap: &mut [u8]) -> Result<(), MountError> {
    let first = group_first_block(sb, group);
    let end = first + blocks_in_group_sb(sb, group) as u64;
    let table_blocks = div_ceil_u64(sb.inodes_per_group as u64 * sb.inode_size as u64, sb.block_size as u64);
    for n in 0..sb.group_count() {
        let gd = gdt::parse_descriptor(gdt_buf, n, sb)?;
        mark_phys_if_in_group(bitmap, first, end, gd.block_bitmap);
        mark_phys_if_in_group(bitmap, first, end, gd.inode_bitmap);
        for off in 0..table_blocks { mark_phys_if_in_group(bitmap, first, end, gd.inode_table + off); }
    }
    Ok(())
}

fn mark_phys_if_in_group(bitmap: &mut [u8], first: u64, end: u64, phys: u64) {
    if phys >= first && phys < end { set_bit(bitmap, (phys - first) as usize); }
}

fn group_has_super(sb: &Superblock, group: u32) -> bool {
    if !sb.has_sparse_super() { return true; }
    group == 0 || group == 1 || is_power_of(group, 3) || is_power_of(group, 5) || is_power_of(group, 7)
}

fn is_power_of(mut n: u32, base: u32) -> bool {
    if n < 1 { return false; }
    while n % base == 0 { n /= base; }
    n == 1
}

fn div_ceil_u64(n: u64, d: u64) -> u64 {
    if d == 0 { 0 } else { (n + d - 1) / d }
}

fn set_bit(bitmap: &mut [u8], bit: usize) {
    if bit / 8 < bitmap.len() { bitmap[bit >> 3] |= 1u8 << (bit & 7); }
}

/// Scan `bitmap` for the first 0 bit in `[0, max_bits)`. Returns
/// the bit index, or None when every covered bit is already set.
/// # C: O(max_bits / 8)
pub fn find_first_clear(bitmap: &[u8], max_bits: u32) -> Option<usize> {
    let max = max_bits as usize;
    let full_bytes = max / 8;
    for (i, &b) in bitmap.iter().take(full_bytes).enumerate() {
        if b != 0xFF {
            for bit in 0..8 {
                if (b & (1 << bit)) == 0 { return Some(i * 8 + bit); }
            }
        }
    }
    let tail_bits = max % 8;
    if tail_bits > 0 && full_bytes < bitmap.len() {
        let b = bitmap[full_bytes];
        for bit in 0..tail_bits {
            if (b & (1 << bit)) == 0 { return Some(full_bytes * 8 + bit); }
        }
    }
    None
}

// Re-export the guard type for the helper signatures. Defined in
// `mount` to keep the lock layout co-located with the struct.
pub use crate::mount::MountStateGuard;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sb(blocks: u32, bpg: u32, ipg: u32, reserved_gdt: u16) -> Superblock {
        let mut b = [0u8; crate::superblock::SUPERBLOCK_LEN];
        b[0x00..0x04].copy_from_slice(&(ipg * 2).to_le_bytes());
        b[0x04..0x08].copy_from_slice(&blocks.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        b[0x18..0x1C].copy_from_slice(&0u32.to_le_bytes());
        b[0x20..0x24].copy_from_slice(&bpg.to_le_bytes());
        b[0x28..0x2C].copy_from_slice(&ipg.to_le_bytes());
        b[0x38..0x3A].copy_from_slice(&crate::superblock::EXT4_SUPER_MAGIC.to_le_bytes());
        b[0x58..0x5A].copy_from_slice(&256u16.to_le_bytes());
        b[0x60..0x64].copy_from_slice(&crate::superblock::INCOMPAT_EXTENTS.to_le_bytes());
        b[0x64..0x68].copy_from_slice(&crate::superblock::RO_COMPAT_SPARSE_SUPER.to_le_bytes());
        b[crate::superblock::SB_OFF_RESERVED_GDT_BLOCKS..crate::superblock::SB_OFF_RESERVED_GDT_BLOCKS + 2]
            .copy_from_slice(&reserved_gdt.to_le_bytes());
        Superblock::parse(&b).unwrap()
    }

    fn put_desc(gdt_buf: &mut [u8], n: usize, bbm: u32, ibm: u32, it: u32, flags: u16) {
        let off = n * 32;
        gdt_buf[off..off + 4].copy_from_slice(&bbm.to_le_bytes());
        gdt_buf[off + 4..off + 8].copy_from_slice(&ibm.to_le_bytes());
        gdt_buf[off + 8..off + 12].copy_from_slice(&it.to_le_bytes());
        gdt_buf[off + gdt::GD_OFF_FLAGS..off + gdt::GD_OFF_FLAGS + 2].copy_from_slice(&flags.to_le_bytes());
    }

    fn bit_set(bitmap: &[u8], bit: usize) -> bool {
        bitmap[bit >> 3] & (1u8 << (bit & 7)) != 0
    }

    #[test]
    fn first_clear_in_full_byte_returns_none() {
        assert_eq!(find_first_clear(&[0xFF; 4], 32), None);
    }

    #[test]
    fn first_clear_picks_lsb_first() {
        // byte 0 = 0b00000110 (bits 1,2 set) → first clear is bit 0
        assert_eq!(find_first_clear(&[0b0000_0110, 0xFF], 16), Some(0));
        // byte 0 = 0xFF, byte 1 = 0xFE → first clear is bit 8
        assert_eq!(find_first_clear(&[0xFF, 0xFE], 16), Some(8));
    }

    #[test]
    fn first_clear_respects_max_bits_tail() {
        // 12 bits total. byte 0 full, byte 1 = 0b0000_0001 (bit 0 set).
        // Tail covers bits 8..12 (lower nibble of byte 1). bit 8 is set;
        // bit 9 is clear → 9.
        assert_eq!(find_first_clear(&[0xFF, 0b0000_0001], 12), Some(9));
        // All 12 bits set in lower nibble → None even though high
        // nibble has clears (those are out of range).
        assert_eq!(find_first_clear(&[0xFF, 0b0000_1111], 12), None);
    }

    #[test]
    fn first_clear_zero_max() {
        assert_eq!(find_first_clear(&[0x00; 4], 0), None);
    }

    #[test]
    fn block_uninit_bitmap_marks_backup_and_flex_metadata() {
        let sb = test_sb(16_384, 8192, 64, 2);
        let first1 = group_first_block(&sb, 1) as u32;
        let mut gdt_buf = alloc::vec![0u8; 64];
        put_desc(&mut gdt_buf, 0, 10, 11, 12, 0);
        put_desc(&mut gdt_buf, 1, first1 + 100, first1 + 101, first1 + 102, gdt::EXT4_BG_BLOCK_UNINIT);
        let bm = init_block_bitmap_for_group(&sb, &gdt_buf, 1).unwrap();
        for bit in 0..4 {
            assert!(bit_set(&bm, bit), "backup super/GDT/reserved bit {bit} must be used");
        }
        assert!(bit_set(&bm, 100), "block bitmap must be used");
        assert!(bit_set(&bm, 101), "inode bitmap must be used");
        for bit in 102..118 {
            assert!(bit_set(&bm, bit), "inode table bit {bit} must be used");
        }
        assert_eq!(find_first_clear(&bm, blocks_in_group_sb(&sb, 1)), Some(4));
    }

    #[test]
    fn block_uninit_bitmap_marks_last_group_tail_used() {
        let sb = test_sb(8192 + 102, 8192, 64, 0);
        let first1 = group_first_block(&sb, 1) as u32;
        let mut gdt_buf = alloc::vec![0u8; 64];
        put_desc(&mut gdt_buf, 0, 10, 11, 12, 0);
        put_desc(&mut gdt_buf, 1, first1 + 10, first1 + 11, first1 + 12, gdt::EXT4_BG_BLOCK_UNINIT);
        let bm = init_block_bitmap_for_group(&sb, &gdt_buf, 1).unwrap();
        assert!(!bit_set(&bm, 100), "last real block remains allocatable unless metadata owns it");
        assert!(bit_set(&bm, 101), "tail bit past group end must be used");
        assert_eq!(find_first_clear(&bm, sb.blocks_per_group), Some(2));
    }
}
