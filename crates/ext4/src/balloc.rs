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

use crate::gdt;
use crate::mount::{Mount, MountError, write_byte_range, read_byte_range_pub};
use crate::superblock::{Superblock, SB_OFF_FREE_BLOCKS_LO, SB_OFF_FREE_BLOCKS_HI};

extern crate alloc;

impl Mount {
    /// Allocate one previously-free filesystem block. Searches
    /// from group `hint` forward, wrapping. Returns the physical
    /// block number; mutates bitmap + GDT counter + SB counter on
    /// disk + in cache. Errors `NoSpace` when every group is full.
    /// # C: O(N_groups * block_size) worst-case
    pub fn alloc_block(&self, hint: u32) -> Result<u64, MountError> {
        let groups = self.sb.group_count();
        if groups == 0 { return Err(MountError::NoSpace); }
        for off in 0..groups {
            let g = (hint + off) % groups;
            if let Some(blk) = self.try_alloc_in_group(g)? {
                return Ok(blk);
            }
        }
        Err(MountError::NoSpace)
    }

    /// Free a block previously returned by `alloc_block`. Clears
    /// the bitmap bit + bumps both counters. No-op + Err if the
    /// bit was already clear (caller bug; surface it).
    /// # C: O(block_size) within one group
    pub fn free_block(&self, phys_blk: u64) -> Result<(), MountError> {
        let (group, bit) = self.locate_block(phys_blk)?;
        let mut state = self.state.lock();
        let mut gd = gdt::parse_descriptor(&state.gdt_buf, group, &self.sb)?;
        let bbm_byte_off = gd.block_bitmap * (self.sb.block_size as u64);
        let mut bitmap = read_byte_range_pub(&*self.dev, bbm_byte_off, self.sb.block_size as usize)?;
        let bidx = bit as usize;
        let mask = 1u8 << (bidx & 7);
        if (bitmap[bidx >> 3] & mask) == 0 {
            return Err(MountError::DoubleFree);
        }
        bitmap[bidx >> 3] &= !mask;
        write_byte_range(&*self.dev, bbm_byte_off, &bitmap)?;
        gd.free_blocks_count = gd.free_blocks_count.saturating_add(1);
        gdt::write_descriptor_counters(&mut state.gdt_buf, group, &self.sb, &gd)?;
        self.persist_gdt_slot(&state, group)?;
        state.sb_free_blocks = state.sb_free_blocks.saturating_add(1);
        self.persist_sb_free_blocks(&state)?;
        Ok(())
    }

    /// Try to find a free bit in `group`. Returns Ok(Some(phys))
    /// on success, Ok(None) if the group is full per its descriptor.
    /// # C: O(block_size)
    fn try_alloc_in_group(&self, group: u32) -> Result<Option<u64>, MountError> {
        let mut state = self.state.lock();
        let mut gd = gdt::parse_descriptor(&state.gdt_buf, group, &self.sb)?;
        if gd.free_blocks_count == 0 { return Ok(None); }
        let bbm_byte_off = gd.block_bitmap * (self.sb.block_size as u64);
        let mut bitmap = read_byte_range_pub(&*self.dev, bbm_byte_off, self.sb.block_size as usize)?;
        let blocks_in_group = self.blocks_in_group(group);
        let bit = match find_first_clear(&bitmap, blocks_in_group) {
            Some(b) => b,
            None    => return Ok(None),
        };
        bitmap[bit >> 3] |= 1u8 << (bit & 7);
        write_byte_range(&*self.dev, bbm_byte_off, &bitmap)?;
        gd.free_blocks_count = gd.free_blocks_count.saturating_sub(1);
        gdt::write_descriptor_counters(&mut state.gdt_buf, group, &self.sb, &gd)?;
        self.persist_gdt_slot(&state, group)?;
        state.sb_free_blocks = state.sb_free_blocks.saturating_sub(1);
        self.persist_sb_free_blocks(&state)?;
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
        let total = self.sb.blocks_count_lo;
        let bpg   = self.sb.blocks_per_group;
        let first = self.sb.first_data_block + group * bpg;
        let end   = core::cmp::min(first + bpg, total);
        end - first
    }

    /// Persist one GDT slot to disk (writes a whole-block window
    /// containing the slot — devices are block-granular).
    pub(crate) fn persist_gdt_slot(&self, state: &MountStateGuard<'_>, group: u32)
        -> Result<(), MountError>
    {
        let dsize = gdt::desc_size_for(&self.sb) as usize;
        let slot_byte = (group as usize) * dsize;
        let bs = self.sb.block_size as usize;
        let blk_idx = slot_byte / bs;
        let byte_off = self.gdt_byte_offset() + (blk_idx * bs) as u64;
        let lo = blk_idx * bs;
        let hi = core::cmp::min(lo + bs, state.gdt_buf.len());
        write_byte_range(&*self.dev, byte_off, &state.gdt_buf[lo..hi])
    }

    pub(crate) fn persist_sb_free_blocks(&self, state: &MountStateGuard<'_>)
        -> Result<(), MountError>
    {
        let lo = (state.sb_free_blocks & 0xFFFF_FFFF) as u32;
        let hi = (state.sb_free_blocks >> 32) as u32;
        let mut sb_buf = read_byte_range_pub(
            &*self.dev,
            crate::superblock::SUPERBLOCK_OFFSET,
            crate::superblock::SUPERBLOCK_LEN,
        )?;
        sb_buf[SB_OFF_FREE_BLOCKS_LO..SB_OFF_FREE_BLOCKS_LO+4].copy_from_slice(&lo.to_le_bytes());
        sb_buf[SB_OFF_FREE_BLOCKS_HI..SB_OFF_FREE_BLOCKS_HI+4].copy_from_slice(&hi.to_le_bytes());
        write_byte_range(&*self.dev, crate::superblock::SUPERBLOCK_OFFSET, &sb_buf)
    }
}

/// Group N's first physical block on the FS.
/// # C: O(1)
pub fn group_first_block(sb: &Superblock, group: u32) -> u64 {
    sb.first_data_block as u64 + (group as u64) * (sb.blocks_per_group as u64)
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
}
