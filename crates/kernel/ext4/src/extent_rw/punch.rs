// fallocate PUNCH_HOLE — deallocate a byte range, turning it into holes.
// Whole blocks fully inside the range are freed and removed from the extent
// tree; partial-block edges are zeroed in place (Linux `ext4_punch_hole`).
// The extent tree is rebuilt from the surviving runs (general across depth 0/1).

use crate::inode::{self, Extent, I_BLOCK_LEN};
use crate::mount::{Mount, MountError};
use alloc::vec::Vec;

use super::records::extent_run as mk_extent;

impl Mount {
    /// fallocate `FALLOC_FL_PUNCH_HOLE` (always with KEEP_SIZE): deallocate
    /// `[offset, offset+len)`, leaving holes that read as zeros. File size is
    /// unchanged. # C: O(N_extents) + O(freed blocks) I/O
    pub fn punch_hole_inode(&self, ino: u32, offset: u64, len: u64) -> Result<(), MountError> {
        self.run_journaled(|m| m.punch_hole_inner(ino, offset, len))
    }

    fn punch_hole_inner(&self, ino: u32, offset: u64, len: u64) -> Result<(), MountError> {
        if len == 0 { return Ok(()); }
        let bs = self.sb.block_size as u64;
        let size = self.read_inode(ino)?.size;
        let end = core::cmp::min(
            offset.checked_add(len).ok_or(MountError::Inode(inode::InodeError::BadLen))?,
            size,
        );
        if offset >= end { return Ok(()); }

        // Zero the partial-block edges in place (keeps the edge blocks allocated;
        // only WHOLE blocks fully inside the range are deallocated).
        let first_full = offset.div_ceil(bs);
        let last_full_excl = end / bs;
        let left_end = core::cmp::min(end, first_full * bs);
        if offset < left_end {
            self.write_at(ino, offset, &alloc::vec![0u8; (left_end - offset) as usize])?;
        }
        let right_start = core::cmp::max(offset, last_full_excl * bs);
        if right_start < end {
            self.write_at(ino, right_start, &alloc::vec![0u8; (end - right_start) as usize])?;
        }

        if first_full < last_full_excl {
            self.punch_blocks_rebuild(ino, first_full as u32, (last_full_excl - 1) as u32)?;
        }
        Ok(())
    }

    /// Remove whole logical blocks `[first, last]` from the extent tree: collect
    /// every data run, free the OLD extent-tree metadata nodes, subtract the
    /// punched range (freeing the physical blocks + splitting straddling
    /// extents), then rebuild the tree from the survivors.
    fn punch_blocks_rebuild(&self, ino: u32, first: u32, last: u32) -> Result<(), MountError> {
        let (mut ibytes, _off) = self.read_inode_bytes(ino)?;
        let mut i_block = [0u8; I_BLOCK_LEN];
        i_block.copy_from_slice(&ibytes[0x28..0x28 + I_BLOCK_LEN]);
        let hdr = inode::parse_extent_header(&i_block)?;

        let runs = self.collect_phys_extents(&i_block)?;
        let mut meta_to_free = Vec::new();
        self.collect_extent_meta(&i_block, &hdr, &mut meta_to_free)?;

        let (ps, pe) = (first, last + 1);
        let mut out: Vec<Extent> = Vec::new();
        let mut data_to_free = Vec::new();
        for r in runs {
            let es = r.logical;
            let ee = r.logical + r.len;
            let is = es.max(ps);
            let ie = ee.min(pe);
            if is >= ie {
                out.push(mk_extent(r.logical, r.phys, r.len, r.unwritten));
                continue;
            }
            for b in is..ie { data_to_free.push(r.phys + (b - es) as u64); }
            if is > es { out.push(mk_extent(es, r.phys, is - es, r.unwritten)); }
            if ie < ee { out.push(mk_extent(ie, r.phys + (ie - es) as u64, ee - ie, r.unwritten)); }
        }
        out.sort_unstable_by_key(|e| e.block);
        let (old_sectors, sectors) = self.write_extent_tree(ino, &mut ibytes, &out)?;
        for b in data_to_free.into_iter().chain(meta_to_free.into_iter()) {
            if let Err(e) = self.free_block(b) {
                return Err(self.rollback_i_blocks_delta(ino, sectors, old_sectors, e));
            }
        }
        Ok(())
    }

    /// Collect ONLY the extent-tree metadata node blocks (interior + leaf), not
    /// data blocks. No-op for a depth-0 inline tree. # C: O(tree) block reads
    pub(super) fn collect_extent_meta(&self, i_block: &[u8; I_BLOCK_LEN], hdr: &inode::ExtentHeader, out: &mut Vec<u64>) -> Result<(), MountError> {
        if hdr.depth == 0 { return Ok(()); }
        for i in 0..hdr.entries {
            if let Some(idx) = inode::parse_extent_idx(i_block, hdr, i) {
                self.collect_meta_subtree(idx.leaf_lba(), hdr.depth - 1, out)?;
            }
        }
        Ok(())
    }

    fn collect_meta_subtree(&self, lba: u64, depth: u16, out: &mut Vec<u64>) -> Result<(), MountError> {
        if depth > 0 {
            let buf = self.read_metadata_block(lba)?;
            let chdr = inode::parse_extent_header_slice(&buf)?;
            for i in 0..chdr.entries {
                if let Some(idx) = inode::parse_extent_idx_slice(&buf, &chdr, i) {
                    self.collect_meta_subtree(idx.leaf_lba(), depth - 1, out)?;
                }
            }
        }
        out.push(lba);
        Ok(())
    }

    /// Rebuild the inode's extent tree from a sorted extent list: inline (depth
    /// 0) for ≤4 extents, else depth-1 leaves under an inline root (≤4 leaves).
    /// Recomputes `i_blocks` and persists the inode. A list too large for a
    /// depth-1 tree (very fragmented, >4·leaf_max extents) is `ExtentTreeFull`.
    pub(super) fn write_extent_tree(&self, ino: u32, ibytes: &mut Vec<u8>, extents: &[Extent]) -> Result<(u32, u32), MountError> {
        let bs = self.sb.block_size as usize;
        let gen = Self::inode_generation(ibytes);
        let mut i_block = [0u8; I_BLOCK_LEN];

        if extents.len() <= 4 {
            let hdr = inode::ExtentHeader {
                magic: inode::EXT4_EXT_MAGIC, entries: extents.len() as u16, max: 4, depth: 0, generation: 0,
            };
            inode::write_extent_header(&mut i_block, &hdr);
            for (i, e) in extents.iter().enumerate() { inode::write_inline_extent(&mut i_block, i as u16, e); }
        } else {
            let leaf_max = crate::csum::extent_block_max(&self.sb, bs) as usize;
            let nleaves = extents.len().div_ceil(leaf_max);
            if nleaves > 4 { return Err(MountError::ExtentTreeFull); }
            let hint = self.extent_hint_group(extents, extents[0].block);
            let mut root_hdr_written = false;
            let root_hdr = inode::ExtentHeader {
                magic: inode::EXT4_EXT_MAGIC, entries: nleaves as u16, max: 4, depth: 1, generation: 0,
            };
            let mut new_meta = Vec::new();
            for (li, chunk) in extents.chunks(leaf_max).enumerate() {
                let leaf_lba = match self.alloc_block(hint) {
                    Ok(lba) => lba,
                    Err(e) => {
                        self.free_allocated_blocks(&new_meta);
                        return Err(e);
                    }
                };
                new_meta.push(leaf_lba);
                let mut leaf_buf = alloc::vec![0u8; bs];
                let lhdr = inode::ExtentHeader {
                    magic: inode::EXT4_EXT_MAGIC, entries: chunk.len() as u16,
                    max: crate::csum::extent_block_max(&self.sb, bs), depth: 0, generation: 0,
                };
                Self::write_slice_extents(&mut leaf_buf, lhdr, chunk);
                if let Err(e) = self.write_extent_block(ino, gen, leaf_lba, &mut leaf_buf) {
                    self.free_allocated_blocks(&new_meta);
                    return Err(e);
                }
                if !root_hdr_written { inode::write_extent_header(&mut i_block, &root_hdr); root_hdr_written = true; }
                inode::write_extent_idx(&mut i_block, li as u16, &Self::idx_for_lba(chunk[0].block, leaf_lba));
            }
            let sectors = match self.count_all_sectors(&i_block) {
                Ok(sectors) => sectors.saturating_add(super::external_xattr_sectors(&self.sb, ibytes)),
                Err(e) => {
                    self.free_allocated_blocks(&new_meta);
                    return Err(e);
                }
            };
            let old_sectors = u32::from_le_bytes([ibytes[0x1C], ibytes[0x1D], ibytes[0x1E], ibytes[0x1F]]);
            if let Err(e) = self.account_i_blocks_delta(ino, old_sectors, sectors) {
                self.free_allocated_blocks(&new_meta);
                return Err(e);
            }
            ibytes[0x1C..0x20].copy_from_slice(&sectors.to_le_bytes());
            ibytes[0x28..0x28 + I_BLOCK_LEN].copy_from_slice(&i_block);
            if let Err(e) = self.write_inode_bytes(ino, ibytes) {
                self.free_allocated_blocks(&new_meta);
                return Err(self.rollback_i_blocks_delta(ino, sectors, old_sectors, e));
            }
            return Ok((old_sectors, sectors));
        }

        // Recompute i_blocks (512-byte sectors) from the rebuilt tree.
        let sectors = self.count_all_sectors(&i_block)?
            .saturating_add(super::external_xattr_sectors(&self.sb, ibytes));
        let old_sectors = u32::from_le_bytes([ibytes[0x1C], ibytes[0x1D], ibytes[0x1E], ibytes[0x1F]]);
        self.account_i_blocks_delta(ino, old_sectors, sectors)?;
        ibytes[0x1C..0x20].copy_from_slice(&sectors.to_le_bytes());
        ibytes[0x28..0x28 + I_BLOCK_LEN].copy_from_slice(&i_block);
        if let Err(e) = self.write_inode_bytes(ino, ibytes) {
            return Err(self.rollback_i_blocks_delta(ino, sectors, old_sectors, e));
        }
        Ok((old_sectors, sectors))
    }
}
