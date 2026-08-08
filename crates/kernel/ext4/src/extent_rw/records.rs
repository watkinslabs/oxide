use crate::inode::{self, Extent, I_BLOCK_LEN};
use crate::mount::{Mount, MountError};
use alloc::vec::Vec;

use super::EXTENT_LEN_MAX;

/// Build an `Extent` record from a physical run `{block, phys, len}`,
/// re-applying the unwritten marker `ee_len` carries in its top bit. `len` must
/// be `1..=EXTENT_LEN_MAX`. # C: O(1)
pub(in crate::extent_rw) fn extent_run(block: u32, phys: u64, len: u32, unwritten: bool) -> Extent {
    Extent {
        block,
        len: if unwritten { len as u16 + EXTENT_LEN_MAX } else { len as u16 },
        start_hi: (phys >> 32) as u16,
        start_lo: (phys & 0xFFFF_FFFF) as u32,
    }
}

impl Mount {
    pub(super) fn extent_for(logical: u32, phys: u64) -> Extent {
        Extent {
            block: logical,
            len: 1,
            start_hi: (phys >> 32) as u16,
            start_lo: (phys & 0xFFFF_FFFF) as u32,
        }
    }

    /// An UNWRITTEN (fallocate-preallocated) extent of `len` blocks at `phys`.
    /// On disk `ee_len = real_len + EXTENT_LEN_MAX` (Linux `ext4_ext_mark_unwritten`)
    /// so reads serve zeros (`is_unwritten()`) until a write converts the range.
    /// `len` must be 1..=EXTENT_LEN_MAX-1. # C: O(1)
    pub(super) fn extent_for_unwritten(logical: u32, phys: u64, len: u16) -> Extent {
        Extent {
            block: logical,
            len: len + EXTENT_LEN_MAX,
            start_hi: (phys >> 32) as u16,
            start_lo: (phys & 0xFFFF_FFFF) as u32,
        }
    }

    pub(super) fn idx_for_lba(block: u32, lba: u64) -> inode::ExtentIdx {
        inode::ExtentIdx {
            block,
            leaf_lo: (lba & 0xFFFF_FFFF) as u32,
            leaf_hi: (lba >> 32) as u16,
            _unused: 0,
        }
    }

    pub(super) fn extent_end(e: &Extent) -> u64 {
        // real_len(): for a written extent == len; for unwritten strips the
        // EXTENT_LEN_MAX flag bit so the LOGICAL range is correct either way.
        e.block as u64 + e.real_len() as u64
    }

    pub(super) fn extent_vec_contains(extents: &[Extent], logical: u32) -> bool {
        extents.iter().any(|e| {
            logical as u64 >= e.block as u64 && (logical as u64) < Self::extent_end(e)
        })
    }

    pub(super) fn extent_hint_group(&self, extents: &[Extent], logical: u32) -> u32 {
        if let Some(e) = extents.iter().rev().find(|e| e.block <= logical) {
            self.group_of_block(e.start_lba())
        } else if let Some(e) = extents.first() {
            self.group_of_block(e.start_lba())
        } else {
            0
        }
    }

    pub(super) fn can_merge(a: &Extent, b: &Extent) -> bool {
        // Only coalesce extents of the SAME writtenness (Linux never merges a
        // written and an unwritten extent), physically + logically adjacent,
        // whose combined REAL length still fits one extent record.
        a.is_unwritten() == b.is_unwritten()
            && Self::extent_end(a) == b.block as u64
            && a.start_lba() + a.real_len() as u64 == b.start_lba()
            && (a.real_len() + b.real_len()) <= EXTENT_LEN_MAX as u32
    }

    pub(super) fn insert_extent_record(extents: &mut Vec<Extent>, new_extent: Extent) -> Result<(), MountError> {
        let new_start = new_extent.block as u64;
        let new_end = Self::extent_end(&new_extent);
        for e in extents.iter() {
            if new_start < Self::extent_end(e) && (e.block as u64) < new_end {
                return Err(MountError::NotFound);
            }
        }
        extents.push(new_extent);
        extents.sort_unstable_by_key(|e| e.block);

        let mut merged: Vec<Extent> = Vec::with_capacity(extents.len());
        for e in extents.iter().copied() {
            if let Some(last) = merged.last_mut() {
                if Self::can_merge(last, &e) {
                    // Combine REAL lengths and re-apply the unwritten flag (both
                    // are same-writtenness per can_merge) — never sum raw `len`,
                    // which would double the EXTENT_LEN_MAX flag for unwritten.
                    let combined = last.real_len() + e.real_len();
                    last.len = if last.is_unwritten() { combined as u16 + EXTENT_LEN_MAX } else { combined as u16 };
                    continue;
                }
            }
            merged.push(e);
        }
        *extents = merged;
        Ok(())
    }

    pub(super) fn inline_extents(i_block: &[u8; I_BLOCK_LEN], hdr: &inode::ExtentHeader) -> Result<Vec<Extent>, MountError> {
        let mut extents = Vec::with_capacity(hdr.entries as usize);
        for i in 0..hdr.entries {
            extents.push(inode::parse_inline_extent(i_block, hdr, i).ok_or(MountError::NotFound)?);
        }
        extents.sort_unstable_by_key(|e| e.block);
        Ok(extents)
    }

    pub(super) fn slice_extents(buf: &[u8], hdr: &inode::ExtentHeader) -> Result<Vec<Extent>, MountError> {
        let mut extents = Vec::with_capacity(hdr.entries as usize);
        for i in 0..hdr.entries {
            extents.push(inode::parse_inline_extent_slice(buf, hdr, i).ok_or(MountError::NotFound)?);
        }
        extents.sort_unstable_by_key(|e| e.block);
        Ok(extents)
    }

    pub(super) fn inline_indices(i_block: &[u8; I_BLOCK_LEN], hdr: &inode::ExtentHeader) -> Result<Vec<inode::ExtentIdx>, MountError> {
        let mut idxs = Vec::with_capacity(hdr.entries as usize);
        for i in 0..hdr.entries {
            idxs.push(inode::parse_extent_idx(i_block, hdr, i).ok_or(MountError::NotFound)?);
        }
        idxs.sort_unstable_by_key(|idx| idx.block);
        Ok(idxs)
    }

    pub(super) fn slice_indices(buf: &[u8], hdr: &inode::ExtentHeader) -> Result<Vec<inode::ExtentIdx>, MountError> {
        let mut idxs = Vec::with_capacity(hdr.entries as usize);
        for i in 0..hdr.entries {
            idxs.push(inode::parse_extent_idx_slice(buf, hdr, i).ok_or(MountError::NotFound)?);
        }
        idxs.sort_unstable_by_key(|idx| idx.block);
        Ok(idxs)
    }

    pub(super) fn write_inline_extents(i_block: &mut [u8; I_BLOCK_LEN], mut hdr: inode::ExtentHeader, extents: &[Extent]) {
        for b in i_block.iter_mut() { *b = 0; }
        hdr.entries = extents.len() as u16;
        hdr.depth = 0;
        inode::write_extent_header(i_block, &hdr);
        for (i, e) in extents.iter().enumerate() {
            inode::write_inline_extent(i_block, i as u16, e);
        }
    }

    pub(super) fn write_slice_extents(buf: &mut [u8], mut hdr: inode::ExtentHeader, extents: &[Extent]) {
        for b in buf.iter_mut() { *b = 0; }
        hdr.entries = extents.len() as u16;
        hdr.depth = 0;
        inode::write_extent_header_slice(buf, &hdr);
        for (i, e) in extents.iter().enumerate() {
            inode::write_inline_extent_slice(buf, i as u16, e);
        }
    }

    pub(super) fn write_inline_indices(i_block: &mut [u8; I_BLOCK_LEN], mut hdr: inode::ExtentHeader, idxs: &[inode::ExtentIdx]) {
        for b in i_block.iter_mut() { *b = 0; }
        hdr.entries = idxs.len() as u16;
        inode::write_extent_header(i_block, &hdr);
        for (i, idx) in idxs.iter().enumerate() {
            inode::write_extent_idx(i_block, i as u16, idx);
        }
    }

    pub(super) fn write_slice_indices(buf: &mut [u8], mut hdr: inode::ExtentHeader, idxs: &[inode::ExtentIdx]) {
        for b in buf.iter_mut() { *b = 0; }
        hdr.entries = idxs.len() as u16;
        inode::write_extent_header_slice(buf, &hdr);
        for (i, idx) in idxs.iter().enumerate() {
            inode::write_extent_idx_slice(buf, i as u16, idx);
        }
    }

    pub(super) fn inline_child_index_for_insert(i_block: &[u8; I_BLOCK_LEN], hdr: &inode::ExtentHeader, logical: u32)
        -> Result<u16, MountError>
    {
        if hdr.entries == 0 { return Err(MountError::NotFound); }
        let mut chosen = 0u16;
        for i in 0..hdr.entries {
            let idx = inode::parse_extent_idx(i_block, hdr, i).ok_or(MountError::NotFound)?;
            if idx.block <= logical {
                chosen = i;
            } else {
                break;
            }
        }
        Ok(chosen)
    }

    pub(super) fn slice_child_index_for_insert(buf: &[u8], hdr: &inode::ExtentHeader, logical: u32)
        -> Result<u16, MountError>
    {
        if hdr.entries == 0 { return Err(MountError::NotFound); }
        let mut chosen = 0u16;
        for i in 0..hdr.entries {
            let idx = inode::parse_extent_idx_slice(buf, hdr, i).ok_or(MountError::NotFound)?;
            if idx.block <= logical {
                chosen = i;
            } else {
                break;
            }
        }
        Ok(chosen)
    }

    pub(super) fn split_extents_for_leaf(extents: &[Extent]) -> (Vec<Extent>, Vec<Extent>) {
        let split = extents.len() / 2;
        (extents[..split].to_vec(), extents[split..].to_vec())
    }

    pub(super) fn split_indices_for_node(idxs: &[inode::ExtentIdx]) -> (Vec<inode::ExtentIdx>, Vec<inode::ExtentIdx>) {
        let split = idxs.len() / 2;
        (idxs[..split].to_vec(), idxs[split..].to_vec())
    }
}
