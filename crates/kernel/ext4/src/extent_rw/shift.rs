// fallocate range-shift modes: COLLAPSE_RANGE (left shift) and INSERT_RANGE
// (right shift). Both re-index every extent past the range, so both go through
// one primitive: collect the inode's physical runs, plan the new logical
// layout, rebuild the extent tree from the plan, then release whatever the
// operation gave back. Argument validation belongs to the fallocate mode
// dispatch; by the time these run, the range is block-aligned and in range.
//
// Module manifest:
// - plan: pure run-list transforms for the left and right shift (no I/O).

mod plan;

use crate::inode::{self, I_BLOCK_LEN};
use crate::mount::{Mount, MountError};
use alloc::vec::Vec;

/// Everything a shift needs from the inode before its tree is rewritten: the
/// raw inode bytes (rewritten in place by the tree builder), the extent runs
/// to re-index, and the metadata node blocks the old tree occupied.
struct ShiftInput {
    ibytes:  Vec<u8>,
    runs:    Vec<super::collect::PhysRun>,
    meta:    Vec<u64>,
}

impl Mount {
    /// fallocate `FALLOC_FL_COLLAPSE_RANGE`: remove `[offset, offset+len)` from
    /// the file and pull every later byte down by `len`, shrinking `i_size` by
    /// `len`. Physical blocks inside the removed range are freed.
    /// # C: O(N_extents) + O(freed blocks) I/O
    pub fn collapse_range_inode(&self, ino: u32, offset: u64, len: u64) -> Result<(), MountError> {
        self.run_journaled(|m| m.collapse_range_inner(ino, offset, len))
    }

    /// fallocate `FALLOC_FL_INSERT_RANGE`: open a `len`-byte hole at `offset` by
    /// pushing every byte at or past it up by `len`, growing `i_size` by `len`.
    /// No block is allocated or freed — only logical block numbers move.
    /// # C: O(N_extents) + tree-rebuild I/O
    pub fn insert_range_inode(&self, ino: u32, offset: u64, len: u64) -> Result<(), MountError> {
        self.run_journaled(|m| m.insert_range_inner(ino, offset, len))
    }

    /// Read the inode's extent geometry ahead of a rewrite. # C: O(tree) I/O
    fn shift_input(&self, ino: u32) -> Result<ShiftInput, MountError> {
        let (ibytes, _off) = self.read_inode_bytes(ino)?;
        let mut i_block = [0u8; I_BLOCK_LEN];
        i_block.copy_from_slice(&ibytes[0x28..0x28 + I_BLOCK_LEN]);
        let hdr = inode::parse_extent_header(&i_block)?;
        let runs = self.collect_phys_extents(&i_block)?;
        let mut meta = Vec::new();
        self.collect_extent_meta(&i_block, &hdr, &mut meta)?;
        Ok(ShiftInput { ibytes, runs, meta })
    }

    /// Blocks-per-shift in logical units. `offset` and `len` are block-aligned
    /// by the time a shift runs, so both divisions are exact. # C: O(1)
    fn shift_units(&self, offset: u64, len: u64) -> Result<(u32, u32), MountError> {
        let bs = self.sb.block_size as u64;
        if bs == 0 { return Err(MountError::Inode(inode::InodeError::BadLen)); }
        let start = u32::try_from(offset / bs).map_err(|_| MountError::Inode(inode::InodeError::BadLen))?;
        let shift = u32::try_from(len / bs).map_err(|_| MountError::Inode(inode::InodeError::BadLen))?;
        start.checked_add(shift).ok_or(MountError::Inode(inode::InodeError::BadLen))?;
        Ok((start, shift))
    }

    fn collapse_range_inner(&self, ino: u32, offset: u64, len: u64) -> Result<(), MountError> {
        let size = self.read_inode(ino)?.size;
        let new_size = size.checked_sub(len).ok_or(MountError::Inode(inode::InodeError::BadLen))?;
        let (start, shift) = self.shift_units(offset, len)?;
        let mut input = self.shift_input(ino)?;
        let (extents, data_to_free) = plan::plan_collapse(&input.runs, start, shift);
        let (old_sectors, sectors) = self.write_extent_tree(ino, &mut input.ibytes, &extents)?;
        for b in data_to_free.into_iter().chain(input.meta.into_iter()) {
            if let Err(e) = self.free_block(b) {
                return Err(self.rollback_i_blocks_delta(ino, sectors, old_sectors, e));
            }
        }
        // Size shrinks only once the blocks are gone: an error before this point
        // leaves the file describing every byte it still owns.
        self.set_inode_size(ino, new_size)
    }

    fn insert_range_inner(&self, ino: u32, offset: u64, len: u64) -> Result<(), MountError> {
        let size = self.read_inode(ino)?.size;
        let new_size = size.checked_add(len).ok_or(MountError::Inode(inode::InodeError::BadLen))?;
        let (start, shift) = self.shift_units(offset, len)?;
        // The file is grown BEFORE the extents move: a failure part-way leaves a
        // file that is too long rather than one whose tail blocks sit past EOF
        // and are therefore unreachable.
        self.set_inode_size(ino, new_size)?;
        let mut input = self.shift_input(ino)?;
        let extents = match plan::plan_insert(&input.runs, start, shift) {
            Ok(extents) => extents,
            Err(e) => { let _ = self.set_inode_size(ino, size); return Err(e); }
        };
        let (old_sectors, sectors) = match self.write_extent_tree(ino, &mut input.ibytes, &extents) {
            Ok(pair) => pair,
            Err(e) => { let _ = self.set_inode_size(ino, size); return Err(e); }
        };
        // Only the OLD tree's metadata nodes are released; every data block is
        // still owned by the file, just at a higher logical index.
        for b in input.meta {
            if let Err(e) = self.free_block(b) {
                return Err(self.rollback_i_blocks_delta(ino, sectors, old_sectors, e));
            }
        }
        Ok(())
    }
}
