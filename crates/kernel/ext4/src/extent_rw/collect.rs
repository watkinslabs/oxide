use crate::inode::{self, I_BLOCK_LEN};
use crate::mount::{Mount, MountError};
use alloc::vec::Vec;

use super::EXTENT_LEN_MAX;

impl Mount {
    /// Collect this inode's leaf extents as logical block runs for seek hole/data.
    /// # C: O(N_extents) + O(depth) block I/Os
    pub(crate) fn collect_leaf_extents(&self, i_block: &[u8; I_BLOCK_LEN])
        -> Result<Vec<(u32, u32)>, MountError>
    {
        let hdr = inode::parse_extent_header(i_block)?;
        if hdr.depth > inode::EXT4_MAX_EXTENT_DEPTH { return Err(MountError::CorruptExtentTree); }
        let mut out: Vec<(u32, u32)> = Vec::new();
        if hdr.depth == 0 {
            for i in 0..hdr.entries {
                if let Some(e) = inode::parse_inline_extent(i_block, &hdr, i) {
                    out.push((e.block, Self::extent_real_len(e.len)));
                }
            }
        } else {
            for i in 0..hdr.entries {
                if let Some(idx) = inode::parse_extent_idx(i_block, &hdr, i) {
                    self.collect_subtree_extents(idx.leaf_lba(), hdr.depth, &mut out)?;
                }
            }
        }
        out.sort_unstable_by_key(|r| r.0);
        Ok(out)
    }

    /// Recursive companion to `collect_leaf_extents`: walk the child block at
    /// `lba`, appending its leaf extents. `parent_depth` = the depth of the node
    /// that pointed here; this node must be exactly one level shallower
    /// (`extent_child_depth_ok`) or the tree is corrupt/cyclic and is rejected,
    /// bounding recursion to the root depth (≤5) rather than overflowing the
    /// kernel stack. # C: O(subtree extents) + O(subtree depth) I/Os
    pub(super) fn collect_subtree_extents(&self, lba: u64, parent_depth: u16,
        out: &mut Vec<(u32, u32)>) -> Result<(), MountError>
    {
        let buf = self.read_metadata_block(lba)?;
        let hdr = inode::parse_extent_header_slice(&buf)?;
        if !inode::extent_child_depth_ok(parent_depth, hdr.depth) {
            return Err(MountError::CorruptExtentTree);
        }
        if hdr.depth == 0 {
            for i in 0..hdr.entries {
                if let Some(e) = inode::parse_inline_extent_slice(&buf, &hdr, i) {
                    out.push((e.block, Self::extent_real_len(e.len)));
                }
            }
        } else {
            for i in 0..hdr.entries {
                if let Some(idx) = inode::parse_extent_idx_slice(&buf, &hdr, i) {
                    self.collect_subtree_extents(idx.leaf_lba(), hdr.depth, out)?;
                }
            }
        }
        Ok(())
    }

    /// Collect leaf extents as PHYSICAL runs (logical, physical, len, unwritten)
    /// in ascending logical order — the mapping FIEMAP reports. Unlike
    /// `collect_leaf_extents` (which drops the physical start + unwritten bit for
    /// SEEK_HOLE/DATA), this preserves the full leaf geometry. Same depth-bound
    /// (`EXT4_MAX_EXTENT_DEPTH` + strictly-decreasing child depth) as the seek
    /// collector. # C: O(N_extents) + O(depth) block I/Os
    pub(crate) fn collect_phys_extents(&self, i_block: &[u8; I_BLOCK_LEN])
        -> Result<Vec<PhysRun>, MountError>
    {
        let hdr = inode::parse_extent_header(i_block)?;
        if hdr.depth > inode::EXT4_MAX_EXTENT_DEPTH { return Err(MountError::CorruptExtentTree); }
        let mut out: Vec<PhysRun> = Vec::new();
        if hdr.depth == 0 {
            for i in 0..hdr.entries {
                if let Some(e) = inode::parse_inline_extent(i_block, &hdr, i) { out.push(PhysRun::of(&e)); }
            }
        } else {
            for i in 0..hdr.entries {
                if let Some(idx) = inode::parse_extent_idx(i_block, &hdr, i) {
                    self.collect_subtree_phys(idx.leaf_lba(), hdr.depth, &mut out)?;
                }
            }
        }
        out.sort_unstable_by_key(|r| r.logical);
        Ok(out)
    }

    /// Public physical extent map of an inode: `(logical_block, physical_block,
    /// len_blocks, unwritten)` runs ascending by logical block — the geometry
    /// `FS_IOC_FIEMAP` reports (the VFS `fiemap` override scales these to bytes).
    /// Reads the inode, then walks its leaf extents. # C: O(N_extents) + I/O
    pub fn extent_map(&self, ino: u32) -> Result<Vec<(u32, u64, u32, bool)>, MountError> {
        let i = self.read_inode(ino)?;
        Ok(self.collect_phys_extents(&i.i_block)?
            .into_iter().map(|r| (r.logical, r.phys, r.len, r.unwritten)).collect())
    }

    /// Recursive companion to `collect_phys_extents` (mirrors
    /// `collect_subtree_extents`' depth guard). # C: O(subtree)
    fn collect_subtree_phys(&self, lba: u64, parent_depth: u16, out: &mut Vec<PhysRun>)
        -> Result<(), MountError>
    {
        let buf = self.read_metadata_block(lba)?;
        let hdr = inode::parse_extent_header_slice(&buf)?;
        if !inode::extent_child_depth_ok(parent_depth, hdr.depth) {
            return Err(MountError::CorruptExtentTree);
        }
        if hdr.depth == 0 {
            for i in 0..hdr.entries {
                if let Some(e) = inode::parse_inline_extent_slice(&buf, &hdr, i) { out.push(PhysRun::of(&e)); }
            }
        } else {
            for i in 0..hdr.entries {
                if let Some(idx) = inode::parse_extent_idx_slice(&buf, &hdr, i) {
                    self.collect_subtree_phys(idx.leaf_lba(), hdr.depth, out)?;
                }
            }
        }
        Ok(())
    }

    /// Real block length of an extent: the top bit of `ee_len` marks an
    /// unwritten (preallocated) extent, so values `> EXTENT_LEN_MAX` carry
    /// the real length in the low 15 bits. # C: O(1)
    #[inline]
    pub(super) fn extent_real_len(ee_len: u16) -> u32 {
        (if ee_len > EXTENT_LEN_MAX { ee_len - EXTENT_LEN_MAX } else { ee_len }) as u32
    }
}

/// One physical leaf-extent run for FIEMAP: logical block, physical block,
/// length in blocks, and whether it is an unwritten (fallocate-preallocated)
/// extent. Block units — the caller scales by block size to bytes.
pub(crate) struct PhysRun {
    pub logical:   u32,
    pub phys:      u64,
    pub len:       u32,
    pub unwritten: bool,
}

impl PhysRun {
    /// # C: O(1)
    fn of(e: &inode::Extent) -> Self {
        Self { logical: e.block, phys: e.start_lba(), len: e.real_len(), unwritten: e.is_unwritten() }
    }
}
