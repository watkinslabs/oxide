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
                    self.collect_subtree_extents(idx.leaf_lba(), &mut out)?;
                }
            }
        }
        out.sort_by_key(|r| r.0);
        Ok(out)
    }

    /// Recursive companion to `collect_leaf_extents`: walk the child block at
    /// `lba`, appending its leaf extents (recursing through interior levels).
    /// # C: O(subtree extents) + O(subtree depth) block I/Os
    pub(super) fn collect_subtree_extents(&self, lba: u64, out: &mut Vec<(u32, u32)>)
        -> Result<(), MountError>
    {
        let buf = self.read_metadata_block(lba)?;
        let hdr = inode::parse_extent_header_slice(&buf)?;
        if hdr.depth == 0 {
            for i in 0..hdr.entries {
                if let Some(e) = inode::parse_inline_extent_slice(&buf, &hdr, i) {
                    out.push((e.block, Self::extent_real_len(e.len)));
                }
            }
        } else {
            for i in 0..hdr.entries {
                if let Some(idx) = inode::parse_extent_idx_slice(&buf, &hdr, i) {
                    self.collect_subtree_extents(idx.leaf_lba(), out)?;
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
