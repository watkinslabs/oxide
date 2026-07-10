use crate::inode::{self, I_BLOCK_LEN};
use crate::mount::{Mount, MountError, write_byte_range};

use super::EXT4_MAX_EXTENT_DEPTH;

impl Mount {
    /// Append one filesystem block to `ino` through the journaled extent path.
    /// # C: O(N_extents) + 1 alloc + 2 block I/Os
    pub fn append_block(&self, ino: u32, data: &[u8]) -> Result<u32, MountError> {
        self.run_journaled(|m| m.append_block_inner(ino, data))
    }

    pub(super) fn append_block_inner(&self, ino: u32, data: &[u8]) -> Result<u32, MountError> {
        let bs = self.sb.block_size as usize;
        if data.len() != bs {
            return Err(MountError::Inode(inode::InodeError::BadLen));
        }
        let (mut ino_bytes, ino_byte_off) = self.read_inode_bytes(ino)?;
        let cur_size = u32::from_le_bytes([ino_bytes[0x04], ino_bytes[0x05], ino_bytes[0x06], ino_bytes[0x07]]) as u64
            | ((u32::from_le_bytes([ino_bytes[0x6C], ino_bytes[0x6D], ino_bytes[0x6E], ino_bytes[0x6F]]) as u64) << 32);
        let new_logical = ((cur_size + bs as u64 - 1) / bs as u64) as u32;
        let new_size = cur_size + bs as u64;
        self.insert_logical_block_with_inode_bytes(ino, &mut ino_bytes, ino_byte_off, new_logical, data, new_size, false, false)
    }

    /// Map `logical` as a preallocated UNWRITTEN block (no data I/O) — the
    /// O(1)-write fallocate path. If the block is already mapped this is a no-op.
    /// # C: O(N_extents) + 1 alloc
    pub(super) fn map_unwritten_block_inner(&self, ino: u32, logical: u32, new_size: u64) -> Result<u32, MountError> {
        let (mut ino_bytes, ino_byte_off) = self.read_inode_bytes(ino)?;
        self.insert_logical_block_with_inode_bytes(ino, &mut ino_bytes, ino_byte_off, logical, &[], new_size, true, false)
    }

    /// Allocate + map `logical` as a WRITTEN extent WITHOUT writing `data` now:
    /// the caller writes the block content later (coalesced with adjacent
    /// blocks into one large device request). The returned physical block IS the
    /// final data location, so a later direct `write_byte_range` to it (before
    /// the batch commit) satisfies data=ordered. Distinct from `unwritten`
    /// (which marks the extent unwritten and serves zeros on read).
    /// # C: O(N_extents) + 1 alloc
    pub(super) fn alloc_written_block_defer(&self, ino: u32, ino_bytes: &mut alloc::vec::Vec<u8>, ino_byte_off: u64, logical: u32, new_size: u64) -> Result<u32, MountError> {
        self.insert_logical_block_with_inode_bytes(ino, ino_bytes, ino_byte_off, logical, &[], new_size, false, true)
    }

    /// `unwritten`: map the block as a preallocated UNWRITTEN extent — allocate
    /// the block but do NOT write `data` (reads serve zeros until a later write
    /// converts it). This is the O(1)-I/O fallocate path (Linux
    /// `ext4_ext_map_blocks` with `EXT4_GET_BLOCKS_UNWRIT_EXT`).
    /// `defer_data`: allocate + map a WRITTEN extent but skip the inline data
    /// write (caller writes it later, coalesced). Mutually exclusive with
    /// `unwritten`.
    pub(super) fn insert_logical_block_with_inode_bytes(
        &self,
        ino: u32,
        ino_bytes: &mut alloc::vec::Vec<u8>,
        ino_byte_off: u64,
        logical: u32,
        data: &[u8],
        new_size: u64,
        unwritten: bool,
        defer_data: bool,
    ) -> Result<u32, MountError> {
        let mut i_block: [u8; I_BLOCK_LEN] = {
            let mut b = [0u8; I_BLOCK_LEN];
            b.copy_from_slice(&ino_bytes[0x28..0x28 + I_BLOCK_LEN]);
            b
        };
        let hdr = inode::parse_extent_header(&i_block)?;
        if hdr.depth > EXT4_MAX_EXTENT_DEPTH { return Err(MountError::DepthUnsupported); }
        if hdr.depth == 0 {
            return self.insert_inline_sorted(ino, ino_bytes, ino_byte_off, &mut i_block, hdr, new_size, logical, data, unwritten, defer_data);
        }

        let bs = self.sb.block_size as usize;
        let gen = Self::inode_generation(ino_bytes);
        let leaf_extents = self.leaf_extents_for_insert(&i_block, &hdr, logical)?;
        if Self::extent_vec_contains(&leaf_extents, logical) {
            return Ok(logical);
        }

        let hint_group = Self::extent_hint_group(self, &leaf_extents, logical);
        let phys = self.alloc_block(hint_group)?;
        let new_extent = if unwritten {
            Self::extent_for_unwritten(logical, phys, 1)
        } else {
            if !defer_data { write_byte_range(&*self.dev, phys * bs as u64, data)?; }
            Self::extent_for(logical, phys)
        };

        let mut simulated_extents = leaf_extents;
        Self::insert_extent_record(&mut simulated_extents, new_extent)?;
        match self.insert_would_exceed_max_depth(&i_block, &hdr, logical, simulated_extents.len()) {
            Ok(false) => {}
            Ok(true) => {
                let _ = self.free_block(phys);
                return Err(MountError::ExtentTreeFull);
            }
            Err(e) => {
                let _ = self.free_block(phys);
                return Err(e);
            }
        }

        let extra_meta_sectors =
            self.insert_into_inline_root(ino, gen, &mut i_block, hdr, logical, new_extent, hint_group)?;
        self.persist_inode_after_append(ino, ino_bytes, ino_byte_off, &i_block, new_size, extra_meta_sectors)?;
        Ok(logical)
    }

}
