use crate::inode::{self, I_BLOCK_LEN};
use crate::extent_rw::meta::InodeMetaUpdate;
use crate::mount::{Mount, MountError};
use alloc::vec::Vec;

use super::EXTENT_LEN_MAX;

impl Mount {
    /// Truncate `ino` to `new_len`, freeing trailing data and extent metadata.
    /// # C: O(N_extents) + N_blocks_freed I/O
    pub fn truncate_inode(&self, ino: u32, new_len: u64) -> Result<(), MountError> {
        self.run_journaled(|m| m.truncate_inode_inner(ino, new_len, None, true))
    }

    pub(crate) fn truncate_inode_with_meta(&self, ino: u32, new_len: u64, meta: InodeMetaUpdate)
        -> Result<(), MountError>
    {
        self.run_journaled(|m| m.truncate_inode_inner(ino, new_len, Some(meta), true))
    }

    /// Final-deletion truncate. The namespace layer releases the inode's full
    /// pre-deletion usage atomically, so block teardown must not release it again.
    pub(crate) fn truncate_inode_for_deletion(&self, ino: u32) -> Result<(), MountError> {
        self.run_journaled(|m| m.truncate_inode_inner(ino, 0, None, false))
    }

    pub(super) fn truncate_inode_inner(&self, ino: u32, new_len: u64, meta: Option<InodeMetaUpdate>, account_quota: bool)
        -> Result<(), MountError>
    {
        let bs = self.sb.block_size as u64;
        let inode = self.read_inode(ino)?;
        let cur_size = inode.size;
        if new_len > cur_size {
            // Extend by writing 0 bytes at new_len-1 (zero-fills).
            let z = [0u8; 1];
            return self.write_at_inner(ino, new_len - 1, &z, meta);
        }
        // Shrink path. Free every data block at logical index >= blocks_keep
        // and reclaim any extent-tree metadata block that becomes orphaned.
        let blocks_keep = (new_len + bs - 1) / bs;
        let (mut bytes, _off_inode) = self.read_inode_bytes(ino)?;
        let gen = Self::inode_generation(&bytes);
        let mut i_block = [0u8; I_BLOCK_LEN];
        i_block.copy_from_slice(&bytes[0x28..0x28 + I_BLOCK_LEN]);
        let hdr0 = inode::parse_extent_header(&i_block)?;
        let mut blocks_to_free = Vec::new();
        let mut node_writes = Vec::new();
        if hdr0.depth == 0 {
            // Inline leaf (depth 0): shrink the trailing extents in place.
            let mut new_entries = hdr0.entries;
            for i in (0..hdr0.entries).rev() {
                let e = inode::parse_inline_extent(&i_block, &hdr0, i).unwrap();
                let first = e.block as u64;
                let extent_len = e.real_len() as u64;
                let last_excl = first + extent_len;
                if first >= blocks_keep {
                    for k in 0..extent_len { blocks_to_free.push(e.start_lba() + k); }
                    new_entries -= 1;
                } else if last_excl > blocks_keep {
                    let keep = (blocks_keep - first) as u16;
                    for k in keep as u64..extent_len { blocks_to_free.push(e.start_lba() + k); }
                    let mut e2 = e;
                    e2.len = if e.is_unwritten() { keep + EXTENT_LEN_MAX } else { keep };
                    inode::write_inline_extent(&mut i_block, i, &e2);
                }
            }
            let mut new_hdr = hdr0;
            new_hdr.entries = new_entries;
            inode::write_extent_header(&mut i_block, &new_hdr);
        } else {
            // Depth >= 1: recurse the rightmost path, freeing orphaned
            // subtrees + tail data (was DepthUnsupported — truncating any
            // multi-extent file failed).
            self.truncate_interior_inline(ino, gen, &mut i_block, hdr0, blocks_keep, &mut blocks_to_free, &mut node_writes)?;
        }
        // i_blocks (512-byte sectors): recompute from the remaining DATA
        // extents + surviving extent-tree metadata blocks across the
        // whole tree, matching Linux's i_blocks accounting.
        let sectors = self.count_all_sectors_planned(&i_block, &node_writes)?
            .saturating_add(super::external_xattr_sectors(&self.sb, &bytes));
        let old_sectors = u32::from_le_bytes([bytes[0x1C], bytes[0x1D], bytes[0x1E], bytes[0x1F]]);
        if account_quota { self.account_i_blocks_delta(ino, old_sectors, sectors)?; }
        bytes[0x1C..0x20].copy_from_slice(&sectors.to_le_bytes());
        bytes[0x28..0x28 + I_BLOCK_LEN].copy_from_slice(&i_block);
        bytes[0x04..0x08].copy_from_slice(&((new_len & 0xFFFF_FFFF) as u32).to_le_bytes());
        bytes[0x6C..0x70].copy_from_slice(&((new_len >> 32) as u32).to_le_bytes());
        if let Some(meta) = meta { self.stamp_inode_meta_fields(&mut bytes, meta); }
        for (lba, mut buf) in node_writes {
            if let Err(e) = self.write_extent_block(ino, gen, lba, &mut buf) {
                return Err(self.rollback_truncate_quota(ino, sectors, old_sectors, account_quota, e));
            }
        }
        if let Err(e) = self.write_inode_bytes(ino, &bytes) {
            return Err(self.rollback_truncate_quota(ino, sectors, old_sectors, account_quota, e));
        }
        for b in blocks_to_free {
            if let Err(e) = self.free_block(b) {
                return Err(self.rollback_truncate_quota(ino, sectors, old_sectors, account_quota, e));
            }
        }
        Ok(())
    }

    fn rollback_truncate_quota(&self, ino: u32, sectors: u32, old_sectors: u32,
        account_quota: bool, error: MountError) -> MountError
    {
        if account_quota { self.rollback_i_blocks_delta(ino, sectors, old_sectors, error) } else { error }
    }

    /// Truncate a depth>=1 tree rooted in the inline i_block: keep only
    /// logical blocks < `blocks_keep`. Children entirely past EOF are freed
    /// whole (`free_subtree`); the straddling child is recursed into. Resets
    /// the inline header to an empty depth-0 tree if everything was freed.
    /// # C: O(tree) block I/Os
    pub(super) fn truncate_interior_inline(&self, ino: u32, gen: u32, i_block: &mut [u8; I_BLOCK_LEN],
                                hdr: inode::ExtentHeader, blocks_keep: u64,
                                blocks_to_free: &mut Vec<u64>, node_writes: &mut Vec<(u64, Vec<u8>)>)
        -> Result<(), MountError>
    {
        let mut entries = hdr.entries;
        for i in (0..hdr.entries).rev() {
            let idx = inode::parse_extent_idx(i_block, &hdr, i).ok_or(MountError::NotFound)?;
            let child = idx.leaf_lba();
            if idx.block as u64 >= blocks_keep {
                self.collect_subtree_blocks(child, hdr.depth - 1, blocks_to_free)?;
                entries -= 1;
            } else {
                if self.truncate_node(ino, gen, child, hdr.depth - 1, blocks_keep, blocks_to_free, node_writes)? {
                    blocks_to_free.push(child);
                    entries -= 1;
                }
                break; // earlier children are entirely < blocks_keep → kept
            }
        }
        if entries == 0 {
            for b in i_block.iter_mut() { *b = 0; }
            let empty = inode::ExtentHeader {
                magic: inode::EXT4_EXT_MAGIC, entries: 0, max: 4, depth: 0, generation: 0,
            };
            inode::write_extent_header(i_block, &empty);
        } else {
            let mut nh = hdr; nh.entries = entries;
            inode::write_extent_header(i_block, &nh);
        }
        Ok(())
    }

    /// Truncate a node block (leaf or interior) at `lba` to keep only
    /// logical blocks < `blocks_keep`. Returns true if the node became
    /// empty (caller frees the block + drops its parent idx).
    /// # C: O(subtree) block I/Os
    pub(super) fn truncate_node(&self, ino: u32, gen: u32, lba: u64, depth: u16, blocks_keep: u64,
        blocks_to_free: &mut Vec<u64>, node_writes: &mut Vec<(u64, Vec<u8>)>) -> Result<bool, MountError> {
        let mut buf = self.read_metadata_block(lba)?;
        let hdr = inode::parse_extent_header_slice(&buf)?;
        let mut entries = hdr.entries;
        if depth == 0 {
            for i in (0..hdr.entries).rev() {
                let e = inode::parse_inline_extent_slice(&buf, &hdr, i).ok_or(MountError::NotFound)?;
                let first = e.block as u64;
                let extent_len = e.real_len() as u64;
                let last_excl = first + extent_len;
                if first >= blocks_keep {
                    for k in 0..extent_len { blocks_to_free.push(e.start_lba() + k); }
                    entries -= 1;
                } else if last_excl > blocks_keep {
                    let keep = (blocks_keep - first) as u16;
                    for k in keep as u64..extent_len { blocks_to_free.push(e.start_lba() + k); }
                    let mut e2 = e;
                    e2.len = if e.is_unwritten() { keep + EXTENT_LEN_MAX } else { keep };
                    inode::write_inline_extent_slice(&mut buf, i, &e2);
                    break;
                } else { break; }
            }
        } else {
            for i in (0..hdr.entries).rev() {
                let idx = inode::parse_extent_idx_slice(&buf, &hdr, i).ok_or(MountError::NotFound)?;
                let child = idx.leaf_lba();
                if idx.block as u64 >= blocks_keep {
                    self.collect_subtree_blocks(child, depth - 1, blocks_to_free)?;
                    entries -= 1;
                } else {
                    if self.truncate_node(ino, gen, child, depth - 1, blocks_keep, blocks_to_free, node_writes)? {
                        blocks_to_free.push(child);
                        entries -= 1;
                    }
                    break;
                }
            }
        }
        let mut nh = hdr; nh.entries = entries;
        inode::write_extent_header_slice(&mut buf, &nh);
        if entries != 0 {
            // The surviving node block changed (entries / trimmed extent) →
            // restamp its extent-tail csum when the plan is applied.
            node_writes.push((lba, buf));
        }
        Ok(entries == 0)
    }

    /// Free every block under (and including) the metadata block at `lba`:
    /// all data blocks at the leaves + every interior/leaf metadata block.
    /// # C: O(subtree) block I/Os
    pub(super) fn collect_subtree_blocks(&self, lba: u64, depth: u16, blocks_to_free: &mut Vec<u64>) -> Result<(), MountError> {
        let buf = self.read_metadata_block(lba)?;
        let hdr = inode::parse_extent_header_slice(&buf)?;
        if depth == 0 {
            for i in 0..hdr.entries {
                let e = inode::parse_inline_extent_slice(&buf, &hdr, i).ok_or(MountError::NotFound)?;
                for k in 0..e.real_len() as u64 { blocks_to_free.push(e.start_lba() + k); }
            }
        } else {
            for i in 0..hdr.entries {
                let idx = inode::parse_extent_idx_slice(&buf, &hdr, i).ok_or(MountError::NotFound)?;
                self.collect_subtree_blocks(idx.leaf_lba(), depth - 1, blocks_to_free)?;
            }
        }
        blocks_to_free.push(lba);
        Ok(())
    }

    fn count_all_sectors_planned(&self, i_block: &[u8; I_BLOCK_LEN], node_writes: &[(u64, Vec<u8>)]) -> Result<u32, MountError> {
        let hdr = inode::parse_extent_header(i_block)?;
        let spb = self.sb.block_size / 512;
        if hdr.depth == 0 {
            let mut s = 0u32;
            for i in 0..hdr.entries {
                if let Some(e) = inode::parse_inline_extent(i_block, &hdr, i) {
                    s = s.saturating_add(e.real_len() * spb);
                }
            }
            return Ok(s);
        }
        let mut s = 0u32;
        for i in 0..hdr.entries {
            let idx = inode::parse_extent_idx(i_block, &hdr, i).ok_or(MountError::NotFound)?;
            s = s.saturating_add(spb);
            s = s.saturating_add(self.count_all_sectors_node_planned(idx.leaf_lba(), hdr.depth - 1, node_writes)?);
        }
        Ok(s)
    }

    fn count_all_sectors_node_planned(&self, lba: u64, depth: u16, node_writes: &[(u64, Vec<u8>)]) -> Result<u32, MountError> {
        let disk_buf;
        let buf = match node_writes.iter().rev().find(|(node_lba, _)| *node_lba == lba) {
            Some((_, planned)) => planned.as_slice(),
            None => {
                disk_buf = self.read_metadata_block(lba)?;
                disk_buf.as_slice()
            }
        };
        let hdr = inode::parse_extent_header_slice(buf)?;
        let spb = self.sb.block_size / 512;
        let mut s = 0u32;
        if depth == 0 {
            for i in 0..hdr.entries {
                if let Some(e) = inode::parse_inline_extent_slice(buf, &hdr, i) {
                    s = s.saturating_add(e.real_len() * spb);
                }
            }
        } else {
            for i in 0..hdr.entries {
                let idx = inode::parse_extent_idx_slice(buf, &hdr, i).ok_or(MountError::NotFound)?;
                s = s.saturating_add(spb);
                s = s.saturating_add(self.count_all_sectors_node_planned(idx.leaf_lba(), depth - 1, node_writes)?);
            }
        }
        Ok(s)
    }

    /// Sum data blocks + extent-tree metadata blocks (in 512-byte
    /// sectors) across the whole extent tree — for the post-truncate
    /// i_blocks field. Matches the append path: every data block and
    /// every external leaf/interior node counts; the inline root rides
    /// the inode and is not counted (Linux does the same).
    /// # C: O(tree) block I/Os
    pub(super) fn count_all_sectors(&self, i_block: &[u8; I_BLOCK_LEN]) -> Result<u32, MountError> {
        let hdr = inode::parse_extent_header(i_block)?;
        let spb = self.sb.block_size / 512;
        if hdr.depth == 0 {
            let mut s = 0u32;
            for i in 0..hdr.entries {
                if let Some(e) = inode::parse_inline_extent(i_block, &hdr, i) {
                    s = s.saturating_add(e.real_len() * spb);
                }
            }
            return Ok(s);
        }
        let mut s = 0u32;
        for i in 0..hdr.entries {
            let idx = inode::parse_extent_idx(i_block, &hdr, i).ok_or(MountError::NotFound)?;
            // The child node block itself is metadata → +spb.
            s = s.saturating_add(spb);
            s = s.saturating_add(self.count_all_sectors_node(idx.leaf_lba(), hdr.depth - 1)?);
        }
        Ok(s)
    }

    pub(super) fn count_all_sectors_node(&self, lba: u64, depth: u16) -> Result<u32, MountError> {
        let buf = self.read_metadata_block(lba)?;
        let hdr = inode::parse_extent_header_slice(&buf)?;
        let spb = self.sb.block_size / 512;
        let mut s = 0u32;
        if depth == 0 {
            for i in 0..hdr.entries {
                if let Some(e) = inode::parse_inline_extent_slice(&buf, &hdr, i) {
                    s = s.saturating_add(e.real_len() * spb);
                }
            }
        } else {
            for i in 0..hdr.entries {
                let idx = inode::parse_extent_idx_slice(&buf, &hdr, i).ok_or(MountError::NotFound)?;
                s = s.saturating_add(spb);
                s = s.saturating_add(self.count_all_sectors_node(idx.leaf_lba(), depth - 1)?);
            }
        }
        Ok(s)
    }
}
