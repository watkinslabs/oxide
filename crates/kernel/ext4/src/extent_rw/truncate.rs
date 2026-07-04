use crate::inode::{self, I_BLOCK_LEN};
use crate::mount::{Mount, MountError, read_byte_range_pub};

impl Mount {
    /// Truncate `ino` to `new_len`, freeing trailing data and extent metadata.
    /// # C: O(N_extents) + N_blocks_freed I/O
    pub fn truncate_inode(&self, ino: u32, new_len: u64) -> Result<(), MountError> {
        self.run_journaled(|m| m.truncate_inode_inner(ino, new_len))
    }

    pub(super) fn truncate_inode_inner(&self, ino: u32, new_len: u64) -> Result<(), MountError> {
        let bs = self.sb.block_size as u64;
        let inode = self.read_inode(ino)?;
        let cur_size = inode.size;
        if new_len > cur_size {
            // Extend by writing 0 bytes at new_len-1 (zero-fills).
            let z = [0u8; 1];
            return self.write_at(ino, new_len - 1, &z);
        }
        // Shrink path. Free every data block at logical index >= blocks_keep
        // and reclaim any extent-tree metadata block that becomes orphaned.
        let blocks_keep = (new_len + bs - 1) / bs;
        let (mut bytes, _off_inode) = self.read_inode_bytes(ino)?;
        let gen = Self::inode_generation(&bytes);
        let mut i_block = [0u8; I_BLOCK_LEN];
        i_block.copy_from_slice(&bytes[0x28..0x28 + I_BLOCK_LEN]);
        let hdr0 = inode::parse_extent_header(&i_block)?;
        if hdr0.depth == 0 {
            // Inline leaf (depth 0): shrink the trailing extents in place.
            let mut new_entries = hdr0.entries;
            for i in (0..hdr0.entries).rev() {
                let e = inode::parse_inline_extent(&i_block, &hdr0, i).unwrap();
                let first = e.block as u64;
                let last_excl = first + e.len as u64;
                if first >= blocks_keep {
                    for k in 0..e.len as u64 { let _ = self.free_block(e.start_lba() + k); }
                    new_entries -= 1;
                } else if last_excl > blocks_keep {
                    let keep = (blocks_keep - first) as u16;
                    for k in keep as u64..e.len as u64 { let _ = self.free_block(e.start_lba() + k); }
                    let mut e2 = e; e2.len = keep;
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
            self.truncate_interior_inline(ino, gen, &mut i_block, hdr0, blocks_keep)?;
        }
        // i_blocks (512-byte sectors): recompute from the remaining DATA
        // extents + surviving extent-tree metadata blocks across the
        // whole tree, matching Linux's i_blocks accounting.
        let sectors = self.count_all_sectors(&i_block)?;
        bytes[0x1C..0x20].copy_from_slice(&sectors.to_le_bytes());
        bytes[0x28..0x28 + I_BLOCK_LEN].copy_from_slice(&i_block);
        bytes[0x04..0x08].copy_from_slice(&((new_len & 0xFFFF_FFFF) as u32).to_le_bytes());
        bytes[0x6C..0x70].copy_from_slice(&((new_len >> 32) as u32).to_le_bytes());
        self.write_inode_bytes(ino, &bytes)?;
        Ok(())
    }

    /// Truncate a depth>=1 tree rooted in the inline i_block: keep only
    /// logical blocks < `blocks_keep`. Children entirely past EOF are freed
    /// whole (`free_subtree`); the straddling child is recursed into. Resets
    /// the inline header to an empty depth-0 tree if everything was freed.
    /// # C: O(tree) block I/Os
    pub(super) fn truncate_interior_inline(&self, ino: u32, gen: u32, i_block: &mut [u8; I_BLOCK_LEN],
                                hdr: inode::ExtentHeader, blocks_keep: u64)
        -> Result<(), MountError>
    {
        let mut entries = hdr.entries;
        for i in (0..hdr.entries).rev() {
            let idx = inode::parse_extent_idx(i_block, &hdr, i).ok_or(MountError::NotFound)?;
            let child = idx.leaf_lba();
            if idx.block as u64 >= blocks_keep {
                self.free_subtree(child, hdr.depth - 1)?;
                entries -= 1;
            } else {
                if self.truncate_node(ino, gen, child, hdr.depth - 1, blocks_keep)? {
                    let _ = self.free_block(child);
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
    pub(super) fn truncate_node(&self, ino: u32, gen: u32, lba: u64, depth: u16, blocks_keep: u64) -> Result<bool, MountError> {
        let bs = self.sb.block_size as usize;
        let mut buf = read_byte_range_pub(&*self.dev, lba * bs as u64, bs)?;
        let hdr = inode::parse_extent_header_slice(&buf)?;
        let mut entries = hdr.entries;
        if depth == 0 {
            for i in (0..hdr.entries).rev() {
                let e = inode::parse_inline_extent_slice(&buf, &hdr, i).ok_or(MountError::NotFound)?;
                let first = e.block as u64;
                let last_excl = first + e.len as u64;
                if first >= blocks_keep {
                    for k in 0..e.len as u64 { let _ = self.free_block(e.start_lba() + k); }
                    entries -= 1;
                } else if last_excl > blocks_keep {
                    let keep = (blocks_keep - first) as u16;
                    for k in keep as u64..e.len as u64 { let _ = self.free_block(e.start_lba() + k); }
                    let mut e2 = e; e2.len = keep;
                    inode::write_inline_extent_slice(&mut buf, i, &e2);
                    break;
                } else { break; }
            }
        } else {
            for i in (0..hdr.entries).rev() {
                let idx = inode::parse_extent_idx_slice(&buf, &hdr, i).ok_or(MountError::NotFound)?;
                let child = idx.leaf_lba();
                if idx.block as u64 >= blocks_keep {
                    self.free_subtree(child, depth - 1)?;
                    entries -= 1;
                } else {
                    if self.truncate_node(ino, gen, child, depth - 1, blocks_keep)? {
                        let _ = self.free_block(child);
                        entries -= 1;
                    }
                    break;
                }
            }
        }
        let mut nh = hdr; nh.entries = entries;
        inode::write_extent_header_slice(&mut buf, &nh);
        // The surviving node block changed (entries / trimmed extent) →
        // restamp its extent-tail csum on write.
        self.write_extent_block(ino, gen, lba, &mut buf)?;
        Ok(entries == 0)
    }

    /// Free every block under (and including) the metadata block at `lba`:
    /// all data blocks at the leaves + every interior/leaf metadata block.
    /// # C: O(subtree) block I/Os
    pub(super) fn free_subtree(&self, lba: u64, depth: u16) -> Result<(), MountError> {
        let bs = self.sb.block_size as usize;
        let buf = read_byte_range_pub(&*self.dev, lba * bs as u64, bs)?;
        let hdr = inode::parse_extent_header_slice(&buf)?;
        if depth == 0 {
            for i in 0..hdr.entries {
                let e = inode::parse_inline_extent_slice(&buf, &hdr, i).ok_or(MountError::NotFound)?;
                for k in 0..e.len as u64 { let _ = self.free_block(e.start_lba() + k); }
            }
        } else {
            for i in 0..hdr.entries {
                let idx = inode::parse_extent_idx_slice(&buf, &hdr, i).ok_or(MountError::NotFound)?;
                self.free_subtree(idx.leaf_lba(), depth - 1)?;
            }
        }
        let _ = self.free_block(lba);
        Ok(())
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
                    s = s.saturating_add((e.len as u32) * spb);
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
        let bs = self.sb.block_size as usize;
        let buf = read_byte_range_pub(&*self.dev, lba * bs as u64, bs)?;
        let hdr = inode::parse_extent_header_slice(&buf)?;
        let spb = self.sb.block_size / 512;
        let mut s = 0u32;
        if depth == 0 {
            for i in 0..hdr.entries {
                if let Some(e) = inode::parse_inline_extent_slice(&buf, &hdr, i) {
                    s = s.saturating_add((e.len as u32) * spb);
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
