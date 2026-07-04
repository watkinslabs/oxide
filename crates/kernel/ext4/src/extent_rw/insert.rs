use crate::inode::{self, Extent, I_BLOCK_LEN};
use crate::mount::{Mount, MountError, write_byte_range};
use alloc::vec::Vec;

use super::{EXT4_MAX_EXTENT_DEPTH, ExtentInsertResult};

impl Mount {
    pub(super) fn insert_into_inline_root(
        &self,
        ino: u32,
        gen: u32,
        i_block: &mut [u8; I_BLOCK_LEN],
        hdr: inode::ExtentHeader,
        logical: u32,
        new_extent: Extent,
        hint_group: u32,
    ) -> Result<u32, MountError> {
        let bs = self.sb.block_size as usize;
        let spb = (self.sb.block_size / 512) as u32;
        let child_n = Self::inline_child_index_for_insert(i_block, &hdr, logical)?;
        let child_idx = inode::parse_extent_idx(i_block, &hdr, child_n).ok_or(MountError::NotFound)?;
        let child = self.insert_into_extent_node(ino, gen, child_idx.leaf_lba(), hdr.depth - 1, logical, new_extent, hint_group)?;

        let mut idxs = Self::inline_indices(i_block, &hdr)?;
        idxs[child_n as usize].block = child.first_block;
        if let Some(right) = child.split {
            idxs.push(right);
        }
        idxs.sort_by_key(|idx| idx.block);

        let mut extra_meta_sectors = child.extra_meta_sectors;
        if idxs.len() <= hdr.max as usize {
            Self::write_inline_indices(i_block, hdr, &idxs);
            return Ok(extra_meta_sectors);
        }

        if hdr.depth >= EXT4_MAX_EXTENT_DEPTH {
            return Err(MountError::ExtentTreeFull);
        }

        let (left_idxs, right_idxs) = Self::split_indices_for_node(&idxs);
        let node_max = crate::csum::extent_block_max(&self.sb, bs);
        if left_idxs.len() > node_max as usize || right_idxs.len() > node_max as usize {
            return Err(MountError::ExtentTreeFull);
        }

        let left_lba = self.alloc_block(hint_group)?;
        let right_lba = self.alloc_block(hint_group)?;
        extra_meta_sectors += spb * 2;

        let mut left_buf = alloc::vec![0u8; bs];
        let left_hdr = inode::ExtentHeader {
            magic: inode::EXT4_EXT_MAGIC,
            entries: left_idxs.len() as u16,
            max: node_max,
            depth: hdr.depth,
            generation: 0,
        };
        Self::write_slice_indices(&mut left_buf, left_hdr, &left_idxs);
        self.write_extent_block(ino, gen, left_lba, &mut left_buf)?;

        let mut right_buf = alloc::vec![0u8; bs];
        let right_hdr = inode::ExtentHeader {
            magic: inode::EXT4_EXT_MAGIC,
            entries: right_idxs.len() as u16,
            max: node_max,
            depth: hdr.depth,
            generation: 0,
        };
        Self::write_slice_indices(&mut right_buf, right_hdr, &right_idxs);
        self.write_extent_block(ino, gen, right_lba, &mut right_buf)?;

        for b in i_block.iter_mut() { *b = 0; }
        let new_root_hdr = inode::ExtentHeader {
            magic: inode::EXT4_EXT_MAGIC,
            entries: 2,
            max: 4,
            depth: hdr.depth + 1,
            generation: 0,
        };
        inode::write_extent_header(i_block, &new_root_hdr);
        inode::write_extent_idx(i_block, 0, &Self::idx_for_lba(left_idxs[0].block, left_lba));
        inode::write_extent_idx(i_block, 1, &Self::idx_for_lba(right_idxs[0].block, right_lba));

        Ok(extra_meta_sectors)
    }

    pub(super) fn insert_into_extent_node(
        &self,
        ino: u32,
        gen: u32,
        lba: u64,
        depth: u16,
        logical: u32,
        new_extent: Extent,
        hint_group: u32,
    ) -> Result<ExtentInsertResult, MountError> {
        let bs = self.sb.block_size as usize;
        let spb = (self.sb.block_size / 512) as u32;
        let mut buf = self.read_metadata_block(lba)?;
        let hdr = inode::parse_extent_header_slice(&buf)?;
        if hdr.depth != depth {
            return Err(MountError::DepthUnsupported);
        }

        if depth == 0 {
            let mut extents = Self::slice_extents(&buf, &hdr)?;
            if Self::extent_vec_contains(&extents, logical) {
                return Ok(ExtentInsertResult {
                    first_block: extents.first().map(|e| e.block).unwrap_or(logical),
                    split: None,
                    extra_meta_sectors: 0,
                });
            }
            Self::insert_extent_record(&mut extents, new_extent)?;
            if extents.len() <= hdr.max as usize {
                let mut new_hdr = hdr;
                new_hdr.entries = extents.len() as u16;
                Self::write_slice_extents(&mut buf, new_hdr, &extents);
                self.write_extent_block(ino, gen, lba, &mut buf)?;
                return Ok(ExtentInsertResult {
                    first_block: extents[0].block,
                    split: None,
                    extra_meta_sectors: 0,
                });
            }

            let (left, right) = Self::split_extents_for_leaf(&extents);
            let mut left_hdr = hdr;
            left_hdr.entries = left.len() as u16;
            Self::write_slice_extents(&mut buf, left_hdr, &left);
            self.write_extent_block(ino, gen, lba, &mut buf)?;

            let right_lba = self.alloc_block(hint_group)?;
            let mut right_buf = alloc::vec![0u8; bs];
            let right_hdr = inode::ExtentHeader {
                magic: inode::EXT4_EXT_MAGIC,
                entries: right.len() as u16,
                max: hdr.max,
                depth: 0,
                generation: 0,
            };
            Self::write_slice_extents(&mut right_buf, right_hdr, &right);
            self.write_extent_block(ino, gen, right_lba, &mut right_buf)?;

            return Ok(ExtentInsertResult {
                first_block: left[0].block,
                split: Some(Self::idx_for_lba(right[0].block, right_lba)),
                extra_meta_sectors: spb,
            });
        }

        let child_n = Self::slice_child_index_for_insert(&buf, &hdr, logical)?;
        let child_idx = inode::parse_extent_idx_slice(&buf, &hdr, child_n).ok_or(MountError::NotFound)?;
        let child = self.insert_into_extent_node(
            ino,
            gen,
            child_idx.leaf_lba(),
            depth - 1,
            logical,
            new_extent,
            hint_group,
        )?;

        let mut idxs = Self::slice_indices(&buf, &hdr)?;
        idxs[child_n as usize].block = child.first_block;
        if let Some(right) = child.split {
            idxs.push(right);
        }
        idxs.sort_by_key(|idx| idx.block);

        let mut extra_meta_sectors = child.extra_meta_sectors;
        if idxs.len() <= hdr.max as usize {
            let mut new_hdr = hdr;
            new_hdr.entries = idxs.len() as u16;
            Self::write_slice_indices(&mut buf, new_hdr, &idxs);
            self.write_extent_block(ino, gen, lba, &mut buf)?;
            return Ok(ExtentInsertResult {
                first_block: idxs[0].block,
                split: None,
                extra_meta_sectors,
            });
        }

        let (left_idxs, right_idxs) = Self::split_indices_for_node(&idxs);
        let mut left_hdr = hdr;
        left_hdr.entries = left_idxs.len() as u16;
        Self::write_slice_indices(&mut buf, left_hdr, &left_idxs);
        self.write_extent_block(ino, gen, lba, &mut buf)?;

        let right_lba = self.alloc_block(hint_group)?;
        extra_meta_sectors += spb;
        let mut right_buf = alloc::vec![0u8; bs];
        let right_hdr = inode::ExtentHeader {
            magic: inode::EXT4_EXT_MAGIC,
            entries: right_idxs.len() as u16,
            max: hdr.max,
            depth,
            generation: 0,
        };
        Self::write_slice_indices(&mut right_buf, right_hdr, &right_idxs);
        self.write_extent_block(ino, gen, right_lba, &mut right_buf)?;

        Ok(ExtentInsertResult {
            first_block: left_idxs[0].block,
            split: Some(Self::idx_for_lba(right_idxs[0].block, right_lba)),
            extra_meta_sectors,
        })
    }

    pub(super) fn leaf_extents_for_insert(
        &self,
        i_block: &[u8; I_BLOCK_LEN],
        hdr: &inode::ExtentHeader,
        logical: u32,
    ) -> Result<Vec<Extent>, MountError> {
        if hdr.depth == 0 {
            return Self::inline_extents(i_block, hdr);
        }

        let mut child_lba = {
            let child_n = Self::inline_child_index_for_insert(i_block, hdr, logical)?;
            inode::parse_extent_idx(i_block, hdr, child_n).ok_or(MountError::NotFound)?.leaf_lba()
        };
        let mut depth = hdr.depth - 1;
        loop {
            let buf = self.read_metadata_block(child_lba)?;
            let child_hdr = inode::parse_extent_header_slice(&buf)?;
            if child_hdr.depth != depth {
                return Err(MountError::DepthUnsupported);
            }
            if depth == 0 {
                return Self::slice_extents(&buf, &child_hdr);
            }
            let child_n = Self::slice_child_index_for_insert(&buf, &child_hdr, logical)?;
            child_lba = inode::parse_extent_idx_slice(&buf, &child_hdr, child_n)
                .ok_or(MountError::NotFound)?
                .leaf_lba();
            depth -= 1;
        }
    }

    pub(super) fn insert_would_exceed_max_depth(
        &self,
        i_block: &[u8; I_BLOCK_LEN],
        hdr: &inode::ExtentHeader,
        logical: u32,
        inserted_leaf_entries: usize,
    ) -> Result<bool, MountError> {
        let mut ancestors: Vec<(u16, u16)> = Vec::new();
        ancestors.push((hdr.entries, hdr.max));

        let mut child_lba = {
            let child_n = Self::inline_child_index_for_insert(i_block, hdr, logical)?;
            inode::parse_extent_idx(i_block, hdr, child_n).ok_or(MountError::NotFound)?.leaf_lba()
        };
        let mut depth = hdr.depth - 1;
        loop {
            let buf = self.read_metadata_block(child_lba)?;
            let child_hdr = inode::parse_extent_header_slice(&buf)?;
            if child_hdr.depth != depth {
                return Err(MountError::DepthUnsupported);
            }
            if depth == 0 {
                if inserted_leaf_entries <= child_hdr.max as usize {
                    return Ok(false);
                }
                break;
            }
            ancestors.push((child_hdr.entries, child_hdr.max));
            let child_n = Self::slice_child_index_for_insert(&buf, &child_hdr, logical)?;
            child_lba = inode::parse_extent_idx_slice(&buf, &child_hdr, child_n)
                .ok_or(MountError::NotFound)?
                .leaf_lba();
            depth -= 1;
        }

        for (level, (entries, max)) in ancestors.iter().rev().enumerate() {
            if (*entries as usize) < (*max as usize) {
                return Ok(false);
            }
            if level == ancestors.len() - 1 {
                return Ok(hdr.depth >= EXT4_MAX_EXTENT_DEPTH);
            }
        }
        Ok(false)
    }

    pub(super) fn insert_inline_sorted(
        &self, ino: u32, ino_bytes: &mut alloc::vec::Vec<u8>, ino_byte_off: u64,
        i_block: &mut [u8; I_BLOCK_LEN], hdr: inode::ExtentHeader,
        new_size: u64, logical: u32, data: &[u8],
    ) -> Result<u32, MountError> {
        let bs = self.sb.block_size as usize;
        let gen = Self::inode_generation(ino_bytes);
        let spb = (self.sb.block_size / 512) as u32;
        let mut extents = Self::inline_extents(i_block, &hdr)?;
        if Self::extent_vec_contains(&extents, logical) {
            return Ok(logical);
        }
        let hint_group = Self::extent_hint_group(self, &extents, logical);
        let phys = self.alloc_block(hint_group)?;
        write_byte_range(&*self.dev, phys * bs as u64, data)?;
        Self::insert_extent_record(&mut extents, Self::extent_for(logical, phys))?;

        let mut extra_meta_sectors = 0;
        if extents.len() <= 4 {
            Self::write_inline_extents(i_block, hdr, &extents);
        } else {
            let leaf_max = crate::csum::extent_block_max(&self.sb, bs);
            if extents.len() > leaf_max as usize {
                return Err(MountError::ExtentTreeFull);
            }
            let leaf_lba = self.alloc_block(hint_group)?;
            extra_meta_sectors += spb;
            let mut leaf_buf = alloc::vec![0u8; bs];
            let leaf_hdr = inode::ExtentHeader {
                magic: inode::EXT4_EXT_MAGIC,
                entries: extents.len() as u16,
                max: leaf_max,
                depth: 0,
                generation: 0,
            };
            Self::write_slice_extents(&mut leaf_buf, leaf_hdr, &extents);
            self.write_extent_block(ino, gen, leaf_lba, &mut leaf_buf)?;
            for b in i_block.iter_mut() { *b = 0; }
            let root_hdr = inode::ExtentHeader {
                magic: inode::EXT4_EXT_MAGIC,
                entries: 1,
                max: 4,
                depth: 1,
                generation: 0,
            };
            inode::write_extent_header(i_block, &root_hdr);
            let idx0 = inode::ExtentIdx {
                block: extents[0].block,
                leaf_lo: (leaf_lba & 0xFFFF_FFFF) as u32,
                leaf_hi: (leaf_lba >> 32) as u16,
                _unused: 0,
            };
            inode::write_extent_idx(i_block, 0, &idx0);
        }
        self.persist_inode_after_append(ino, ino_bytes, ino_byte_off, i_block, new_size, extra_meta_sectors)?;
        Ok(logical)
    }

}
