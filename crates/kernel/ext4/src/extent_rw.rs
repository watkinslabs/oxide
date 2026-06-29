// File-data RW path: append, sparse allocation, write, and truncate.
// Allocation inserts extents in logical-block order, grows adjacent physical
// runs when possible, and splits inline/external extent nodes instead of
// relying on append-only metadata layout.

use crate::inode::{self, Extent, I_BLOCK_LEN};
use crate::mount::{Mount, MountError, write_byte_range, read_byte_range_pub};

extern crate alloc;
use alloc::vec::Vec;

const EXT4_MAX_EXTENT_DEPTH: u16 = 5;

struct ExtentInsertResult {
    first_block: u32,
    split: Option<inode::ExtentIdx>,
    extra_meta_sectors: u32,
}

impl Mount {
    /// Append `data` to the file at `ino`. `data.len()` must equal
    /// `sb.block_size` (the FS-block-granular interface). Allocates
    /// one fresh block, writes the bytes, and either extends the
    /// trailing extent or adds a new inline leaf. Updates inode
    /// `i_size` + writes the mutated inode bytes back to disk.
    ///
    /// Returns the file-relative logical block index that was
    /// just appended (== prior `(i_size + bs - 1) / bs`).
    /// # C: O(N_extents) + 1 alloc + 2 block I/Os (data + inode)
    pub fn append_block(&self, ino: u32, data: &[u8]) -> Result<u32, MountError> {
        self.run_journaled(|m| m.append_block_inner(ino, data))
    }

    fn append_block_inner(&self, ino: u32, data: &[u8]) -> Result<u32, MountError> {
        let bs = self.sb.block_size as usize;
        if data.len() != bs {
            return Err(MountError::Inode(inode::InodeError::BadLen));
        }
        let (mut ino_bytes, ino_byte_off) = self.read_inode_bytes(ino)?;
        let cur_size = u32::from_le_bytes([ino_bytes[0x04], ino_bytes[0x05], ino_bytes[0x06], ino_bytes[0x07]]) as u64
            | ((u32::from_le_bytes([ino_bytes[0x6C], ino_bytes[0x6D], ino_bytes[0x6E], ino_bytes[0x6F]]) as u64) << 32);
        let new_logical = ((cur_size + bs as u64 - 1) / bs as u64) as u32;
        let new_size = cur_size + bs as u64;
        self.insert_logical_block_with_inode_bytes(ino, &mut ino_bytes, ino_byte_off, new_logical, data, new_size)
    }

    fn append_logical_block_inner(&self, ino: u32, logical: u32, data: &[u8], new_size: u64) -> Result<u32, MountError> {
        let bs = self.sb.block_size as usize;
        if data.len() != bs {
            return Err(MountError::Inode(inode::InodeError::BadLen));
        }
        let (mut ino_bytes, ino_byte_off) = self.read_inode_bytes(ino)?;
        self.insert_logical_block_with_inode_bytes(ino, &mut ino_bytes, ino_byte_off, logical, data, new_size)
    }

    fn insert_logical_block_with_inode_bytes(
        &self,
        ino: u32,
        ino_bytes: &mut alloc::vec::Vec<u8>,
        ino_byte_off: u64,
        logical: u32,
        data: &[u8],
        new_size: u64,
    ) -> Result<u32, MountError> {
        let mut i_block: [u8; I_BLOCK_LEN] = {
            let mut b = [0u8; I_BLOCK_LEN];
            b.copy_from_slice(&ino_bytes[0x28..0x28 + I_BLOCK_LEN]);
            b
        };
        let hdr = inode::parse_extent_header(&i_block)?;
        if hdr.depth > EXT4_MAX_EXTENT_DEPTH { return Err(MountError::DepthUnsupported); }
        if hdr.depth == 0 {
            return self.insert_inline_sorted(ino, ino_bytes, ino_byte_off, &mut i_block, hdr, new_size, logical, data);
        }

        let bs = self.sb.block_size as usize;
        let gen = Self::inode_generation(ino_bytes);
        let leaf_extents = self.leaf_extents_for_insert(&i_block, &hdr, logical)?;
        if Self::extent_vec_contains(&leaf_extents, logical) {
            return Ok(logical);
        }

        let hint_group = Self::extent_hint_group(self, &leaf_extents, logical);
        let phys = self.alloc_block(hint_group)?;
        write_byte_range(&*self.dev, phys * bs as u64, data)?;
        let new_extent = Self::extent_for(logical, phys);

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

    fn insert_into_inline_root(
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

    fn insert_into_extent_node(
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

    fn leaf_extents_for_insert(
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

    fn insert_would_exceed_max_depth(
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

    fn insert_inline_sorted(
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

    fn extent_for(logical: u32, phys: u64) -> Extent {
        Extent {
            block: logical,
            len: 1,
            start_hi: (phys >> 32) as u16,
            start_lo: (phys & 0xFFFF_FFFF) as u32,
        }
    }

    fn idx_for_lba(block: u32, lba: u64) -> inode::ExtentIdx {
        inode::ExtentIdx {
            block,
            leaf_lo: (lba & 0xFFFF_FFFF) as u32,
            leaf_hi: (lba >> 32) as u16,
            _unused: 0,
        }
    }

    fn extent_end(e: &Extent) -> u64 {
        e.block as u64 + e.len as u64
    }

    fn extent_vec_contains(extents: &[Extent], logical: u32) -> bool {
        extents.iter().any(|e| {
            logical as u64 >= e.block as u64 && (logical as u64) < Self::extent_end(e)
        })
    }

    fn extent_hint_group(&self, extents: &[Extent], logical: u32) -> u32 {
        if let Some(e) = extents.iter().rev().find(|e| e.block <= logical) {
            self.group_of_block(e.start_lba())
        } else if let Some(e) = extents.first() {
            self.group_of_block(e.start_lba())
        } else {
            0
        }
    }

    fn can_merge(a: &Extent, b: &Extent) -> bool {
        Self::extent_end(a) == b.block as u64
            && a.start_lba() + a.len as u64 == b.start_lba()
            && (a.len as u32 + b.len as u32) <= EXTENT_LEN_MAX as u32
    }

    fn insert_extent_record(extents: &mut Vec<Extent>, new_extent: Extent) -> Result<(), MountError> {
        let new_start = new_extent.block as u64;
        let new_end = Self::extent_end(&new_extent);
        for e in extents.iter() {
            if new_start < Self::extent_end(e) && (e.block as u64) < new_end {
                return Err(MountError::NotFound);
            }
        }
        extents.push(new_extent);
        extents.sort_by_key(|e| e.block);

        let mut merged: Vec<Extent> = Vec::with_capacity(extents.len());
        for e in extents.iter().copied() {
            if let Some(last) = merged.last_mut() {
                if Self::can_merge(last, &e) {
                    last.len = last.len.saturating_add(e.len);
                    continue;
                }
            }
            merged.push(e);
        }
        *extents = merged;
        Ok(())
    }

    fn inline_extents(i_block: &[u8; I_BLOCK_LEN], hdr: &inode::ExtentHeader) -> Result<Vec<Extent>, MountError> {
        let mut extents = Vec::with_capacity(hdr.entries as usize);
        for i in 0..hdr.entries {
            extents.push(inode::parse_inline_extent(i_block, hdr, i).ok_or(MountError::NotFound)?);
        }
        extents.sort_by_key(|e| e.block);
        Ok(extents)
    }

    fn slice_extents(buf: &[u8], hdr: &inode::ExtentHeader) -> Result<Vec<Extent>, MountError> {
        let mut extents = Vec::with_capacity(hdr.entries as usize);
        for i in 0..hdr.entries {
            extents.push(inode::parse_inline_extent_slice(buf, hdr, i).ok_or(MountError::NotFound)?);
        }
        extents.sort_by_key(|e| e.block);
        Ok(extents)
    }

    fn inline_indices(i_block: &[u8; I_BLOCK_LEN], hdr: &inode::ExtentHeader) -> Result<Vec<inode::ExtentIdx>, MountError> {
        let mut idxs = Vec::with_capacity(hdr.entries as usize);
        for i in 0..hdr.entries {
            idxs.push(inode::parse_extent_idx(i_block, hdr, i).ok_or(MountError::NotFound)?);
        }
        idxs.sort_by_key(|idx| idx.block);
        Ok(idxs)
    }

    fn slice_indices(buf: &[u8], hdr: &inode::ExtentHeader) -> Result<Vec<inode::ExtentIdx>, MountError> {
        let mut idxs = Vec::with_capacity(hdr.entries as usize);
        for i in 0..hdr.entries {
            idxs.push(inode::parse_extent_idx_slice(buf, hdr, i).ok_or(MountError::NotFound)?);
        }
        idxs.sort_by_key(|idx| idx.block);
        Ok(idxs)
    }

    fn write_inline_extents(i_block: &mut [u8; I_BLOCK_LEN], mut hdr: inode::ExtentHeader, extents: &[Extent]) {
        for b in i_block.iter_mut() { *b = 0; }
        hdr.entries = extents.len() as u16;
        hdr.depth = 0;
        inode::write_extent_header(i_block, &hdr);
        for (i, e) in extents.iter().enumerate() {
            inode::write_inline_extent(i_block, i as u16, e);
        }
    }

    fn write_slice_extents(buf: &mut [u8], mut hdr: inode::ExtentHeader, extents: &[Extent]) {
        for b in buf.iter_mut() { *b = 0; }
        hdr.entries = extents.len() as u16;
        hdr.depth = 0;
        inode::write_extent_header_slice(buf, &hdr);
        for (i, e) in extents.iter().enumerate() {
            inode::write_inline_extent_slice(buf, i as u16, e);
        }
    }

    fn write_inline_indices(i_block: &mut [u8; I_BLOCK_LEN], mut hdr: inode::ExtentHeader, idxs: &[inode::ExtentIdx]) {
        for b in i_block.iter_mut() { *b = 0; }
        hdr.entries = idxs.len() as u16;
        inode::write_extent_header(i_block, &hdr);
        for (i, idx) in idxs.iter().enumerate() {
            inode::write_extent_idx(i_block, i as u16, idx);
        }
    }

    fn write_slice_indices(buf: &mut [u8], mut hdr: inode::ExtentHeader, idxs: &[inode::ExtentIdx]) {
        for b in buf.iter_mut() { *b = 0; }
        hdr.entries = idxs.len() as u16;
        inode::write_extent_header_slice(buf, &hdr);
        for (i, idx) in idxs.iter().enumerate() {
            inode::write_extent_idx_slice(buf, i as u16, idx);
        }
    }

    fn inline_child_index_for_insert(i_block: &[u8; I_BLOCK_LEN], hdr: &inode::ExtentHeader, logical: u32)
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

    fn slice_child_index_for_insert(buf: &[u8], hdr: &inode::ExtentHeader, logical: u32)
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

    fn split_extents_for_leaf(extents: &[Extent]) -> (Vec<Extent>, Vec<Extent>) {
        let split = extents.len() / 2;
        (extents[..split].to_vec(), extents[split..].to_vec())
    }

    fn split_indices_for_node(idxs: &[inode::ExtentIdx]) -> (Vec<inode::ExtentIdx>, Vec<inode::ExtentIdx>) {
        let split = idxs.len() / 2;
        (idxs[..split].to_vec(), idxs[split..].to_vec())
    }

    /// Splice the (possibly mutated) i_block + new size + i_blocks
    /// back into `ino_bytes` and write the inode slot (csum-stamped).
    /// `extra_meta_sectors` is the count of newly-allocated extent-tree
    /// metadata blocks (leaf/interior) this append created, expressed in
    /// 512-byte sectors — added to i_blocks alongside the one data block,
    /// matching Linux which counts metadata blocks in i_blocks.
    fn persist_inode_after_append(
        &self, ino: u32, ino_bytes: &mut alloc::vec::Vec<u8>, _ino_byte_off: u64,
        i_block: &[u8; I_BLOCK_LEN], new_size: u64, extra_meta_sectors: u32,
    ) -> Result<(), MountError> {
        ino_bytes[0x28..0x28 + I_BLOCK_LEN].copy_from_slice(i_block);
        ino_bytes[0x04..0x08].copy_from_slice(&((new_size & 0xFFFF_FFFF) as u32).to_le_bytes());
        ino_bytes[0x6C..0x70].copy_from_slice(&((new_size >> 32) as u32).to_le_bytes());
        let prev_i_blocks = u32::from_le_bytes([ino_bytes[0x1C], ino_bytes[0x1D], ino_bytes[0x1E], ino_bytes[0x1F]]);
        let added_sectors = (self.sb.block_size / 512) as u32 + extra_meta_sectors;
        let new_i_blocks = prev_i_blocks.saturating_add(added_sectors);
        ino_bytes[0x1C..0x20].copy_from_slice(&new_i_blocks.to_le_bytes());
        self.write_inode_bytes(ino, ino_bytes)
    }

    /// Read the raw on-disk inode slot bytes for `ino`. Returns the
    /// bytes + the byte offset they were read from (so the caller
    /// can write the mutated buffer back to the same slot).
    /// # C: O(1) I/O
    pub fn read_inode_bytes(&self, ino: u32) -> Result<(Vec<u8>, u64), MountError> {
        let (group, idx) = crate::gdt::locate_inode(&self.sb, ino)?;
        let gd = self.group_desc(group)?;
        let off_in_table = (idx as u64) * (self.sb.inode_size as u64);
        let byte_off = gd.inode_table * (self.sb.block_size as u64) + off_in_table;
        let bytes = self.read_meta_byte_range(byte_off, self.sb.inode_size as usize)?;
        Ok((bytes, byte_off))
    }

    /// Write a freshly-mutated inode-bytes slot back to disk. Stamps
    /// the metadata_csum (`i_checksum_lo`/`_hi`) before writing so the
    /// slot is valid for stock Linux/e2fsck (no-op without the feature).
    /// # C: O(inode_size) csum + O(1) I/O
    pub fn write_inode_bytes(&self, ino: u32, bytes: &[u8]) -> Result<(), MountError> {
        let (group, idx) = crate::gdt::locate_inode(&self.sb, ino)?;
        let gd = self.group_desc(group)?;
        let off_in_table = (idx as u64) * (self.sb.inode_size as u64);
        let byte_off = gd.inode_table * (self.sb.block_size as u64) + off_in_table;
        if bytes.len() != self.sb.inode_size as usize {
            return Err(MountError::Inode(inode::InodeError::BadLen));
        }
        let mut owned = bytes.to_vec();
        crate::csum::stamp_inode_csum(&self.sb, ino, &mut owned);
        // Inode bytes are metadata — route through journaled path.
        self.metadata_write(byte_off, &owned)
    }

    /// Stamp the `ext4_extent_tail` csum into an external extent
    /// block buffer and write it (journaled). The inline i_block
    /// extent root has no tail — it rides the inode csum — so this
    /// is only for allocated leaf/interior blocks.
    /// # C: O(bs) csum + 1 block I/O
    pub(crate) fn write_extent_block(&self, ino: u32, gen: u32, lba: u64, buf: &mut Vec<u8>)
        -> Result<(), MountError>
    {
        let _ = ino;
        crate::csum::stamp_extent_block_csum(&self.sb, ino, gen, buf);
        let bs = self.sb.block_size as u64;
        self.metadata_write(lba * bs, buf)
    }

    /// Read this inode's on-disk `i_generation` (csum keying input).
    /// # C: O(1)
    fn inode_generation(ino_bytes: &[u8]) -> u32 {
        u32::from_le_bytes([ino_bytes[0x64], ino_bytes[0x65], ino_bytes[0x66], ino_bytes[0x67]])
    }

    /// Group containing a given physical block. Inverse of
    /// `group_first_block`.
    /// # C: O(1)
    pub fn group_of_block(&self, phys: u64) -> u32 {
        let bpg = self.sb.blocks_per_group as u64;
        if bpg == 0 { return 0; }
        let rel = phys.saturating_sub(self.sb.first_data_block as u64);
        (rel / bpg) as u32
    }

    /// Collect this inode's leaf extents as `(first_logical_block, len_blocks)`
    /// runs, ascending by logical block — descending ANY number of interior
    /// extent-index levels (Linux `ext4_find_extent` over the whole tree). An
    /// extent's `ee_len > EXTENT_LEN_MAX` marks an UNWRITTEN (preallocated)
    /// extent; its real length is `ee_len - EXTENT_LEN_MAX`. Unwritten extents
    /// are allocated space, so they count as DATA for `SEEK_HOLE`/`SEEK_DATA`.
    /// Gaps between consecutive runs are holes. Drives the ext4
    /// `seek_hole_data` override.
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
    fn collect_subtree_extents(&self, lba: u64, out: &mut Vec<(u32, u32)>)
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
    fn extent_real_len(ee_len: u16) -> u32 {
        (if ee_len > EXTENT_LEN_MAX { ee_len - EXTENT_LEN_MAX } else { ee_len }) as u32
    }
}

/// Cap per ext4 spec: an extent's `ee_len` is 16 bits, but the
/// top bit signals "uninitialized"; usable max is 0x8000.
pub const EXTENT_LEN_MAX: u16 = 0x8000;

impl Mount {
    /// Patch the on-disk inode `i_size` field directly, without
    /// touching extents or block counters. Used after a partial-
    /// final-block append to reflect the true byte length.
    /// # C: O(1) I/O
    pub fn set_inode_size(&self, ino: u32, size: u64) -> Result<(), MountError> {
        let (mut bytes, _off) = self.read_inode_bytes(ino)?;
        bytes[0x04..0x08].copy_from_slice(&((size & 0xFFFF_FFFF) as u32).to_le_bytes());
        bytes[0x6C..0x70].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
        self.write_inode_bytes(ino, &bytes)
    }

    /// Random-access write: `data` lands at byte offset `off` in
    /// the file at `ino`, extending the file (with zero-filled
    /// blocks if needed) when `off + data.len() > i_size`. Existing
    /// blocks touched by the write are RMW'd in-place. The trailing
    /// `i_size` is set to `max(prev_size, off + data.len())`.
    /// Caller invalidates any page cache.
    /// # C: O(file growth + N_blocks_in_range) I/O
    pub fn write_at(&self, ino: u32, off: u64, data: &[u8]) -> Result<(), MountError> {
        self.run_journaled(|m| m.write_at_inner(ino, off, data))
    }

    /// Allocate backing blocks through `offset + len`. With `keep_size`, the
    /// original `i_size` is restored after allocation without freeing extents.
    /// # C: O(file growth)
    pub fn fallocate_inode(&self, ino: u32, offset: u64, len: u64, keep_size: bool) -> Result<(), MountError> {
        let end = offset.checked_add(len).ok_or(MountError::Inode(inode::InodeError::BadLen))?;
        if len == 0 { return Ok(()); }
        self.run_journaled(|m| {
            let old_size = m.read_inode(ino)?.size;
            let bs = m.sb.block_size as u64;
            let first_lb64 = offset / bs;
            let last_lb64 = (end - 1) / bs;
            if first_lb64 > u32::MAX as u64 || last_lb64 > u32::MAX as u64 {
                return Err(MountError::Inode(inode::InodeError::BadLen));
            }
            let first_lb = first_lb64 as u32;
            let last_lb = last_lb64 as u32;
            let final_size = if keep_size { old_size } else { core::cmp::max(old_size, end) };
            let zero_blk = alloc::vec![0u8; bs as usize];

            for lb in first_lb..=last_lb {
                let inode = m.read_inode(ino)?;
                let visible_size = core::cmp::max(inode.size, (lb as u64 + 1) * bs);
                m.append_logical_block_inner(ino, lb, &zero_blk, visible_size)?;
            }
            m.set_inode_size(ino, final_size)?;
            Ok(())
        })
    }

    fn write_at_inner(&self, ino: u32, off: u64, data: &[u8]) -> Result<(), MountError> {
        let bs = self.sb.block_size as u64;
        let bs_us = bs as usize;
        if data.is_empty() { return Ok(()); }
        let inode = self.read_inode(ino)?;
        let cur_size = inode.size;
        let end = off + data.len() as u64;
        let new_size = core::cmp::max(cur_size, end);
        let cur_blocks = (cur_size + bs - 1) / bs;
        let new_blocks = (new_size + bs - 1) / bs;
        // Phase 1: zero-extend file to new_blocks worth of blocks.
        let zero_blk = alloc::vec![0u8; bs_us];
        for _ in cur_blocks..new_blocks {
            self.append_block(ino, &zero_blk)?;
        }
        // Phase 2: RMW each touched block. Re-read inode (extents
        // changed during phase 1).
        let inode2 = self.read_inode(ino)?;
        let first_lb = (off / bs) as u32;
        let last_lb  = ((end - 1) / bs) as u32;
        let mut written = 0usize;
        for lb in first_lb..=last_lb {
            let blk_start_byte = (lb as u64) * bs;
            let in_blk_off = if blk_start_byte >= off { 0usize }
                             else { (off - blk_start_byte) as usize };
            let blk_end_byte = blk_start_byte + bs;
            let copy_end_in_blk = if end >= blk_end_byte { bs_us }
                                  else { (end - blk_start_byte) as usize };
            let copy_len = copy_end_in_blk - in_blk_off;
            let mut blk = self.read_file_block(&inode2, lb)?;
            if blk.len() < bs_us { blk.resize(bs_us, 0); }
            blk[in_blk_off..in_blk_off + copy_len]
                .copy_from_slice(&data[written .. written + copy_len]);
            self.write_file_block(&inode2, lb, &blk)?;
            written += copy_len;
        }
        // Phase 3: persist the (potentially partial-block) i_size.
        self.set_inode_size(ino, new_size)?;
        Ok(())
    }

    /// Truncate `ino` to `new_len` bytes. Frees trailing whole
    /// blocks; updates the trailing extent's `len` (or removes
    /// extent leaves) when `new_len` falls before its current end.
    /// Inline-only (depth=0). Larger files (multi-leaf) are
    /// handled by walking + freeing leaves from the tail.
    /// # C: O(N_extents) + N_blocks_freed I/O
    pub fn truncate_inode(&self, ino: u32, new_len: u64) -> Result<(), MountError> {
        self.run_journaled(|m| m.truncate_inode_inner(ino, new_len))
    }

    fn truncate_inode_inner(&self, ino: u32, new_len: u64) -> Result<(), MountError> {
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
    fn truncate_interior_inline(&self, ino: u32, gen: u32, i_block: &mut [u8; I_BLOCK_LEN],
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
    fn truncate_node(&self, ino: u32, gen: u32, lba: u64, depth: u16, blocks_keep: u64) -> Result<bool, MountError> {
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
    fn free_subtree(&self, lba: u64, depth: u16) -> Result<(), MountError> {
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
    fn count_all_sectors(&self, i_block: &[u8; I_BLOCK_LEN]) -> Result<u32, MountError> {
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

    fn count_all_sectors_node(&self, lba: u64, depth: u16) -> Result<u32, MountError> {
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

    /// Bump (or decrement) the link count of an inode by `delta`.
    /// Saturating; never goes negative — caller is responsible for
    /// only freeing the inode when the count reaches 0 via
    /// `unlink`.
    /// # C: O(1) I/O
    pub fn adjust_nlink(&self, ino: u32, delta: i32) -> Result<u16, MountError> {
        let (mut bytes, off) = self.read_inode_bytes(ino)?;
        let cur = u16::from_le_bytes([bytes[0x1A], bytes[0x1B]]);
        let new = if delta >= 0 {
            cur.saturating_add(delta as u16)
        } else {
            cur.saturating_sub((-delta) as u16)
        };
        bytes[0x1A..0x1C].copy_from_slice(&new.to_le_bytes());
        let _ = off;
        self.write_inode_bytes(ino, &bytes)?;
        Ok(new)
    }
}
