use alloc::vec;
use alloc::vec::Vec;

use crate::inode::{self, Inode};
use crate::mount::{Mount, MountError};

const DIRECT_BLOCKS: u32 = 12;

impl Mount {
    pub(crate) fn fallocate_legacy_inode_inner(
        &self, ino: u32, offset: u64, len: u64, keep_size: bool,
    ) -> Result<(), MountError> {
        if len == 0 { return Ok(()); }
        let bs = self.sb.block_size as u64;
        let old_size = self.read_inode(ino)?.size;
        let end = offset.checked_add(len)
            .ok_or(MountError::Inode(inode::InodeError::BadLen))?;
        let first = offset / bs;
        let last = end.saturating_add(bs - 1) / bs;
        let zero = vec![0u8; bs as usize];
        for logical in first..last {
            let current = self.read_inode(ino)?;
            match self.resolve_pblock(&current, logical as u32) {
                Ok(_) => {}
                Err(MountError::NotFound) => self.write_at_inner(ino, logical * bs, &zero, None)?,
                Err(error) => return Err(error),
            }
        }
        let final_size = if keep_size { old_size } else { core::cmp::max(old_size, end) };
        self.set_inode_size(ino, final_size)?;
        Ok(())
    }

    pub(crate) fn punch_legacy_inode_inner(
        &self, ino: u32, offset: u64, len: u64,
    ) -> Result<(), MountError> {
        if len == 0 { return Ok(()); }
        let bs = self.sb.block_size as u64;
        let inode = self.read_inode(ino)?;
        let end = core::cmp::min(
            offset.checked_add(len).ok_or(MountError::Inode(inode::InodeError::BadLen))?,
            inode.size,
        );
        if offset >= end { return Ok(()); }
        self.release_inode_prealloc(ino)?;
        let first_full = offset.div_ceil(bs);
        let last_full = end / bs;
        for logical in [offset / bs, end.saturating_sub(1) / bs] {
            if logical >= first_full && logical < last_full { continue; }
            let logical = logical as u32;
            let Ok(phys) = self.resolve_pblock(&inode, logical) else { continue; };
            let mut block = self.read_file_block(&inode, logical)?;
            let start = if logical as u64 == offset / bs { (offset % bs) as usize } else { 0 };
            let finish = if logical as u64 == end.saturating_sub(1) / bs { (end % bs) as usize } else { bs as usize };
            if start < finish { block[start..finish].fill(0); self.write_data_byte_range(phys * bs, &block)?; }
        }
        if first_full >= last_full { return Ok(()); }

        let ptrs = self.sb.block_size / 4;
        let mut raw = self.read_inode_bytes(ino)?.0;
        let mut data_free = Vec::new();
        let mut meta_free = Vec::new();
        for logical64 in first_full..last_full {
            let logical = logical64 as u32;
            let Ok(phys) = self.resolve_pblock(&inode, logical) else { continue; };
            self.clear_legacy_mapping(&mut raw, logical, ptrs, &mut meta_free)?;
            data_free.push(phys);
        }
        let old_sectors = inode.i_blocks as u32;
        let freed = data_free.len().saturating_add(meta_free.len()) as u32;
        let new_sectors = old_sectors.saturating_sub(freed.saturating_mul(self.sb.sectors_per_block()));
        self.account_i_blocks_delta(ino, old_sectors, new_sectors)?;
        raw[0x1C..0x20].copy_from_slice(&new_sectors.to_le_bytes());
        if let Err(error) = self.write_inode_bytes_data(ino, &raw) {
            return Err(self.rollback_i_blocks_delta(ino, new_sectors, old_sectors, error));
        }
        for block in data_free.into_iter().chain(meta_free.into_iter()) { self.free_block(block)?; }
        Ok(())
    }

    fn clear_legacy_mapping(
        &self, raw: &mut [u8], logical: u32, ptrs: u32,
        meta_free: &mut Vec<u64>,
    ) -> Result<(), MountError> {
        let (depth, indexes) = Self::legacy_path(logical, ptrs)?;
        if depth == 0 {
            let off = 0x28 + logical as usize * 4;
            raw[off..off + 4].fill(0);
            return Ok(());
        }
        let root_off = 0x28 + (12 + depth - 1) * 4;
        let root = u32::from_le_bytes([raw[root_off], raw[root_off + 1], raw[root_off + 2], raw[root_off + 3]]) as u64;
        if root == 0 { return Ok(()); }
        let mut nodes: Vec<(u64, Vec<u8>, usize)> = Vec::new();
        let mut current = root;
        for level in 0..depth {
            let table = self.read_metadata_block(current)?;
            let slot = indexes[level] as usize;
            let off = slot * 4;
            let child = u32::from_le_bytes([table[off], table[off + 1], table[off + 2], table[off + 3]]) as u64;
            if child == 0 { return Ok(()); }
            nodes.push((current, table, slot));
            current = child;
        }
        let data = current;
        self.check_inode_blocks(data, 1)?;
        let mut child_empty = true;
        for (lba, mut table, slot) in nodes.into_iter().rev() {
            let off = slot * 4;
            if child_empty { table[off..off + 4].fill(0); }
            let empty = table.chunks_exact(4).all(|p| p == [0, 0, 0, 0]);
            if empty {
                meta_free.push(lba);
                child_empty = true;
            } else {
                self.metadata_write(lba * self.sb.block_size as u64, &table)?;
                child_empty = false;
                break;
            }
        }
        if child_empty { raw[root_off..root_off + 4].fill(0); }
        Ok(())
    }

    pub(crate) fn truncate_legacy_inode_inner(
        &self, ino: u32, new_len: u64, meta: Option<super::meta::InodeMetaUpdate>,
        account_quota: bool,
    ) -> Result<(), MountError> {
        let bs = self.sb.block_size as u64;
        let inode = self.read_inode(ino)?;
        if new_len >= inode.size {
            if new_len == inode.size { return Ok(()); }
            return self.write_at_inner(ino, new_len - 1, &[0], meta);
        }
        if new_len % bs != 0 && new_len != 0 {
            let logical = (new_len / bs) as u32;
            if let Ok(phys) = self.resolve_pblock(&inode, logical) {
                let mut block = self.read_file_block(&inode, logical)?;
                block[(new_len % bs) as usize..].fill(0);
                self.write_data_byte_range(phys * bs, &block)?;
            }
        }
        self.release_inode_prealloc(ino)?;
        let keep = new_len.saturating_add(bs - 1) / bs;
        let ptrs = self.sb.block_size / 4;
        let mut raw = self.read_inode_bytes(ino)?.0;
        let mut data_free = Vec::new();
        let mut meta_free = Vec::new();

        for logical in 0..DIRECT_BLOCKS {
            if u64::from(logical) >= keep {
                let off = 0x28 + logical as usize * 4;
                let phys = u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]) as u64;
                if phys != 0 { self.check_inode_blocks(phys, 1)?; data_free.push(phys); raw[off..off + 4].fill(0); }
            }
        }
        let starts = [
            (12usize, u64::from(DIRECT_BLOCKS), 1usize),
            (13usize, u64::from(DIRECT_BLOCKS) + u64::from(ptrs), 2usize),
            (14usize, u64::from(DIRECT_BLOCKS) + u64::from(ptrs) + u64::from(ptrs) * u64::from(ptrs), 3usize),
        ];
        for &(root_idx, base, depth) in &starts {
            let off = 0x28 + root_idx * 4;
            let root = u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]) as u64;
            if root == 0 { continue; }
            if self.prune_legacy_node(root, depth, base, keep, ptrs, &mut data_free, &mut meta_free)? {
                raw[off..off + 4].fill(0);
                meta_free.push(root);
            }
        }
        let freed = data_free.len().saturating_add(meta_free.len()) as u32;
        let old_sectors = inode.i_blocks as u32;
        let new_sectors = old_sectors.saturating_sub(freed.saturating_mul(self.sb.sectors_per_block()));
        if account_quota { self.account_i_blocks_delta(ino, old_sectors, new_sectors)?; }
        raw[0x04..0x08].copy_from_slice(&(new_len as u32).to_le_bytes());
        raw[0x6C..0x70].copy_from_slice(&((new_len >> 32) as u32).to_le_bytes());
        raw[0x1C..0x20].copy_from_slice(&new_sectors.to_le_bytes());
        if let Some(update) = meta { self.stamp_inode_meta_fields(&mut raw, update); }
        if let Err(error) = self.write_inode_bytes_data(ino, &raw) {
            return Err(if account_quota { self.rollback_i_blocks_delta(ino, new_sectors, old_sectors, error) } else { error });
        }
        for block in data_free.into_iter().chain(meta_free.into_iter()) {
            self.free_block(block)?;
        }
        Ok(())
    }

    fn prune_legacy_node(
        &self, lba: u64, level: usize, base: u64, keep: u64, ptrs: u32,
        data_free: &mut Vec<u64>, meta_free: &mut Vec<u64>,
    ) -> Result<bool, MountError> {
        let mut table = self.read_metadata_block(lba)?;
        let span = (0..level.saturating_sub(1)).fold(1u64, |v, _| v.saturating_mul(u64::from(ptrs)));
        let mut changed = false;
        for slot in 0..ptrs as usize {
            let off = slot * 4;
            let child = u32::from_le_bytes([table[off], table[off + 1], table[off + 2], table[off + 3]]) as u64;
            if child == 0 { continue; }
            let child_base = base.saturating_add(slot as u64 * span);
            if level == 1 {
                if child_base >= keep {
                    self.check_inode_blocks(child, 1)?;
                    data_free.push(child);
                    table[off..off + 4].fill(0);
                    changed = true;
                }
            } else {
                let remove = if child_base >= keep {
                    self.prune_legacy_node(child, level - 1, child_base, 0, ptrs, data_free, meta_free)?
                } else {
                    self.prune_legacy_node(child, level - 1, child_base, keep, ptrs, data_free, meta_free)?
                };
                if !remove { continue; }
                table[off..off + 4].fill(0);
                meta_free.push(child);
                changed = true;
            }
        }
        let empty = table.chunks_exact(4).all(|p| p == [0, 0, 0, 0]);
        if changed && !empty { self.metadata_write(lba * self.sb.block_size as u64, &table)?; }
        Ok(empty)
    }

    /// Write legacy ext2/3-style mappings without converting the inode to an
    /// extent tree. This is the Linux `ext4_ind_map_blocks` ownership boundary:
    /// build a complete missing branch, publish its last link only after every
    /// new block is ready, and leave the inode in the legacy format.
    ///
    /// The branch builder covers direct, single-, double-, and triple-indirect
    /// paths. # C: O(touched blocks × indirect depth)
    pub(super) fn write_legacy_at_inner(
        &self, ino: u32, off: u64, data: &[u8], meta: Option<super::meta::InodeMetaUpdate>,
    ) -> Result<(), MountError> {
        let bs = self.sb.block_size as u64;
        let bs_us = bs as usize;
        let mut inode = self.read_inode(ino)?;
        let end = off.checked_add(data.len() as u64)
            .ok_or(MountError::Inode(inode::InodeError::BadLen))?;
        let first = off / bs;
        let last = (end - 1) / bs;
        if last > u64::from(u32::MAX) { return Err(MountError::BadBlock); }
        let mut raw = self.read_inode_bytes(ino)?.0;
        let mut allocated = Vec::new();
        let old_sectors = inode.i_blocks as u32;
        let mut extra_blocks = 0u32;
        let mut written = 0usize;

        for logical64 in first..=last {
            let logical = logical64 as u32;
            let block_start = logical64 * bs;
            let in_off = if off > block_start { (off - block_start) as usize } else { 0 };
            let copy_end = core::cmp::min(bs, end.saturating_sub(block_start)) as usize;
            let copy_len = copy_end.saturating_sub(in_off);
            let mapped = match self.resolve_pblock(&inode, logical) {
                Ok(phys) => phys,
                Err(MountError::NotFound) => {
                    let (phys, metadata) = match self.allocate_legacy_branch(
                        ino, &mut raw, logical, &mut allocated) {
                        Ok(mapped) => mapped,
                        Err(error) => {
                            for &block in allocated.iter().rev() { let _ = self.free_block(block); }
                            return Err(error);
                        }
                    };
                    // Every missing branch contains one data block; metadata
                    // is returned separately so i_blocks charges both the
                    // leaf and any newly-created indirect nodes.
                    extra_blocks = extra_blocks.saturating_add(1).saturating_add(metadata);
                    inode = Inode::parse(&raw, &self.sb)?;
                    phys
                }
                Err(error) => {
                    return Err(error);
                }
            };
            let mut block = if in_off == 0 && copy_len == bs_us {
                vec![0u8; bs_us]
            } else {
                self.read_file_block(&inode, logical)?
            };
            block[in_off..in_off + copy_len]
                .copy_from_slice(&data[written..written + copy_len]);
            if let Err(error) = self.write_data_byte_range(mapped * bs, &block) {
                return self.rollback_legacy_allocations(&allocated, error);
            }
            written += copy_len;
        }

        let new_size = core::cmp::max(inode.size, end);
        raw[0x04..0x08].copy_from_slice(&(new_size as u32).to_le_bytes());
        raw[0x6C..0x70].copy_from_slice(&((new_size >> 32) as u32).to_le_bytes());
        if extra_blocks != 0 {
            let new_sectors = old_sectors.saturating_add(
                extra_blocks.saturating_mul(self.sb.sectors_per_block()));
            if let Err(error) = self.account_i_blocks_delta(ino, old_sectors, new_sectors) {
                return self.rollback_legacy_allocations(&allocated, error);
            }
            raw[0x1C..0x20].copy_from_slice(&new_sectors.to_le_bytes());
        }
        if let Some(update) = meta { self.stamp_inode_meta_fields(&mut raw, update); }
        if let Err(error) = self.write_inode_bytes_data(ino, &raw) {
            let charged = old_sectors.saturating_add(
                extra_blocks.saturating_mul(self.sb.sectors_per_block()));
            for &block in allocated.iter().rev() { let _ = self.free_block(block); }
            return Err(self.rollback_i_blocks_delta(ino, charged, old_sectors, error));
        }
        Ok(())
    }

    fn allocate_legacy_branch(
        &self, ino: u32, raw: &mut Vec<u8>, logical: u32, allocated: &mut Vec<u64>,
    ) -> Result<(u64, u32), MountError> {
        let ptrs = self.sb.block_size / 4;
        let (depth, indexes) = Self::legacy_path(logical, ptrs)?;
        if depth == 0 {
            let off = 0x28 + logical as usize * 4;
            let data = self.alloc_block_flags(0, self.data_reserve_flags(ino))?;
            if data > u64::from(u32::MAX) { let _ = self.free_block(data); return Err(MountError::BadBlock); }
            allocated.push(data);
            raw[off..off + 4].copy_from_slice(&(data as u32).to_le_bytes());
            return Ok((data, 0));
        }

        let root_off = 0x28 + (12 + depth - 1) * 4;
        let root = u32::from_le_bytes([
            raw[root_off], raw[root_off + 1], raw[root_off + 2], raw[root_off + 3],
        ]) as u64;
        let mut current = root;
        let mut missing = if root == 0 { Some(0usize) } else { None };
        for level in 0..depth {
            if missing.is_some() { break; }
            let table = self.read_metadata_block(current)?;
            let slot = indexes[level] as usize * 4;
            let child = u32::from_le_bytes([
                table[slot], table[slot + 1], table[slot + 2], table[slot + 3],
            ]) as u64;
            if child == 0 { missing = Some(level + 1); } else { current = child; }
        }
        let missing = missing.ok_or(MountError::NotFound)?;
        let mut new_blocks = Vec::new();
        let hint = self.group_of_block(current);
        for _level in missing..depth {
            let block = self.alloc_block_nofail(hint)?;
            if block > u64::from(u32::MAX) {
                let _ = self.free_block(block);
                return Err(MountError::BadBlock);
            }
            allocated.push(block);
            new_blocks.push(block);
        }
        let data = self.alloc_block_flags(hint, self.data_reserve_flags(ino))?;
        if data > u64::from(u32::MAX) {
            let _ = self.free_block(data);
            return Err(MountError::BadBlock);
        }
        allocated.push(data);
        new_blocks.push(data);

        // Prepare every newly allocated indirect node from the leaf upward.
        // This is ext4_alloc_branch's disconnected-branch invariant: no
        // reachable pointer is changed until all new blocks are initialized.
        for level in (missing..depth).rev() {
            let node_index = level - missing;
            let child = new_blocks[node_index + 1];
            let mut table = vec![0u8; self.sb.block_size as usize];
            let slot = indexes[level] as usize * 4;
            table[slot..slot + 4].copy_from_slice(&(child as u32).to_le_bytes());
            self.metadata_write(new_blocks[node_index] * self.sb.block_size as u64, &table)?;
        }

        let first_child = new_blocks[0];
        if missing == 0 {
            raw[root_off..root_off + 4].copy_from_slice(&(first_child as u32).to_le_bytes());
        } else {
            let parent_slot = indexes[missing - 1] as usize * 4;
            let mut table = self.read_metadata_block(current)?;
            table[parent_slot..parent_slot + 4].copy_from_slice(&(first_child as u32).to_le_bytes());
            self.metadata_write(current * self.sb.block_size as u64, &table)?;
        }
        Ok((data, (depth - missing) as u32))
    }

    fn legacy_path(logical: u32, ptrs: u32) -> Result<(usize, [u32; 3]), MountError> {
        if ptrs == 0 { return Err(MountError::BadBlock); }
        if logical < DIRECT_BLOCKS { return Ok((0, [logical, 0, 0])); }
        let mut n = logical - DIRECT_BLOCKS;
        if n < ptrs { return Ok((1, [n, 0, 0])); }
        n -= ptrs;
        let square = ptrs.checked_mul(ptrs).ok_or(MountError::BadBlock)?;
        if n < square { return Ok((2, [n / ptrs, n % ptrs, 0])); }
        n -= square;
        let cube = square.checked_mul(ptrs).ok_or(MountError::BadBlock)?;
        if n >= cube { return Err(MountError::NotFound); }
        Ok((3, [n / square, (n / ptrs) % ptrs, n % ptrs]))
    }

    fn rollback_legacy_allocations(
        &self, allocated: &[u64], error: MountError,
    ) -> Result<(), MountError> {
        for &block in allocated.iter().rev() { let _ = self.free_block(block); }
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{Mount, DIRECT_BLOCKS};

    #[test]
    fn legacy_path_uses_linux_direct_boundaries() {
        assert_eq!(Mount::legacy_path(0, 1024).unwrap(), (0, [0, 0, 0]));
        assert_eq!(Mount::legacy_path(DIRECT_BLOCKS, 1024).unwrap(), (1, [0, 0, 0]));
        assert_eq!(Mount::legacy_path(DIRECT_BLOCKS + 1024, 1024).unwrap(), (2, [0, 0, 0]));
        assert_eq!(Mount::legacy_path(DIRECT_BLOCKS + 1024 + 1024 * 1024, 1024).unwrap(), (3, [0, 0, 0]));
    }

    #[test]
    fn legacy_path_rejects_blocks_beyond_triple_indirect_capacity() {
        let ptrs = 1024u32;
        let max = DIRECT_BLOCKS + ptrs + ptrs * ptrs + ptrs * ptrs * ptrs;
        assert_eq!(Mount::legacy_path(max, ptrs), Err(crate::mount::MountError::NotFound));
    }
}
