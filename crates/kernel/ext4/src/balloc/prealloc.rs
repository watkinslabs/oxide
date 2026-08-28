//! Inode data-preallocation ownership.
//!
//! The bitmap reservation is durable metadata, but the tail has no inode
//! extent until a later regular-file write consumes it. Keeping that split
//! explicit prevents directory and metadata allocation from seeing a data PA
//! as an extent, while still letting the same inode reuse its next blocks.

use alloc::vec::Vec;

use crate::gdt;
use super::super::{Mount, MountError};

/// One contiguous tail reserved for regular-file data.
pub(crate) struct InodePrealloc {
    pub(crate) logical_start: u32,
    pub(crate) blocks: Vec<u64>,
    pub(crate) used: u32,
}

/// One contiguous tail reserved for any small regular-file allocation in a
/// block group. Unlike an inode PA it has no logical owner. # C: O(1)
pub(crate) struct GroupPrealloc {
    pub(crate) blocks: Vec<u64>,
}

impl Mount {
    /// Return the next physical blocks of an inode PA when the write begins
    /// exactly at its next logical block. # C: O(N PAs)
    pub(crate) fn peek_inode_prealloc(&self, ino: u32, logical: u32, want: u32)
        -> Option<Vec<u64>>
    {
        if want == 0 { return Some(Vec::new()); }
        let s = self.state.lock();
        let pas = s.inode_prealloc.get(&ino)?;
        pas.iter().find_map(|pa| {
            let next = pa.logical_start.checked_add(pa.used)?;
            if next != logical { return None; }
            let available = (pa.blocks.len() as u32).saturating_sub(pa.used);
            let take = core::cmp::min(want, available) as usize;
            Some(pa.blocks[pa.used as usize .. pa.used as usize + take].to_vec())
        })
    }

    /// Retire one block from an inode PA after its extent was published. # C: O(N PAs)
    pub(crate) fn consume_inode_prealloc(&self, ino: u32, logical: u32) -> bool {
        let mut s = self.state.lock();
        let Some(pas) = s.inode_prealloc.get_mut(&ino) else { return false; };
        let Some(idx) = pas.iter().position(|pa| {
            pa.logical_start.checked_add(pa.used) == Some(logical)
        }) else { return false; };
        pas[idx].used += 1;
        if pas[idx].used as usize == pas[idx].blocks.len() { pas.remove(idx); }
        if pas.is_empty() { s.inode_prealloc.remove(&ino); }
        true
    }

    /// Keep an unconsumed tail for this inode's next sequential write. # C: O(1)
    pub(crate) fn add_inode_prealloc(&self, ino: u32, logical_start: u32, blocks: Vec<u64>) {
        if blocks.is_empty() { return; }
        self.state.lock().inode_prealloc.entry(ino).or_default()
            .push(InodePrealloc { logical_start, blocks, used: 0 });
    }

    /// Return a reusable locality PA from the hinted group. # C: O(N PAs)
    pub(crate) fn peek_group_prealloc(&self, group: u32, want: u32) -> Option<Vec<u64>> {
        if want == 0 { return Some(Vec::new()); }
        let s = self.state.lock();
        s.group_prealloc.get(&group)?.iter().find_map(|pa| {
            if pa.blocks.len() < want as usize { return None; }
            Some(pa.blocks[..want as usize].to_vec())
        })
    }

    /// Retire the prefix of a reusable locality PA after mapping it. # C: O(N PAs)
    pub(crate) fn consume_group_prealloc(&self, group: u32, count: u32) -> bool {
        let mut s = self.state.lock();
        let Some(pas) = s.group_prealloc.get_mut(&group) else { return false; };
        let Some(idx) = pas.iter().position(|pa| pa.blocks.len() >= count as usize) else { return false; };
        pas[idx].blocks.drain(..count as usize);
        if pas[idx].blocks.is_empty() { pas.remove(idx); }
        if pas.is_empty() { s.group_prealloc.remove(&group); }
        true
    }

    /// Keep a locality tail for another small-file allocation. # C: O(1)
    pub(crate) fn add_group_prealloc(&self, group: u32, blocks: Vec<u64>) {
        if blocks.is_empty() { return; }
        self.state.lock().group_prealloc.entry(group).or_default()
            .push(GroupPrealloc { blocks });
    }

    /// Whether any locality-group PA is currently available. # C: O(1)
    /// Release all unconsumed inode PAs through the normal bitmap owner. # C: O(N PA blocks)
    pub(crate) fn release_inode_prealloc(&self, ino: u32) -> Result<(), MountError> {
        // Like Linux's inode preallocation list, these blocks are free in the
        // on-disk bitmap and reserved only in the in-memory buddy view.  Drop
        // the reservation; there is no bitmap transaction to perform here.
        let pas = self.state.lock().inode_prealloc.remove(&ino).unwrap_or_default();
        let mut released = Vec::new();
        for pa in pas {
            released.extend(pa.blocks.into_iter().skip(pa.used as usize));
        }
        let mut s = self.state.lock();
        for block in released {
            let Ok((group, bit)) = self.locate_block(block) else { continue };
            let Ok(gd) = gdt::parse_descriptor(&s.gdt_buf, group, &self.sb) else { continue };
            let off = gd.block_bitmap * self.sb.block_size as u64;
            if let Some(bitmap) = s.block_bitmap_cache.get_mut(&off) {
                bitmap[bit as usize >> 3] &= !(1 << (bit & 7));
                let order = super::scan::largest_free_order(bitmap, self.blocks_in_group(group));
                if let Some(order) = order { s.group_free_order.insert(group, order); }
                else { s.group_free_order.remove(&group); }
            }
        }
        Ok(())
    }

    /// Release every inode PA before the mount's final state disappears. # C: O(N PA blocks)
    pub(crate) fn release_all_inode_prealloc(&self) -> Result<(), MountError> {
        let inos: Vec<u32> = self.state.lock().inode_prealloc.keys().copied().collect();
        let mut first = None;
        for ino in inos {
            if let Err(e) = self.release_inode_prealloc(ino) {
                if first.is_none() { first = Some(e); }
            }
        }
        first.map_or(Ok(()), Err)
    }

    /// Release all reusable locality PAs by removing only their in-memory
    /// masks; the disk bitmap already records these blocks as free. # C: O(N PA blocks)
    pub(crate) fn release_all_group_prealloc(&self) -> Result<(), MountError> {
        let pas = core::mem::take(&mut self.state.lock().group_prealloc);
        let mut s = self.state.lock();
        for (_, entries) in pas {
            for pa in entries {
                for block in pa.blocks {
                    let Ok((group, bit)) = self.locate_block(block) else { continue };
                    let Ok(gd) = gdt::parse_descriptor(&s.gdt_buf, group, &self.sb) else { continue };
                    let off = gd.block_bitmap * self.sb.block_size as u64;
                    if let Some(bitmap) = s.block_bitmap_cache.get_mut(&off) {
                        bitmap[bit as usize >> 3] &= !(1 << (bit & 7));
                        let order = super::scan::largest_free_order(bitmap, self.blocks_in_group(group));
                        if let Some(order) = order { s.group_free_order.insert(group, order); }
                        else { s.group_free_order.remove(&group); }
                    }
                }
            }
        }
        Ok(())
    }

    /// Hide inode-PA tails from an in-memory allocation bitmap.  The disk
    /// bitmap remains the authority and deliberately does not contain these
    /// reservations, matching ext4_mb_generate_from_pa().
    pub(crate) fn mask_group_prealloc(&self, group: u32, bitmap: &mut [u8]) {
        let first = super::group_first_block(&self.sb, group);
        let s = self.state.lock();
        for pas in s.inode_prealloc.values() {
            for pa in pas {
                for &block in pa.blocks.iter().skip(pa.used as usize) {
                    if let Some(bit) = block.checked_sub(first) {
                        if bit < u64::from(self.blocks_in_group(group)) {
                            bitmap[bit as usize >> 3] |= 1 << (bit & 7);
                        }
                    }
                }
            }
        }
        for pas in s.group_prealloc.values() {
            for pa in pas {
                for &block in &pa.blocks {
                    if let Some(bit) = block.checked_sub(first) {
                        if bit < u64::from(self.blocks_in_group(group)) {
                            bitmap[bit as usize >> 3] |= 1 << (bit & 7);
                        }
                    }
                }
            }
        }
    }

    /// Remove inode-PA masks, producing the actual on-disk bitmap view.
    pub(crate) fn clear_group_prealloc(&self, group: u32, bitmap: &mut [u8]) {
        let first = super::group_first_block(&self.sb, group);
        let s = self.state.lock();
        for pas in s.inode_prealloc.values() {
            for pa in pas {
                for &block in pa.blocks.iter().skip(pa.used as usize) {
                    if let Some(bit) = block.checked_sub(first) {
                        if bit < u64::from(self.blocks_in_group(group)) {
                            bitmap[bit as usize >> 3] &= !(1 << (bit & 7));
                        }
                    }
                }
            }
        }
        for pas in s.group_prealloc.values() {
            for pa in pas {
                for &block in &pa.blocks {
                    if let Some(bit) = block.checked_sub(first) {
                        if bit < u64::from(self.blocks_in_group(group)) {
                            bitmap[bit as usize >> 3] &= !(1 << (bit & 7));
                        }
                    }
                }
            }
        }
    }

    /// Convert one in-memory inode or locality PA block into a durable
    /// allocation. # C: O(block_size)
    pub(crate) fn claim_prealloc_block(&self, phys: u64) -> Result<(), MountError> {
        self.run_journaled(|m| {
            let (group, bit) = m.locate_block(phys)?;
            let gd_orig = {
                let s = m.state.lock();
                gdt::parse_descriptor(&s.gdt_buf, group, &m.sb)?
            };
            let off = gd_orig.block_bitmap * m.sb.block_size as u64;
            // The block-bitmap cache is the masked in-memory buddy view. PA
            // ownership is not on disk, so reversing that mask is not an
            // authoritative disk image once another allocator operation has
            // changed the bitmap. Read the shadow/cache-backed metadata view
            // directly, as Linux keeps the on-disk bitmap separate from its
            // PA-generated buddy state.
            let mut disk = m.read_meta_byte_range(off, m.sb.block_size as usize)?;
            if !crate::csum::verify_block_bitmap_csum_at(
                &m.sb, &m.state.lock().gdt_buf, group, &disk)
            {
                crate::mount::first_csum_failure(b"block-bitmap-claim", group as u64, off);
                return Err(MountError::BadChecksum);
            }
            let idx = bit as usize;
            let mask = 1u8 << (idx & 7);
            if disk[idx >> 3] & mask != 0 { return Err(MountError::NoSpace); }
            disk[idx >> 3] |= mask;
            let mut cache = disk.clone();
            m.mask_group_prealloc(group, &mut cache);
            let mut gd = gd_orig;
            gd.free_blocks_count = gd.free_blocks_count.saturating_sub(1);
            {
                let mut s = m.state.lock();
                gdt::write_descriptor_counters(&mut s.gdt_buf, group, &m.sb, &gd)?;
                crate::csum::set_block_bitmap_csum(&m.sb, &mut s.gdt_buf, group, &disk);
                gdt::on_block_allocated(&mut s.gdt_buf, group, &m.sb);
                crate::csum::stamp_group_desc_csum(&m.sb, &mut s.gdt_buf, group);
                s.sb_free_blocks = s.sb_free_blocks.saturating_sub(1);
            }
            m.metadata_write(off, &disk)?;
            m.persist_gdt_slot_meta(group)?;
            m.persist_sb_free_blocks_meta()?;
            m.flush_pending_tx()?;
            m.publish_group_bitmap(group, off, cache);
            Ok(())
        })
    }
}
