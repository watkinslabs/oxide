//! Inode data-preallocation ownership.
//!
//! The bitmap reservation is durable metadata, but the tail has no inode
//! extent until a later regular-file write consumes it. Keeping that split
//! explicit prevents directory and metadata allocation from seeing a data PA
//! as an extent, while still letting the same inode reuse its next blocks.

use alloc::vec;
use alloc::vec::Vec;

pub(crate) fn locality_cpu() -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; return hal_x86_64::X86CpuOps::current_cpu() as usize; }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; return hal_aarch64::ArmCpuOps::current_cpu() as usize; }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

pub(crate) fn locality_cpu_count() -> u32 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; return hal_x86_64::X86CpuOps::cpu_count(); }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; return hal_aarch64::ArmCpuOps::cpu_count(); }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 1 }
}

use crate::gdt;
use super::super::{Mount, MountError};

/// One contiguous tail reserved for regular-file data.
pub(crate) struct InodePrealloc {
    pub(crate) logical_start: u32,
    pub(crate) blocks: Vec<u64>,
    pub(crate) used: Vec<bool>,
}

/// One contiguous tail reserved for any small regular-file allocation in a
/// block group. Unlike an inode PA it has no logical owner. # C: O(1)
pub(crate) struct GroupPrealloc {
    pub(crate) blocks: Vec<u64>,
}

const GROUP_PREALLOC_LIST_LIMIT: usize = 8;
const GROUP_PREALLOC_ORDER_BUCKETS: u8 = 10;

/// Linux indexes locality PAs by `fls(request_len) - 1`, then searches that
/// bucket and larger buckets. Keep the same bounded order domain rather than
/// merging unrelated request sizes into one list.
fn group_prealloc_order(blocks: u32) -> u8 {
    if blocks <= 1 { return 0; }
    (u32::BITS - 1 - blocks.leading_zeros())
        .min(u32::from(GROUP_PREALLOC_ORDER_BUCKETS - 1)) as u8
}

/// Keep the locality PA list bounded like Linux's per-order list. It is
/// allowed to grow to eight entries; the ninth insertion trims the bucket
/// back to five, retaining the largest free reservations. This hysteresis is
/// deliberate: trimming on every insertion would make the list churn, while
/// retaining eight after overflow would change Linux's reclaim pressure. # C: O(N log N)
fn trim_group_preallocations(entries: &mut Vec<GroupPrealloc>) {
    if entries.len() <= GROUP_PREALLOC_LIST_LIMIT { return; }
    entries.sort_unstable_by(|left, right| right.blocks.len().cmp(&left.blocks.len()));
    entries.truncate(5);
}

fn reinsert_group_preallocs(
    map: &mut alloc::collections::BTreeMap<(usize, u32, u8), Vec<GroupPrealloc>>,
    cpu: usize,
    group: u32,
    pas: Vec<GroupPrealloc>,
) {
    for pa in pas {
        let new_order = group_prealloc_order(pa.blocks.len() as u32);
        let entries = map.entry((cpu, group, new_order)).or_default();
        entries.push(pa);
        trim_group_preallocations(entries);
    }
}

fn inode_pa_blocks(pa: &InodePrealloc, logical: u32, want: u32) -> Option<Vec<u64>> {
    let offset = logical.checked_sub(pa.logical_start)? as usize;
    if offset >= pa.blocks.len() || pa.used[offset] { return None; }
    let mut blocks = Vec::new();
    for n in offset..pa.blocks.len() {
        if pa.used[n] || blocks.len() == want as usize { break; }
        blocks.push(pa.blocks[n]);
    }
    (!blocks.is_empty()).then_some(blocks)
}

fn select_group_pa<'a>(entries: &'a [GroupPrealloc], want: u32, goal: u64)
    -> Option<&'a GroupPrealloc>
{
    entries.iter()
        .filter(|pa| pa.blocks.len() >= want as usize && !pa.blocks.is_empty())
        .min_by_key(|pa| pa.blocks[0].abs_diff(goal))
}

/// Remove one exact physical block from a locality bucket while preserving
/// contiguity of every remaining reservation. Group PAs normally consume from
/// the front like Linux; splitting also keeps the ownership invariant safe if
/// a caller presents an interior block. Kept pure for focused tests.
fn consume_group_prealloc_block(entries: &mut Vec<GroupPrealloc>, phys: u64) -> bool {
    let Some(pa_idx) = entries.iter().position(|pa| pa.blocks.iter().any(|&block| block == phys)) else {
        return false;
    };
    let block_idx = entries[pa_idx].blocks.iter().position(|&block| block == phys).unwrap();
    let suffix = entries[pa_idx].blocks.split_off(block_idx + 1);
    entries[pa_idx].blocks.pop();
    if !suffix.is_empty() {
        entries.insert(pa_idx + 1, GroupPrealloc { blocks: suffix });
    }
    if entries[pa_idx].blocks.is_empty() { entries.remove(pa_idx); }
    true
}

impl Mount {
    /// Return contiguous free physical blocks from an overlapping inode PA.
    /// Linux permits a request to consume an interior PA block, not only its
    /// sequential head. # C: O(N PAs + request)
    pub(crate) fn peek_inode_prealloc(&self, ino: u32, logical: u32, want: u32)
        -> Option<Vec<u64>>
    {
        if want == 0 { return Some(Vec::new()); }
        let s = self.state.lock();
        let pas = s.inode_prealloc.get(&ino)?;
        pas.iter().find_map(|pa| inode_pa_blocks(pa, logical, want))
    }

    /// Retire one block from an inode PA after its extent was published. # C: O(N PAs)
    pub(crate) fn consume_inode_prealloc(&self, ino: u32, logical: u32) -> bool {
        let mut s = self.state.lock();
        let Some(pas) = s.inode_prealloc.get_mut(&ino) else { return false; };
        let Some((idx, offset)) = pas.iter().enumerate().find_map(|(idx, pa)| {
            let offset = logical.checked_sub(pa.logical_start)? as usize;
            (offset < pa.blocks.len() && !pa.used[offset]).then_some((idx, offset))
        }) else { return false; };
        pas[idx].used[offset] = true;
        if pas[idx].used.iter().all(|used| *used) { pas.remove(idx); }
        if pas.is_empty() { s.inode_prealloc.remove(&ino); }
        true
    }

    /// Undo a durable claim made from an inode PA after extent publication
    /// fails. Remove the claim before freeing the bitmap bit, because the
    /// bitmap owner masks still-reserved PA blocks.
    pub(crate) fn rollback_inode_prealloc_claim(&self, ino: u32, logical: u32, phys: u64)
        -> Result<(), MountError>
    {
        let _ = self.consume_inode_prealloc(ino, logical);
        if let Err(error) = self.free_block(phys) {
            self.add_inode_prealloc(ino, logical, vec![phys]);
            return Err(error);
        }
        self.add_inode_prealloc(ino, logical, vec![phys]);
        Ok(())
    }

    /// Keep an unconsumed tail for this inode's next sequential write. # C: O(1)
    pub(crate) fn add_inode_prealloc(&self, ino: u32, logical_start: u32, blocks: Vec<u64>) {
        if blocks.is_empty() { return; }
        self.state.lock().inode_prealloc.entry(ino).or_default()
            .push(InodePrealloc { logical_start, used: vec![false; blocks.len()], blocks });
    }

    /// Return the nearest usable locality PA and its actual group owner.
    /// Linux searches every PA in the current CPU's locality lists; the goal
    /// only ranks candidates and must not restrict the search to one hinted
    /// group. # C: O(N PAs)
    pub(crate) fn peek_group_prealloc_owner(&self, want: u32, goal: u64)
        -> Option<(usize, u32, Vec<u64>)>
    {
        let cpu = locality_cpu();
        if want == 0 { return Some((cpu, 0, Vec::new())); }
        let first_order = group_prealloc_order(want);
        let s = self.state.lock();
        let mut best: Option<(u64, u32, Vec<u64>)> = None;
        for order in first_order..GROUP_PREALLOC_ORDER_BUCKETS {
            for (&(_, group, _), pas) in s.group_prealloc.iter()
                .filter(|(&(owner, _, bucket), _)| owner == cpu && bucket == order)
            {
                if let Some(pa) = select_group_pa(pas, want, goal) {
                    let distance = pa.blocks[0].abs_diff(goal);
                    if best.as_ref().is_none_or(|(old, _, _)| distance < *old) {
                        best = Some((distance, group, pa.blocks[..want as usize].to_vec()));
                    }
                }
            }
        }
        best.map(|(_, group, blocks)| (cpu, group, blocks))
    }

    /// Retire the exact physical block selected from the CPU-local PA list.
    /// Selection may choose the closest of several reservations, so removing
    /// an arbitrary eligible prefix would leave the claimed block reserved in
    /// memory and retire a different block that was never consumed.
    /// # C: O(N PAs)
    pub(crate) fn consume_group_prealloc_on_cpu(&self, cpu: usize, group: u32, phys: u64) -> bool {
        let mut s = self.state.lock();
        for order in 0..GROUP_PREALLOC_ORDER_BUCKETS {
            let key = (cpu, group, order);
            let Some(mut pas) = s.group_prealloc.remove(&key) else { continue; };
            if !consume_group_prealloc_block(&mut pas, phys) {
                s.group_prealloc.insert(key, pas);
                continue;
            }
            // Linux's ext4_mb_release_context() removes a consumed group PA
            // from its old free-length list and inserts every surviving tail
            // into the bucket for its current pa_free length. Keeping a tail
            // under the original request bucket makes the locality index lie
            // about its size and defeats the bounded-list trim policy.
            reinsert_group_preallocs(&mut s.group_prealloc, cpu, group, pas);
            return true;
        }
        false
    }

    /// Undo a durable claim made from a locality PA, preserving the PA as a
    /// reusable one-block reservation after the bitmap bit is freed.
    pub(crate) fn rollback_group_prealloc_claim(&self, cpu: usize, group: u32, phys: u64)
        -> Result<(), MountError>
    {
        let _ = self.consume_group_prealloc_on_cpu(cpu, group, phys);
        if let Err(error) = self.free_block(phys) {
            self.add_group_prealloc_on_cpu(cpu, group, 1, vec![phys]);
            return Err(error);
        }
        self.add_group_prealloc_on_cpu(cpu, group, 1, vec![phys]);
        Ok(())
    }

    /// Keep a locality tail on the CPU-local list selected by the allocation
    /// context.  The caller must pass the CPU sampled before a blocking
    /// allocation, matching Linux's `raw_cpu_ptr(s_locality_groups)` lifetime.
    /// # C: O(N)
    pub(crate) fn add_group_prealloc_on_cpu(&self, cpu: usize, group: u32, request: u32, blocks: Vec<u64>) {
        if blocks.is_empty() { return; }
        let mut s = self.state.lock();
        let order = group_prealloc_order(request);
        let entries = s.group_prealloc.entry((cpu, group, order)).or_default();
        entries.push(GroupPrealloc { blocks });
        trim_group_preallocations(entries);
    }

    /// Whether an in-memory PA can hide free blocks from a new allocation. # C: O(1)
    pub(crate) fn has_prealloc(&self) -> bool {
        let s = self.state.lock();
        !s.inode_prealloc.is_empty() || !s.group_prealloc.is_empty()
    }

    /// Count unconsumed inode-PA blocks available for discard. # C: O(N PA blocks)
    pub(crate) fn inode_prealloc_free_blocks(&self) -> u32 {
        self.state.lock().inode_prealloc.values().flat_map(|pas| pas.iter())
            .map(|pa| pa.used.iter().filter(|used| !**used).count() as u32)
            .sum()
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
            released.extend(pa.blocks.into_iter().zip(pa.used).filter_map(|(block, used)| (!used).then_some(block)));
        }
        let mut s = self.state.lock();
        for block in released {
            let Ok((group, bit)) = self.locate_block(block) else { continue };
            let Ok(gd) = gdt::parse_descriptor(&s.gdt_buf, group, &self.sb) else { continue };
            let off = gd.block_bitmap * self.sb.block_size as u64;
            if let Some(bitmap) = s.block_bitmap_cache.get_mut(&off) {
                bitmap[bit as usize >> 3] &= !(1 << (bit & 7));
                let order = super::scan::largest_free_order(bitmap, self.blocks_in_group(group));
                let avg = super::scan::average_fragment_order(bitmap, self.blocks_in_group(group));
                let old_order = s.group_free_order.insert(group, order.unwrap_or(0));
                super::scan::replace_order_index(&mut s.group_free_order_index, group, old_order, order);
                if order.is_none() { s.group_free_order.remove(&group); }
                let old_avg = s.group_avg_fragment_order.insert(group, avg.unwrap_or(0));
                super::scan::replace_order_index(&mut s.group_avg_fragment_index, group, old_avg, avg);
                if avg.is_none() { s.group_avg_fragment_order.remove(&group); }
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
        for ((_, _, _), entries) in pas {
            for pa in entries {
                for block in pa.blocks {
                    let Ok((group, bit)) = self.locate_block(block) else { continue };
                    let Ok(gd) = gdt::parse_descriptor(&s.gdt_buf, group, &self.sb) else { continue };
                    let off = gd.block_bitmap * self.sb.block_size as u64;
                    if let Some(bitmap) = s.block_bitmap_cache.get_mut(&off) {
                        bitmap[bit as usize >> 3] &= !(1 << (bit & 7));
                        let order = super::scan::largest_free_order(bitmap, self.blocks_in_group(group));
                        let avg = super::scan::average_fragment_order(bitmap, self.blocks_in_group(group));
                        let old_order = s.group_free_order.insert(group, order.unwrap_or(0));
                        super::scan::replace_order_index(&mut s.group_free_order_index, group, old_order, order);
                        if order.is_none() { s.group_free_order.remove(&group); }
                        let old_avg = s.group_avg_fragment_order.insert(group, avg.unwrap_or(0));
                        super::scan::replace_order_index(&mut s.group_avg_fragment_index, group, old_avg, avg);
                        if avg.is_none() { s.group_avg_fragment_order.remove(&group); }
                    }
                }
            }
        }
        Ok(())
    }

    /// Discard complete locality PAs until at least `needed` blocks are
    /// reclaimable. Linux discards whole PAs, so the result may exceed the
    /// request but never splits a reservation.
    /// # C: O(N PA blocks)
    pub(crate) fn discard_group_preallocations(&self, needed: u32) -> Result<u32, MountError> {
        if needed == 0 { return Ok(0); }
        let mut released = Vec::new();
        let mut remaining = alloc::collections::BTreeMap::new();
        let mut free = 0u32;
        let pas = core::mem::take(&mut self.state.lock().group_prealloc);
        for (key, entries) in pas {
            let mut keep = Vec::new();
            for pa in entries {
                if free < needed {
                    free = free.saturating_add(pa.blocks.len() as u32);
                    released.extend(pa.blocks);
                } else {
                    keep.push(pa);
                }
            }
            if !keep.is_empty() { remaining.insert(key, keep); }
        }
        self.state.lock().group_prealloc = remaining;
        let mut s = self.state.lock();
        for block in released {
            let Ok((group, bit)) = self.locate_block(block) else { continue };
            let Ok(gd) = gdt::parse_descriptor(&s.gdt_buf, group, &self.sb) else { continue };
            let off = gd.block_bitmap * self.sb.block_size as u64;
            if let Some(bitmap) = s.block_bitmap_cache.get_mut(&off) {
                bitmap[bit as usize >> 3] &= !(1 << (bit & 7));
                let order = super::scan::largest_free_order(bitmap, self.blocks_in_group(group));
                let avg = super::scan::average_fragment_order(bitmap, self.blocks_in_group(group));
                let old_order = s.group_free_order.insert(group, order.unwrap_or(0));
                super::scan::replace_order_index(&mut s.group_free_order_index, group, old_order, order);
                if order.is_none() { s.group_free_order.remove(&group); }
                let old_avg = s.group_avg_fragment_order.insert(group, avg.unwrap_or(0));
                super::scan::replace_order_index(&mut s.group_avg_fragment_index, group, old_avg, avg);
                if avg.is_none() { s.group_avg_fragment_order.remove(&group); }
            }
        }
        Ok(free)
    }

    /// Hide inode-PA tails from an in-memory allocation bitmap.  The disk
    /// bitmap remains the authority and deliberately does not contain these
    /// reservations, matching ext4_mb_generate_from_pa().
    pub(crate) fn mask_group_prealloc(&self, group: u32, bitmap: &mut [u8]) {
        let first = super::group_first_block(&self.sb, group);
        let s = self.state.lock();
        for pas in s.inode_prealloc.values() {
            for pa in pas {
                for (&block, &used) in pa.blocks.iter().zip(&pa.used) {
                    if used { continue; }
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
                for (&block, &used) in pa.blocks.iter().zip(&pa.used) {
                    if used { continue; }
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

#[cfg(test)]
#[path = "prealloc_tests.rs"]
mod tests;
