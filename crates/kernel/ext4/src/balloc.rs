// ext4 block bitmap allocator. Walks group bitmaps for the first
// clear bit, sets it, persists bitmap + group-descriptor counter
// + superblock counter back to the underlying `BlockDevice`.
//
// Bitmap layout per Linux: one bit per fs block in the group;
// LSB-first within each byte; bit 0 of byte 0 is the *first*
// physical block belonging to the group. Group N's first physical
// block = `sb.first_data_block + N * sb.blocks_per_group`.
//
// The allocator owns bitmap RMW and counter updates inside the mount
// operation transaction.

use crate::gdt;

pub mod scan;
pub mod reserve;
pub(crate) mod prealloc;
mod free;
use reserve::ReserveFlags;
use crate::mount::{Mount, MountError};
use crate::superblock::{Superblock, SB_OFF_FREE_BLOCKS_LO, SB_OFF_FREE_BLOCKS_HI};
#[cfg(not(target_os = "oxide-kernel"))]
use core::sync::atomic::Ordering;

extern crate alloc;
use alloc::vec::Vec;

impl Mount {
    /// Eagerly load every allocation bitmap requested by the Linux-compatible
    /// `prefetch_block_bitmaps` option. The normal lazy path and this path
    /// publish through the same bitmap cache and summaries.
    pub(crate) fn prefetch_block_bitmaps(&self) -> Result<(), MountError> {
        for group in 0..self.sb.group_count() {
            let gd = {
                let s = self.state.lock();
                gdt::parse_descriptor(&s.gdt_buf, group, &self.sb)?
            };
            let byte_off = gd.block_bitmap * self.sb.block_size as u64;
            if self.state.lock().block_bitmap_cache.contains_key(&byte_off) { continue; }
            let uninit = { let s = self.state.lock(); gdt::block_uninit(&s.gdt_buf, group, &self.sb) };
            let bitmap = if uninit {
                let s = self.state.lock();
                init_block_bitmap_for_group(&self.sb, &s.gdt_buf, group)?
            } else {
                let bitmap = self.read_meta_byte_range(byte_off, self.sb.block_size as usize)?;
                if !crate::csum::verify_block_bitmap_csum_at(
                    &self.sb, &self.state.lock().gdt_buf, group, &bitmap) {
                    crate::mount::first_csum_failure(b"block-bitmap-prefetch", group as u64, byte_off);
                    return Err(MountError::BadChecksum);
                }
                bitmap
            };
            self.publish_group_bitmap(group, byte_off, bitmap);
        }
        Ok(())
    }

    /// Allocate a contiguous run of previously-free filesystem blocks.
    ///
    /// This is the small request-shaped part of Linux ext4's multiblock
    /// allocator.  A full-stripe request prefers a stripe-aligned run, then
    /// falls back to the first contiguous run when fragmentation makes the
    /// preferred placement unavailable.  The returned physical addresses are
    /// the blocks reserved by this call, in request order.
    /// # C: O(N_groups * block_size * count)
    pub(crate) fn alloc_blocks_flags(&self, hint: u32, count: u32, flags: ReserveFlags)
        -> Result<Vec<u64>, MountError>
    {
        self.alloc_blocks_for_inode(None, hint, count, flags)
    }

    /// Allocate data blocks with Linux's per-inode stream goal. # C: O(N_groups * block_size * count)
    pub(crate) fn alloc_blocks_for_inode(&self, ino: Option<u32>, hint: u32, count: u32, flags: ReserveFlags)
        -> Result<Vec<u64>, MountError>
    {
        if count == 0 { return Ok(Vec::new()); }
        #[cfg(not(target_os = "oxide-kernel"))]
        if self.faults.next_alloc_block.swap(false, Ordering::AcqRel) { return Err(MountError::BlockIo); }
        #[cfg(not(target_os = "oxide-kernel"))]
        {
            let left = self.faults.alloc_block_after.load(Ordering::Acquire);
            if left != 0 {
                // A test fault counts allocation attempts, not bitmap writes.
                // A multiblock request is atomic, so a fault within its span
                // rejects the request before reserving any of its blocks.
                if left <= count {
                    self.faults.alloc_block_after.store(0, Ordering::Release);
                    return Err(MountError::BlockIo);
                }
                self.faults.alloc_block_after.fetch_sub(count, Ordering::AcqRel);
            }
        }
        let optimize = self.optimize_scan();
        let may_dip = reserve::may_dip_into_reserve(&self.behaviour(), &self.alloc_cred(), flags);
        self.run_journaled(|m| {
            let groups = m.sb.group_count();
            if groups == 0 { return Err(MountError::NoSpace); }
            let free = m.state.lock().sb_free_blocks;
            if !reserve::has_free_blocks(free, u64::from(count), m.sb.r_blocks_count, may_dip) {
                return Err(MountError::NoSpace);
            }
            let mut retries = 0u8;
            loop {
                let freest = if optimize { m.freest_group(groups) } else { None };
                let stream = ino.and_then(|ino| m.stream_goal_group(ino, groups));
                let preferred = if optimize { m.group_for_request(groups, count, hint) } else { None };
                let start = stream.or(preferred).unwrap_or_else(|| scan::scan_start(hint, groups, optimize, freest));
                for off in 0..groups {
                    let group = (start + off) % groups;
                    if let Some(run) = m.try_alloc_run_in_group(group, count)? {
                        if let Some(ino) = ino { m.record_stream_goal(ino, group, groups); }
                        return Ok(run);
                    }
                }
                // Linux discards reclaimable locality PAs after a failed
                // mballoc scan and retries only when blocks were freed.
                if retries == 3 || !m.has_prealloc() { return Err(MountError::NoSpace); }
                let mut freed = m.discard_group_preallocations(count)?;
                if freed == 0 {
                    freed = m.inode_prealloc_free_blocks();
                    if freed == 0 { return Err(MountError::NoSpace); }
                    m.release_all_inode_prealloc()?;
                }
                retries += 1;
                if !reserve::has_free_blocks(
                    m.state.lock().sb_free_blocks, u64::from(count),
                    m.sb.r_blocks_count, may_dip) {
                    return Err(MountError::NoSpace);
                }
            }
        })
    }

    fn stream_goal_group(&self, ino: u32, groups: u32) -> Option<u32> {
        if groups == 0 { return None; }
        let slot = stream_goal_slot(ino, groups);
        self.state.lock().stream_last_groups.get(&slot).copied()
    }

    fn record_stream_goal(&self, ino: u32, group: u32, groups: u32) {
        self.state.lock().stream_last_groups.insert(stream_goal_slot(ino, groups), group);
    }

    /// Allocate one previously-free filesystem block for file data. Wraps in a
    /// journal scope so bitmap + GDT + SB counter writes commit
    /// atomically.
    /// # C: O(N_groups * block_size) worst-case
    pub fn alloc_block(&self, hint: u32) -> Result<u64, MountError> {
        self.alloc_block_flags(hint, ReserveFlags::DATA)
    }

    /// Allocate one block for metadata whose caller is already past the point
    /// of no return. An extent tree part-way through a rewrite cannot answer
    /// ENOSPC and leave a half-built tree behind, so its nodes come out of the
    /// reserve when nothing else is left.
    /// # C: same as [`Mount::alloc_block`]
    pub fn alloc_block_nofail(&self, hint: u32) -> Result<u64, MountError> {
        self.alloc_block_flags(hint, ReserveFlags::METADATA_NOFAIL)
    }

    /// The claim a data allocation for inode `ino` has on the reserve. A quota
    /// file's own blocks come out of it: quota accounting is what records that
    /// the disk filled up, so it cannot be the first thing a full filesystem
    /// stops being able to write.
    /// # C: O(1)
    pub(crate) fn data_reserve_flags(&self, ino: u32) -> ReserveFlags {
        let visible = self.quota_sb.lock().upgrade()
            .map(|sb| crate::quota::is_active_quota_file(&sb, ino))
            .unwrap_or(false);
        if self.sb.is_quota_inode(ino) || visible {
            ReserveFlags::QUOTA_FILE
        } else {
            ReserveFlags::DATA
        }
    }

    /// Allocate one previously-free filesystem block, stating what claim the
    /// allocation has on the superblock's reserved blocks.
    /// # C: O(N_groups * block_size) worst-case
    pub fn alloc_block_flags(&self, hint: u32, flags: ReserveFlags) -> Result<u64, MountError> {
        #[cfg(not(target_os = "oxide-kernel"))]
        if self.faults.next_alloc_block.swap(false, Ordering::AcqRel) { return Err(MountError::BlockIo); }
        #[cfg(not(target_os = "oxide-kernel"))]
        {
            let left = self.faults.alloc_block_after.load(Ordering::Acquire);
            if left != 0 && self.faults.alloc_block_after.fetch_sub(1, Ordering::AcqRel) == 1 {
                return Err(MountError::BlockIo);
            }
        }
        let optimize = self.optimize_scan();
        // Who is asking, and what claim their allocation has on the reserve.
        // Read before the journal scope: the credentials belong to the caller,
        // not to whichever context happens to drain the transaction.
        let may_dip = reserve::may_dip_into_reserve(&self.behaviour(), &self.alloc_cred(), flags);
        self.run_journaled(|m| {
            let groups = m.sb.group_count();
            if groups == 0 { return Err(MountError::NoSpace); }
            // The reserve gate, before any group is scanned: a caller with no
            // claim on the reserved blocks is out of space while they are all
            // that is left, exactly as if the bitmaps were full.
            let free = m.state.lock().sb_free_blocks;
            const ONE_BLOCK: u64 = 1;
            if !reserve::has_free_blocks(free, ONE_BLOCK, m.sb.r_blocks_count, may_dip) {
                return Err(MountError::NoSpace);
            }
            // `mb_optimize_scan=`: where the walk STARTS. It still visits every
            // group, so the answer never changes — only how many full groups
            // are read before it is reached.
            let freest = if optimize { m.freest_group(groups) } else { None };
            let preferred = if optimize { m.group_for_request(groups, 1, hint) } else { None };
            let start = preferred.unwrap_or_else(|| scan::scan_start(hint, groups, optimize, freest));
            for off in 0..groups {
                let g = (start + off) % groups;
                if let Some(blk) = m.try_alloc_in_group(g)? {
                    return Ok(blk);
                }
            }
            Err(MountError::NoSpace)
        })
    }

    /// Whether this mount scans block groups in free-space order. The mount
    /// option decides it; a mount that named none gets the answer its own size
    /// implies. # C: O(1)
    fn optimize_scan(&self) -> bool {
        self.behaviour().mb_optimize_scan
            .unwrap_or_else(|| scan::optimize_scan_default(self.sb.group_count()))
    }

    /// The group with the most free blocks, from the cached group descriptors.
    ///
    /// Read straight off the counters the allocator already maintains rather
    /// than from a second index of its own: an index would be a parallel copy
    /// of this same truth, free to disagree with it after any allocation.
    /// # C: O(N_groups)
    fn freest_group(&self, groups: u32) -> Option<(u32, u64)> {
        let s = self.state.lock();
        let mut best: Option<(u32, u64)> = None;
        for g in 0..groups {
            let Ok(d) = gdt::parse_descriptor(&s.gdt_buf, g, &self.sb) else { continue };
            let free = d.free_blocks_count as u64;
            let score = s.group_free_order.get(&g).copied()
                .map(|order| 1u64 << u32::from(order)).unwrap_or(free);
            if best.is_none_or(|(_, b)| score > b) { best = Some((g, score)); }
        }
        best
    }

    /// Linux's CR_GOAL_LEN_FAST starts with groups whose average free
    /// fragment can satisfy the request, then falls back to the normal scan.
    /// Unknown groups are deliberately omitted until their bitmap is loaded;
    /// the descriptor count remains the fallback authority.
    fn group_for_request(&self, groups: u32, count: u32, hint: u32) -> Option<u32> {
        if count == 0 { return None; }
        if count.is_power_of_two() && count > 1 {
            let wanted = count.ilog2() as u8;
            let s = self.state.lock();
            for (_, candidates) in s.group_free_order_index.range(wanted..) {
                if let Some(group) = candidates.range(hint..groups).next()
                    .or_else(|| candidates.iter().next()) {
                    return Some(*group);
                }
            }
            return None;
        }
        let wanted = scan::ceil_log2(count);
        let s = self.state.lock();
        for (_, candidates) in s.group_avg_fragment_index.range(wanted..) {
            if let Some(group) = candidates.range(hint..groups).next()
                .or_else(|| candidates.iter().next()) {
                return Some(*group);
            }
        }
        None
    }

    /// Try to find a free bit in `group`. Returns Ok(Some(phys))
    /// on success, Ok(None) if the group is full per its descriptor.
    /// # C: O(block_size)
    fn try_alloc_in_group(&self, group: u32) -> Result<Option<u64>, MountError> {
        // NB: serialized by the caller holding `op_lock` across the whole create
        // operation (see create.rs) — concurrent creates can't pick same block.
        let gd_orig = {
            let s = self.state.lock();
            gdt::parse_descriptor(&s.gdt_buf, group, &self.sb)?
        };
        if gd_orig.free_blocks_count == 0 { return Ok(None); }
        let bbm_byte_off = gd_orig.block_bitmap * (self.sb.block_size as u64);
        let uninit = { let s = self.state.lock(); gdt::block_uninit(&s.gdt_buf, group, &self.sb) };
        let cached = { self.state.lock().block_bitmap_cache.get(&bbm_byte_off).cloned() };
        let mut bitmap = if let Some(bitmap) = cached {
            bitmap
        } else if uninit {
            let s = self.state.lock();
            init_block_bitmap_for_group(&self.sb, &s.gdt_buf, group)?
        } else {
            let bitmap = self.read_meta_byte_range(bbm_byte_off, self.sb.block_size as usize)?;
            if !crate::csum::verify_block_bitmap_csum_at(&self.sb, &self.state.lock().gdt_buf, group, &bitmap) {
                crate::mount::first_csum_failure(b"block-bitmap-alloc", group as u64, bbm_byte_off);
                return Err(MountError::BadChecksum);
            }
            bitmap
        };
        let mut disk_bitmap = bitmap.clone();
        self.clear_group_prealloc(group, &mut disk_bitmap);
        self.mask_group_prealloc(group, &mut bitmap);
        let blocks_in_group = self.blocks_in_group(group);
        let bit = match find_first_clear(&bitmap, blocks_in_group) {
            Some(b) => b,
            None    => return Ok(None),
        };
        bitmap[bit >> 3] |= 1u8 << (bit & 7);
        disk_bitmap[bit >> 3] |= 1u8 << (bit & 7);
        let mut gd = gd_orig;
        gd.free_blocks_count = gd.free_blocks_count.saturating_sub(1);
        {
            let mut s = self.state.lock();
            gdt::write_descriptor_counters(&mut s.gdt_buf, group, &self.sb, &gd)?;
            crate::csum::set_block_bitmap_csum(&self.sb, &mut s.gdt_buf, group, &disk_bitmap);
            gdt::on_block_allocated(&mut s.gdt_buf, group, &self.sb);
            crate::csum::stamp_group_desc_csum(&self.sb, &mut s.gdt_buf, group);
            s.sb_free_blocks = s.sb_free_blocks.saturating_sub(1);
        }
        self.metadata_write(bbm_byte_off, &disk_bitmap)?;
        self.persist_gdt_slot_meta(group)?;
        self.persist_sb_free_blocks_meta()?;
        // Force commit so the next alloc_block within the same
        // outer scope reads the updated bitmap from disk.
        self.flush_pending_tx()?;
        self.publish_group_bitmap(group, bbm_byte_off, bitmap);
        let phys = group_first_block(&self.sb, group) + bit as u64;
        Ok(Some(phys))
    }

    /// Reserve one contiguous run in a group and persist its bitmap/counters.
    /// The stripe-aligned candidate is tried first for a request at least as
    /// wide as the configured stripe; otherwise the first run wins.
    fn try_alloc_run_in_group(&self, group: u32, count: u32)
        -> Result<Option<Vec<u64>>, MountError>
    {
        let gd_orig = {
            let s = self.state.lock();
            gdt::parse_descriptor(&s.gdt_buf, group, &self.sb)?
        };
        if u32::from(gd_orig.free_blocks_count) < count { return Ok(None); }
        let bbm_byte_off = gd_orig.block_bitmap * (self.sb.block_size as u64);
        let uninit = { let s = self.state.lock(); gdt::block_uninit(&s.gdt_buf, group, &self.sb) };
        let cached = { self.state.lock().block_bitmap_cache.get(&bbm_byte_off).cloned() };
        let mut bitmap = if let Some(bitmap) = cached {
            bitmap
        } else if uninit {
            let s = self.state.lock();
            init_block_bitmap_for_group(&self.sb, &s.gdt_buf, group)?
        } else {
            let bitmap = self.read_meta_byte_range(bbm_byte_off, self.sb.block_size as usize)?;
            if !crate::csum::verify_block_bitmap_csum_at(&self.sb, &self.state.lock().gdt_buf, group, &bitmap) {
                crate::mount::first_csum_failure(b"block-bitmap-alloc-run", group as u64, bbm_byte_off);
                return Err(MountError::BadChecksum);
            }
            bitmap
        };
        let mut disk_bitmap = bitmap.clone();
        self.clear_group_prealloc(group, &mut disk_bitmap);
        self.mask_group_prealloc(group, &mut bitmap);
        let blocks = self.blocks_in_group(group);
        let stripe = self.behaviour().stripe;
        let first_phys = group_first_block(&self.sb, group);
        let aligned = if count >= stripe && stripe > 1 {
            find_contiguous_run(&bitmap, blocks, count, first_phys, Some(stripe))
        } else { None };
        let start = aligned.or_else(|| find_contiguous_run(&bitmap, blocks, count, first_phys, None));
        let Some(start) = start else { return Ok(None) };
        for bit in start..start + count {
            bitmap[bit as usize >> 3] |= 1u8 << (bit & 7);
            disk_bitmap[bit as usize >> 3] |= 1u8 << (bit & 7);
        }
        let mut gd = gd_orig;
        gd.free_blocks_count = gd.free_blocks_count.saturating_sub(count);
        {
            let mut s = self.state.lock();
            gdt::write_descriptor_counters(&mut s.gdt_buf, group, &self.sb, &gd)?;
            crate::csum::set_block_bitmap_csum(&self.sb, &mut s.gdt_buf, group, &disk_bitmap);
            gdt::on_block_allocated(&mut s.gdt_buf, group, &self.sb);
            crate::csum::stamp_group_desc_csum(&self.sb, &mut s.gdt_buf, group);
            s.sb_free_blocks = s.sb_free_blocks.saturating_sub(u64::from(count));
        }
        self.metadata_write(bbm_byte_off, &disk_bitmap)?;
        self.persist_gdt_slot_meta(group)?;
        self.persist_sb_free_blocks_meta()?;
        self.flush_pending_tx()?;
        self.publish_group_bitmap(group, bbm_byte_off, bitmap);
        Ok(Some((0..count).map(|n| first_phys + u64::from(start + n)).collect()))
    }

    fn locate_block(&self, phys: u64) -> Result<(u32, u32), MountError> {
        let bpg = self.sb.blocks_per_group as u64;
        if bpg == 0 || phys < self.sb.first_data_block as u64 {
            return Err(MountError::BadBlock);
        }
        let rel = phys - self.sb.first_data_block as u64;
        let group = (rel / bpg) as u32;
        let bit   = (rel % bpg) as u32;
        if group >= self.sb.group_count() { return Err(MountError::BadBlock); }
        if bit >= self.blocks_in_group(group) { return Err(MountError::BadBlock); }
        Ok((group, bit))
    }

    fn blocks_in_group(&self, group: u32) -> u32 {
        let total = self.sb.blocks_count();
        let bpg   = self.sb.blocks_per_group as u64;
        let first = self.sb.first_data_block as u64 + group as u64 * bpg;
        let end   = core::cmp::min(first + bpg, total);
        end.saturating_sub(first) as u32
    }

    /// Persist one GDT slot to disk through `metadata_write` (so
    /// it's journaled when a scope is open). Briefly locks state
    /// to copy the slot's containing fs-block bytes; releases the
    /// lock before the write.
    /// # C: O(block_size)
    pub(crate) fn persist_gdt_slot_meta(&self, group: u32) -> Result<(), MountError> {
        let dsize = gdt::desc_size_for(&self.sb) as usize;
        let slot_byte = (group as usize) * dsize;
        let bs = self.sb.block_size as usize;
        let blk_idx = slot_byte / bs;
        let byte_off = self.gdt_byte_offset() + (blk_idx * bs) as u64;
        let payload = {
            let s = self.state.lock();
            let lo = blk_idx * bs;
            let hi = core::cmp::min(lo + bs, s.gdt_buf.len());
            s.gdt_buf[lo..hi].to_vec()
        };
        self.metadata_write(byte_off, &payload)
    }

    /// Persist `sb_free_blocks` to the on-disk superblock through
    /// `metadata_write`.
    /// # C: O(SB read + 1 block write)
    pub(crate) fn persist_sb_free_blocks_meta(&self) -> Result<(), MountError> {
        let (lo_v, hi_v) = {
            let s = self.state.lock();
            ((s.sb_free_blocks & 0xFFFF_FFFF) as u32, (s.sb_free_blocks >> 32) as u32)
        };
        let mut sb_buf = self.read_meta_byte_range(
            crate::superblock::SUPERBLOCK_OFFSET,
            crate::superblock::SUPERBLOCK_LEN,
        )?;
        sb_buf[SB_OFF_FREE_BLOCKS_LO..SB_OFF_FREE_BLOCKS_LO+4].copy_from_slice(&lo_v.to_le_bytes());
        sb_buf[SB_OFF_FREE_BLOCKS_HI..SB_OFF_FREE_BLOCKS_HI+4].copy_from_slice(&hi_v.to_le_bytes());
        crate::csum::stamp_superblock_csum(&self.sb, &mut sb_buf);
        self.metadata_write(crate::superblock::SUPERBLOCK_OFFSET, &sb_buf)
    }
}

fn stream_goal_slot(ino: u32, groups: u32) -> u32 {
    let slots = prealloc::locality_cpu_count().min(groups.div_ceil(4)).max(1);
    stream_goal_slot_with_slots(ino, slots)
}

fn stream_goal_slot_with_slots(ino: u32, slots: u32) -> u32 {
    ino % slots.max(1)
}

impl Mount {
    /// Publish the validated bitmap and its free-space summaries only
    /// after the metadata transaction is durable. The summary is advisory;
    /// the bitmap remains the allocation authority.
    /// # C: O(block_size)
    fn publish_group_bitmap(&self, group: u32, byte_off: u64, bitmap: Vec<u8>) {
        let order = scan::largest_free_order(&bitmap, self.blocks_in_group(group));
        let avg = scan::average_fragment_order(&bitmap, self.blocks_in_group(group));
        let mut s = self.state.lock();
        s.block_bitmap_cache.insert(byte_off, bitmap);
        let old_order = s.group_free_order.insert(group, order.unwrap_or(0));
        scan::replace_order_index(&mut s.group_free_order_index, group, old_order, order);
        if order.is_none() { s.group_free_order.remove(&group); }
        let old_avg = s.group_avg_fragment_order.insert(group, avg.unwrap_or(0));
        scan::replace_order_index(&mut s.group_avg_fragment_index, group, old_avg, avg);
        if avg.is_none() { s.group_avg_fragment_order.remove(&group); }
    }
}

/// Group N's first physical block on the FS.
/// # C: O(1)
pub fn group_first_block(sb: &Superblock, group: u32) -> u64 {
    sb.first_data_block as u64 + (group as u64) * (sb.blocks_per_group as u64)
}

fn init_block_bitmap_for_group(sb: &Superblock, gdt_buf: &[u8], group: u32) -> Result<Vec<u8>, MountError> {
    let bs = sb.block_size as usize;
    let mut bitmap = alloc::vec![0u8; bs];
    let blocks = blocks_in_group_sb(sb, group);
    mark_tail_used(&mut bitmap, blocks);
    mark_group_backups(sb, group, &mut bitmap);
    mark_descriptor_owned_metadata(sb, gdt_buf, group, &mut bitmap)?;
    Ok(bitmap)
}

fn blocks_in_group_sb(sb: &Superblock, group: u32) -> u32 {
    let bpg = sb.blocks_per_group as u64;
    let first = group_first_block(sb, group);
    let end = core::cmp::min(first + bpg, sb.blocks_count());
    end.saturating_sub(first) as u32
}

fn mark_tail_used(bitmap: &mut [u8], blocks: u32) {
    let max = bitmap.len() * 8;
    for bit in blocks as usize..max { set_bit(bitmap, bit); }
}

fn mark_group_backups(sb: &Superblock, group: u32, bitmap: &mut [u8]) {
    if !group_has_super(sb, group) { return; }
    let gdt_blocks = div_ceil_u64(sb.group_count() as u64 * gdt::desc_size_for(sb) as u64, sb.block_size as u64);
    let meta = 1 + gdt_blocks + sb.reserved_gdt_blocks as u64;
    let blocks = blocks_in_group_sb(sb, group) as u64;
    for bit in 0..core::cmp::min(meta, blocks) { set_bit(bitmap, bit as usize); }
}

fn mark_descriptor_owned_metadata(sb: &Superblock, gdt_buf: &[u8], group: u32, bitmap: &mut [u8]) -> Result<(), MountError> {
    let first = group_first_block(sb, group);
    let end = first + blocks_in_group_sb(sb, group) as u64;
    let table_blocks = div_ceil_u64(sb.inodes_per_group as u64 * sb.inode_size as u64, sb.block_size as u64);
    for n in 0..sb.group_count() {
        let gd = gdt::parse_descriptor(gdt_buf, n, sb)?;
        mark_phys_if_in_group(bitmap, first, end, gd.block_bitmap);
        mark_phys_if_in_group(bitmap, first, end, gd.inode_bitmap);
        for off in 0..table_blocks { mark_phys_if_in_group(bitmap, first, end, gd.inode_table + off); }
    }
    Ok(())
}

fn mark_phys_if_in_group(bitmap: &mut [u8], first: u64, end: u64, phys: u64) {
    if phys >= first && phys < end { set_bit(bitmap, (phys - first) as usize); }
}

fn group_has_super(sb: &Superblock, group: u32) -> bool {
    if !sb.has_sparse_super() { return true; }
    group == 0 || group == 1 || is_power_of(group, 3) || is_power_of(group, 5) || is_power_of(group, 7)
}

fn is_power_of(mut n: u32, base: u32) -> bool {
    if n < 1 { return false; }
    while n % base == 0 { n /= base; }
    n == 1
}

fn div_ceil_u64(n: u64, d: u64) -> u64 {
    if d == 0 { 0 } else { (n + d - 1) / d }
}

fn set_bit(bitmap: &mut [u8], bit: usize) {
    if bit / 8 < bitmap.len() { bitmap[bit >> 3] |= 1u8 << (bit & 7); }
}

fn find_contiguous_run(bitmap: &[u8], max_bits: u32, count: u32, first_phys: u64,
                       stripe: Option<u32>) -> Option<u32> {
    if count == 0 || count > max_bits { return None; }
    let mut best_aligned: Option<(u32, u32)> = None;
    let mut best_any: Option<(u32, u32)> = None;
    let mut run_start = 0;
    let mut run_len = 0;
    let mut consider = |start: u32, len: u32| {
        if len < count { return; }
        let candidate = start;
        let replace = |best: &mut Option<(u32, u32)>| {
            if best.is_none_or(|(old_len, old_start)|
                len < old_len || (len == old_len && candidate < old_start)) {
                *best = Some((len, candidate));
            }
        };
        replace(&mut best_any);
        if let Some(width) = stripe.filter(|width| *width > 1) {
            let misalignment = (first_phys + u64::from(start)) % u64::from(width);
            let aligned = start + if misalignment == 0 { 0 } else {
                width - misalignment as u32
            };
            if aligned.saturating_add(count) <= start.saturating_add(len) {
                let aligned_len = len - (aligned - start);
                if best_aligned.is_none_or(|(old_len, old_start)|
                    aligned_len < old_len || (aligned_len == old_len && aligned < old_start)) {
                    best_aligned = Some((aligned_len, aligned));
                }
            }
        }
    };
    for bit in 0..=max_bits {
        if bit < max_bits && bitmap[bit as usize >> 3] & (1u8 << (bit & 7)) == 0 {
            if run_len == 0 { run_start = bit; }
            run_len += 1;
            continue;
        }
        if run_len != 0 { consider(run_start, run_len); }
        run_len = 0;
    }
    if let Some((_, start)) = best_aligned { return Some(start); }
    best_any.map(|(_, start)| start)
}

/// Scan `bitmap` for the first 0 bit in `[0, max_bits)`. Returns
/// the bit index, or None when every covered bit is already set.
/// # C: O(max_bits / 8)
pub fn find_first_clear(bitmap: &[u8], max_bits: u32) -> Option<usize> {
    let max = max_bits as usize;
    let full_bytes = max / 8;
    for (i, &b) in bitmap.iter().take(full_bytes).enumerate() {
        if b != 0xFF {
            for bit in 0..8 {
                if (b & (1 << bit)) == 0 { return Some(i * 8 + bit); }
            }
        }
    }
    let tail_bits = max % 8;
    if tail_bits > 0 && full_bytes < bitmap.len() {
        let b = bitmap[full_bytes];
        for bit in 0..tail_bits {
            if (b & (1 << bit)) == 0 { return Some(full_bytes * 8 + bit); }
        }
    }
    None
}

// Re-export the guard type for helper signatures.
pub use crate::mount::MountStateGuard;

#[cfg(test)]
#[path = "balloc_tests.rs"]
mod tests;
