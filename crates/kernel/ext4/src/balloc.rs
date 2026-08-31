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
            let gdt_bytes = self.read_gdt_bytes()?;
            let gd = gdt::parse_descriptor(&gdt_bytes, group, &self.sb)?;
            let byte_off = gd.block_bitmap * self.sb.block_size as u64;
            if self.state.lock().block_bitmap_cache.contains_key(&byte_off) { continue; }
            let uninit = gdt::block_uninit(&gdt_bytes, group, &self.sb);
            let bitmap = if uninit {
                init_block_bitmap_for_group(&self.sb, &gdt_bytes, group)?
            } else {
                let bitmap = self.read_meta_byte_range(byte_off, self.sb.block_size as usize)?;
                if !crate::csum::verify_block_bitmap_csum_at(
                    &self.sb, &gdt_bytes, group, &bitmap) {
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
        self.alloc_blocks_for_inode_goal(None, hint, count, flags, None)
    }

    /// Allocate data blocks with Linux's per-inode stream goal. # C: O(N_groups * block_size * count)
    pub(crate) fn alloc_blocks_for_inode(&self, ino: Option<u32>, hint: u32, count: u32, flags: ReserveFlags)
        -> Result<Vec<u64>, MountError>
    {
        self.alloc_blocks_for_inode_goal(ino, hint, count, flags, None)
    }

    /// Allocate with the physical neighbour carried by the inode mapping
    /// owner. Linux's mballoc tries this goal in the selected group before
    /// entering the broader buddy/bitmap criteria; `None` preserves callers
    /// that have no physical locality fact.
    pub(crate) fn alloc_blocks_for_inode_goal(
        &self, ino: Option<u32>, hint: u32, count: u32, flags: ReserveFlags,
        goal_phys: Option<u64>,
    ) -> Result<Vec<u64>, MountError>
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
            let free = m.state_free_blocks();
            if !reserve::has_free_blocks(free, u64::from(count), m.sb.r_blocks_count, may_dip) {
                return Err(MountError::NoSpace);
            }
            let mut retries = 0u8;
            loop {
                let freest = if optimize { m.freest_group(groups) } else { None };
                let stream = ino.and_then(|ino| m.stream_goal_group(ino, groups));
                let preferred = if optimize {
                    m.group_for_request(groups, count, hint, !flags.use_reserved)
                } else { None };
                let start = stream.or(preferred).unwrap_or_else(|| scan::scan_start(hint, groups, optimize, freest));
                let mut tried = alloc::collections::BTreeSet::new();
                if optimize {
                    let mut candidates = {
                        let s = m.state.lock();
                        scan::indexed_candidates(&s.group_free_order_index,
                            &s.group_avg_fragment_index, groups, count, hint, !flags.use_reserved)
                    };
                    if let Some(goal_group) = goal_phys.map(|phys| m.group_of_block(phys)) {
                        candidates.retain(|&group| group != goal_group);
                        candidates.insert(0, goal_group);
                    }
                    for group in candidates {
                        tried.insert(group);
                        if let Some(run) = m.try_alloc_run_in_group(group, count, goal_phys)? {
                            if let Some(ino) = ino { m.record_stream_goal(ino, group, groups); }
                            return Ok(run);
                        }
                    }
                }
                for off in 0..groups {
                    let group = (start + off) % groups;
                    if tried.contains(&group) { continue; }
                    if let Some(run) = m.try_alloc_run_in_group(group, count, goal_phys)? {
                        if let Some(ino) = ino { m.record_stream_goal(ino, group, groups); }
                        return Ok(run);
                    }
                }
                // Linux discards reclaimable locality PAs after a failed
                // mballoc scan and retries only when blocks were freed.
                if retries == 3 || !m.has_prealloc() {
                    if let Some(run) = m.alloc_best_effort_run(count)? {
                        if let Some(ino) = ino { m.record_stream_goal(ino, m.group_of_block(run[0]), groups); }
                        return Ok(run);
                    }
                    return Err(MountError::NoSpace);
                }
                let mut freed = m.discard_group_preallocations(count)?;
                if freed == 0 {
                    freed = m.discard_inode_preallocations(count)?;
                    if freed == 0 {
                        if let Some(run) = m.alloc_best_effort_run(count)? {
                            if let Some(ino) = ino { m.record_stream_goal(ino, m.group_of_block(run[0]), groups); }
                            return Ok(run);
                        }
                        return Err(MountError::NoSpace);
                    }
                }
                retries += 1;
                if !reserve::has_free_blocks(
                    m.state_free_blocks(), u64::from(count),
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
            let free = m.state_free_blocks();
            const ONE_BLOCK: u64 = 1;
            if !reserve::has_free_blocks(free, ONE_BLOCK, m.sb.r_blocks_count, may_dip) {
                return Err(MountError::NoSpace);
            }
            // `mb_optimize_scan=`: where the walk STARTS. It still visits every
            // group, so the answer never changes — only how many full groups
            // are read before it is reached.
            let freest = if optimize { m.freest_group(groups) } else { None };
            let preferred = if optimize {
                m.group_for_request(groups, 1, hint, !flags.use_reserved)
            } else { None };
            let start = preferred.unwrap_or_else(|| scan::scan_start(hint, groups, optimize, freest));
            let mut tried = alloc::collections::BTreeSet::new();
            if optimize {
                let candidates = {
                    let s = self.state.lock();
                    scan::indexed_candidates(&s.group_free_order_index,
                        &s.group_avg_fragment_index, groups, 1, hint, !flags.use_reserved)
                };
                for group in candidates {
                    tried.insert(group);
                    if let Some(blk) = m.try_alloc_in_group(group)? { return Ok(blk); }
                }
            }
            for off in 0..groups {
                let g = (start + off) % groups;
                if tried.contains(&g) { continue; }
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
        // The optimized mballoc path maintains this order index as bitmap
        // ownership changes. Consult it first, matching Linux's xarray scan;
        // rebuilding a ranking from every descriptor here made each
        // allocation O(N_groups) even after the mount had loaded summaries.
        if let Some(best) = {
            let s = self.state.lock();
            scan::indexed_freest_group(&s.group_free_order_index, groups)
        } {
            return Some(best);
        }
        // Before the first bitmap summary is published, retain the descriptor
        // fallback so optimized scan still has a useful start group.
        let gdt = self.read_gdt_bytes().ok()?;
        let s = self.state.lock();
        let mut best: Option<(u32, u64)> = None;
        for g in 0..groups {
            let Ok(d) = gdt::parse_descriptor(&gdt, g, &self.sb) else { continue };
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
    fn group_for_request(&self, groups: u32, count: u32, hint: u32, best_avail: bool) -> Option<u32> {
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
            // The power-of-two buddy criterion has no candidate. Linux then
            // enters CR_BEST_AVAIL_LEN for regular data and progressively
            // lowers the fragment-size goal by at most three orders before
            // falling through to the ordinary scan. Keep `count` unchanged:
            // this chooses a scan candidate, never a short allocation.
        }
        let s = self.state.lock();
        let mut goals = alloc::vec::Vec::new();
        goals.push(count);
        if best_avail {
            for trim in 1..=3 {
                if let Some(goal) = scan::best_available_goal_len(count, trim) {
                    if !goals.contains(&goal) { goals.push(goal); }
                }
            }
        }
        for goal in goals {
            let wanted = scan::fragment_order_for_len(goal);
            for (_, candidates) in s.group_avg_fragment_index.range(wanted..) {
                if let Some(group) = candidates.range(hint..groups).next()
                    .or_else(|| candidates.iter().next()) {
                    return Some(*group);
                }
            }
        }
        None
    }


    /// Try to find a free bit in `group`. Returns Ok(Some(phys))
    /// on success, Ok(None) if the group is full per its descriptor.
    /// # C: O(block_size)
    fn try_alloc_in_group(&self, group: u32) -> Result<Option<u64>, MountError> {
        let group_lock = self.group_lock(group);
        // SAFETY: process context, with no spinlock held.
        let _group_guard = unsafe { group_lock.lock() };
        // SAFETY: the GDT owner is a sleepable leaf and no spinlock is held.
        let _gdt_guard = unsafe { self.gdt_lock.lock() };
        let mut gdt_bytes = self.read_gdt_bytes()?;
        let gd_orig = gdt::parse_descriptor(&gdt_bytes, group, &self.sb)?;
        if gd_orig.free_blocks_count == 0 { return Ok(None); }
        let bbm_byte_off = gd_orig.block_bitmap * (self.sb.block_size as u64);
        let uninit = gdt::block_uninit(&gdt_bytes, group, &self.sb);
        let cached = self.cached_group_bitmap(bbm_byte_off);
        let mut bitmap = if let Some(bitmap) = cached {
            bitmap
        } else if uninit {
            init_block_bitmap_for_group(&self.sb, &gdt_bytes, group)?
        } else {
            let bitmap = self.read_meta_byte_range(bbm_byte_off, self.sb.block_size as usize)?;
            if !crate::csum::verify_block_bitmap_csum_at(&self.sb, &gdt_bytes, group, &bitmap) {
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
        gdt::write_descriptor_counters(&mut gdt_bytes, group, &self.sb, &gd)?;
        crate::csum::set_block_bitmap_csum(&self.sb, &mut gdt_bytes, group, &disk_bitmap);
        gdt::on_block_allocated(&mut gdt_bytes, group, &self.sb);
        crate::csum::stamp_group_desc_csum(&self.sb, &mut gdt_bytes, group);
        self.metadata_write(bbm_byte_off, &disk_bitmap)?;
        self.persist_gdt_slot_bytes_meta(group, &gdt_bytes)?;
        self.persist_sb_free_blocks_meta(-1)?;
        // Force commit so the next alloc_block within the same
        // outer scope reads the updated bitmap from disk.
        self.flush_pending_tx()?;
        // Cache the authoritative on-disk image; the preallocation-masked
        // `bitmap` is only the allocator's visible scan view.
        self.publish_group_bitmap(group, bbm_byte_off, disk_bitmap);
        let phys = group_first_block(&self.sb, group) + bit as u64;
        Ok(Some(phys))
    }

    /// Reserve one contiguous run in a group and persist its bitmap/counters.
    /// The stripe-aligned candidate is tried first for requests at least as
    /// wide as the configured stripe; an exact goal still follows Linux's
    /// stricter equal-length stripe rule.
    fn try_alloc_run_in_group(&self, group: u32, count: u32, goal_phys: Option<u64>)
        -> Result<Option<Vec<u64>>, MountError>
    {
        self.try_alloc_run_in_group_sized(group, count, goal_phys, false)
    }

    /// Last resort before reporting the volume full: hand back the longest run
    /// the filesystem can still offer, shorter than asked for.
    ///
    /// Every ordinary scan wants one run of the whole request. When the free
    /// space is merely fragmented none exists, and refusing the write reports
    /// ENOSPC on a volume with gigabytes free -- which page writeback delivers
    /// to the writing process as an I/O error. The reference keeps the biggest
    /// extent it saw and uses that.
    ///
    /// Groups are tried richest-first so the grant is as long as the volume can
    /// make it: taking a short run from a nearly full group when a long one is
    /// available elsewhere is what shatters a file into minimum-sized extents,
    /// and the deeper extent tree then costs more than the allocation saved.
    /// # C: O(N_groups) descriptor reads + one group scan
    fn alloc_best_effort_run(&self, count: u32) -> Result<Option<Vec<u64>>, MountError> {
        if count == 0 { return Ok(None); }
        let groups = self.sb.group_count();
        let gdt_bytes = self.read_gdt_bytes()?;
        let mut ranked: Vec<(u32, u32)> = Vec::new();
        for group in 0..groups {
            let gd = gdt::parse_descriptor(&gdt_bytes, group, &self.sb)?;
            let free = u32::from(gd.free_blocks_count);
            if free != 0 { ranked.push((free, group)); }
        }
        ranked.sort_unstable_by(|a, b| b.0.cmp(&a.0));
        for (_, group) in ranked {
            if let Some(run) = self.try_alloc_run_in_group_sized(group, count, None, true)? {
                return Ok(Some(run));
            }
        }
        Ok(None)
    }

    /// `best_effort` takes the longest run this group can offer when none
    /// reaches `count`, the way the reference uses the biggest extent it found
    /// rather than reporting the volume full. The caller maps what it gets and
    /// comes back for the rest.
    /// # C: O(blocks in group) scan + one bitmap/GDT/SB write
    fn try_alloc_run_in_group_sized(&self, group: u32, count: u32, goal_phys: Option<u64>,
        best_effort: bool) -> Result<Option<Vec<u64>>, MountError>
    {
        let group_lock = self.group_lock(group);
        // SAFETY: process context, with no spinlock held.
        let _group_guard = unsafe { group_lock.lock() };
        // SAFETY: the GDT owner is a sleepable leaf and no spinlock is held.
        let _gdt_guard = unsafe { self.gdt_lock.lock() };
        let mut gdt_bytes = self.read_gdt_bytes()?;
        let gd_orig = gdt::parse_descriptor(&gdt_bytes, group, &self.sb)?;
        let floor = if best_effort { 1 } else { count };
        if u32::from(gd_orig.free_blocks_count) < floor { return Ok(None); }
        let bbm_byte_off = gd_orig.block_bitmap * (self.sb.block_size as u64);
        let uninit = gdt::block_uninit(&gdt_bytes, group, &self.sb);
        let cached = self.cached_group_bitmap(bbm_byte_off);
        let mut bitmap = if let Some(bitmap) = cached {
            bitmap
        } else if uninit {
            init_block_bitmap_for_group(&self.sb, &gdt_bytes, group)?
        } else {
            let bitmap = self.read_meta_byte_range(bbm_byte_off, self.sb.block_size as usize)?;
            if !crate::csum::verify_block_bitmap_csum_at(&self.sb, &gdt_bytes, group, &bitmap) {
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
        let goal_bit = goal_phys.and_then(|phys| {
            let bit = phys.checked_sub(first_phys)?;
            (bit < u64::from(blocks)).then_some(bit as u32)
        });
        let goal = goal_bit.and_then(|bit| find_goal_run(
            &bitmap, blocks, count, first_phys, bit, stripe));
        let aligned = if goal.is_none() && count >= stripe && stripe > 1 {
            find_contiguous_run(&bitmap, blocks, count, first_phys, Some(stripe))
        } else { None };
        let start = goal.or(aligned).or_else(|| find_contiguous_run(&bitmap, blocks, count, first_phys, None));
        let (start, count) = match start {
            Some(start) => (start, count),
            None if best_effort => match find_longest_run(&bitmap, blocks, count) {
                Some(found) => found,
                None => return Ok(None),
            },
            None => return Ok(None),
        };
        for bit in start..start + count {
            bitmap[bit as usize >> 3] |= 1u8 << (bit & 7);
            disk_bitmap[bit as usize >> 3] |= 1u8 << (bit & 7);
        }
        let mut gd = gd_orig;
        gd.free_blocks_count = gd.free_blocks_count.saturating_sub(count);
        gdt::write_descriptor_counters(&mut gdt_bytes, group, &self.sb, &gd)?;
        crate::csum::set_block_bitmap_csum(&self.sb, &mut gdt_bytes, group, &disk_bitmap);
        gdt::on_block_allocated(&mut gdt_bytes, group, &self.sb);
        crate::csum::stamp_group_desc_csum(&self.sb, &mut gdt_bytes, group);
        self.metadata_write(bbm_byte_off, &disk_bitmap)?;
        self.persist_gdt_slot_bytes_meta(group, &gdt_bytes)?;
        self.persist_sb_free_blocks_meta(-i64::from(count))?;
        self.flush_pending_tx()?;
        // Cache the authoritative on-disk image; the preallocation-masked
        // `bitmap` is only the allocator's visible scan view.
        self.publish_group_bitmap(group, bbm_byte_off, disk_bitmap);
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

    /// Stage a descriptor's containing filesystem block from the canonical
    /// metadata image. Callers must hold the relevant group/GDT ownership.
    /// # C: O(block_size)
    pub(crate) fn persist_gdt_slot_bytes_meta(&self, group: u32, gdt: &[u8]) -> Result<(), MountError> {
        let dsize = gdt::desc_size_for(&self.sb) as usize;
        let slot_byte = (group as usize) * dsize;
        let bs = self.sb.block_size as usize;
        let blk_idx = slot_byte / bs;
        let byte_off = crate::mount::gdt_block_byte_offset_for(&self.sb, blk_idx as u32);
        let lo = blk_idx * bs;
        let hi = core::cmp::min(lo + bs, gdt.len());
        self.metadata_write(byte_off, &gdt[lo..hi])
    }

    /// Apply a free-block counter delta to the authoritative superblock
    /// buffer and journal it through `metadata_write`.
    /// `metadata_write`.
    /// # C: O(SB read + 1 block write)
    pub(crate) fn persist_sb_free_blocks_meta(&self, delta: i64) -> Result<(), MountError> {
        let mut sb_buf = self.read_meta_byte_range(
            crate::superblock::SUPERBLOCK_OFFSET,
            crate::superblock::SUPERBLOCK_LEN,
        )?;
        let lo = u32::from_le_bytes(sb_buf[SB_OFF_FREE_BLOCKS_LO..SB_OFF_FREE_BLOCKS_LO+4].try_into().unwrap()) as u64;
        let hi = u32::from_le_bytes(sb_buf[SB_OFF_FREE_BLOCKS_HI..SB_OFF_FREE_BLOCKS_HI+4].try_into().unwrap()) as u64;
        let old = lo | (hi << 32);
        let next = if delta >= 0 { old.saturating_add(delta as u64) } else { old.saturating_sub(delta.unsigned_abs()) };
        sb_buf[SB_OFF_FREE_BLOCKS_LO..SB_OFF_FREE_BLOCKS_LO+4].copy_from_slice(&(next as u32).to_le_bytes());
        sb_buf[SB_OFF_FREE_BLOCKS_HI..SB_OFF_FREE_BLOCKS_HI+4].copy_from_slice(&((next >> 32) as u32).to_le_bytes());
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
        // A running JBD2 transaction owns the shadow image. A per-operation
        // bitmap result may be older than another handle's staged bytes, so
        // never publish it into the clean/advisory cache before commit.
        if self.state.lock().shadow.is_some() { return; }
        let mut visible = bitmap.clone();
        self.mask_group_prealloc(group, &mut visible);
        let order = scan::largest_free_order(&visible, self.blocks_in_group(group));
        let avg = scan::average_fragment_order(&visible, self.blocks_in_group(group));
        let mut s = self.state.lock();
        s.block_bitmap_cache.insert(byte_off, bitmap);
        let old_order = s.group_free_order.insert(group, order.unwrap_or(0));
        scan::replace_order_index(&mut s.group_free_order_index, group, old_order, order);
        if order.is_none() { s.group_free_order.remove(&group); }
        let old_avg = s.group_avg_fragment_order.insert(group, avg.unwrap_or(0));
        scan::replace_order_index(&mut s.group_avg_fragment_index, group, old_avg, avg);
        if avg.is_none() { s.group_avg_fragment_order.remove(&group); }
    }

    fn cached_group_bitmap(&self, byte_off: u64) -> Option<Vec<u8>> {
        let s = self.state.lock();
        // Dirty shadow bytes are the sole transaction image; a clean cached
        // bitmap is not eligible while that LBA is staged.
        if s.shadow.as_ref().is_some_and(|shadow| shadow.contains_key(&byte_off)) { return None; }
        s.block_bitmap_cache.get(&byte_off).cloned()
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
    // ext4_mb_measure_extent() does not scan an unbounded number of free
    // extents.  Linux accepts the best candidate after these limits: larger
    // candidates need fewer samples, while unsatisfied candidates get more
    // chances to find a run that can satisfy the request.
    const MAX_TO_SCAN: u32 = 200;
    const MIN_TO_SCAN: u32 = 10;
    let mut best_aligned: Option<(u32, u32)> = None;
    let mut best_any: Option<(u32, u32)> = None;
    let mut found = 0u32;
    let mut run_start = 0;
    let mut run_len = 0;
    let mut consider = |start: u32, len: u32| -> bool {
        if len < count { return false; }
        found += 1;
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
        // An exact extent is Linux's immediate winner.  For an aligned
        // request, an exactly-sized aligned subrange is equally definitive.
        let aligned_exact = best_aligned.is_some_and(|(aligned_len, _)| aligned_len == count);
        if len == count || aligned_exact {
            return true;
        }
        let satisfied = best_aligned.map_or(len >= count, |(available, _)| available >= count);
        if (satisfied && found >= MIN_TO_SCAN) || (!satisfied && found >= MAX_TO_SCAN) {
            return true;
        }
        false
    };
    for bit in 0..=max_bits {
        if bit < max_bits && bitmap[bit as usize >> 3] & (1u8 << (bit & 7)) == 0 {
            if run_len == 0 { run_start = bit; }
            run_len += 1;
            continue;
        }
        let should_stop = if run_len != 0 { consider(run_start, run_len) } else { false };
        run_len = 0;
        if should_stop { break; }
    }
    if let Some((_, start)) = best_aligned { return Some(start); }
    best_any.map(|(_, start)| start)
}

/// Longest free run in this group, capped at `want`, for a request that no
/// single run can satisfy.
///
/// The reference keeps the biggest extent it saw and uses it when nothing
/// reaches the requested length -- "if the request isn't satisfied, any found
/// extent larger than previous best one is better". The length asked for is a
/// maximum; refusing the whole write because no one run reaches it reports a
/// full filesystem while the space is merely fragmented. Taking the LARGEST
/// available run rather than an arbitrary fraction is what keeps the resulting
/// file from being shattered into minimum-sized extents.
/// # C: O(max_bits)
fn find_longest_run(bitmap: &[u8], max_bits: u32, want: u32) -> Option<(u32, u32)> {
    if want == 0 { return None; }
    let mut best: Option<(u32, u32)> = None;
    let mut run_start = 0u32;
    let mut run_len = 0u32;
    let close = |start: u32, len: u32, best: &mut Option<(u32, u32)>| {
        if len == 0 { return; }
        let take = len.min(want);
        if best.is_none_or(|(best_len, _)| take > best_len) { *best = Some((take, start)); }
    };
    for bit in 0..=max_bits {
        if bit < max_bits && bitmap[bit as usize >> 3] & (1u8 << (bit & 7)) == 0 {
            if run_len == 0 { run_start = bit; }
            run_len += 1;
            continue;
        }
        close(run_start, run_len, &mut best);
        run_len = 0;
        if best.is_some_and(|(len, _)| len == want) { break; }
    }
    best.map(|(len, start)| (start, len))
}

/// Fast Linux `TRY_GOAL` check: accept the exact physical goal when the
/// complete request is free there; otherwise the caller falls through to the
/// normal bounded candidate scan. # C: O(request)
fn find_goal_run(bitmap: &[u8], max_bits: u32, count: u32, first_phys: u64,
                 goal: u32, stripe: u32) -> Option<u32> {
    if count == 0 || goal.checked_add(count)? > max_bits { return None; }
    if count == stripe && stripe > 1
        && (first_phys + u64::from(goal)) % u64::from(stripe) != 0 { return None; }
    for bit in goal..goal + count {
        if bitmap[bit as usize >> 3] & (1u8 << (bit & 7)) != 0 { return None; }
    }
    Some(goal)
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
