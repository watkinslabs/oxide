use alloc::vec;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

use crate::inode;
use crate::extent_rw::meta::InodeMetaUpdate;
use crate::mount::{Mount, MountError};

use super::collect::PhysRun;

struct ReservedRun {
    logical_start: u32,
    blocks: Vec<u64>,
    from_inode_pa: bool,
    from_group_pa: bool,
    group_cpu: Option<usize>,
    /// Fresh data reservation beyond this operation's requested range.
    prefix_start: Option<u32>,
    prefix_blocks: Vec<u64>,
    tail_start: Option<u32>,
    tail_blocks: Vec<u64>,
}

const GROUP_PREALLOC_MAX_REQUEST: u32 = 16;

/// Reserve each contiguous logical hole in one Linux-shaped mballoc request.
/// An existing extent terminates a request; physical contiguity must never be
/// claimed across a mapped logical block. # C: O(N_extents + N_hole_runs)
fn reserve_hole_runs(m: &Mount, first: u32, last: u32, extents: &[PhysRun], ino: u32,
    current_size: u64, preallocate: bool) -> Result<Vec<ReservedRun>, MountError>
{
    let mut runs = Vec::new();
    let mut cursor = first as u64;
    let end = last as u64;
    let is_mapped = |lb: u32| {
        extents.iter().any(|r| {
            let start = r.logical as u64;
            lb as u64 >= start && (lb as u64) < start + r.len as u64
        })
    };
    while cursor <= end {
        let lb = cursor as u32;
        if is_mapped(lb) {
            cursor += 1;
            continue;
        }
        let start = cursor;
        while cursor <= end && !is_mapped(cursor as u32) { cursor += 1; }
        let count = (cursor - start) as u32;
        if preallocate {
            if let Some(blocks) = m.peek_inode_prealloc(ino, start as u32, count) {
                if !blocks.is_empty() {
                    let used = blocks.len() as u32;
                    runs.push(ReservedRun { logical_start: start as u32, blocks,
                        from_inode_pa: true, from_group_pa: false,
                        group_cpu: None,
                        prefix_start: None, prefix_blocks: Vec::new(),
                        tail_start: None, tail_blocks: Vec::new() });
                    cursor = start + u64::from(used);
                    continue;
                }
            }
        }
        // Linux derives the allocation context's goal from the inode's
        // neighbouring extent, so a fallocate on an existing file stays near
        // that file instead of restarting every multiblock request at group 0.
        let goal_phys = extents.iter().rev().find(|r| u64::from(r.logical) <= start)
            .and_then(|r| r.phys.checked_add(u64::from(r.len)))
            .or_else(|| extents.first().map(|r| r.phys));
        let hint = goal_phys.map(|phys| m.group_of_block(phys)).unwrap_or(0);
        let group_prealloc = preallocate
            && count <= GROUP_PREALLOC_MAX_REQUEST
            && super::prealloc::group_prealloc_eligible(
                m.sb.block_size as u64, current_size, start as u32, count);
        // Linux captures the locality-group pointer before mballoc can block;
        // retain that owner for a fresh PA tail even if this task migrates
        // before the reservation is published.
        let group_owner = group_prealloc.then(crate::balloc::prealloc::locality_cpu);
        if group_prealloc {
            if let Some((group_cpu, _pa_group, blocks)) = m.peek_group_prealloc_owner(
                count, goal_phys.unwrap_or_else(|| crate::balloc::group_first_block(&m.sb, hint))) {
                runs.push(ReservedRun { logical_start: start as u32, blocks,
                    from_inode_pa: false, from_group_pa: true,
                    group_cpu: Some(group_cpu),
                    prefix_start: None, prefix_blocks: Vec::new(),
                    tail_start: None, tail_blocks: Vec::new() });
                cursor = start + u64::from(count);
                continue;
            }
        }
        let (allocation_start, reserve_count, mut normalized) = if preallocate {
            let (normalized_start, normalized_end) = super::prealloc::normalized_range(
                m.sb.block_size as u64, current_size, start as u32, count,
                m.sb.blocks_per_group);
            let normalized_clear = count > GROUP_PREALLOC_MAX_REQUEST
                && normalized_start <= start
                && normalized_end >= start + u64::from(count)
                && !extents.iter().any(|r| {
                    let extent_start = u64::from(r.logical);
                    let extent_end = extent_start + u64::from(r.len);
                    extent_start < normalized_end && normalized_start < extent_end
                });
            if normalized_clear {
                (normalized_start, normalized_end.saturating_sub(normalized_start)
                    .min(u64::from(u32::MAX)) as u32, true)
            } else {
                (start, count, false)
            }
        } else { (start, count, false) };
        let mut reserve_count = if normalized {
            reserve_count
        } else if preallocate {
            count.saturating_add(if group_prealloc {
                super::prealloc::group_prealloc_blocks(
                    m.sb.block_size as u64, m.behaviour().stripe)
            } else { super::prealloc::tail_blocks(m.sb.block_size as u64, current_size, start as u32, count) })
        } else { count };
        let normalized_prefix = start.saturating_sub(allocation_start) as usize;
        let flags = m.data_reserve_flags(ino);
        let stream_ino = if preallocate && !group_prealloc { Some(ino) } else { None };
        let mut allocated = m.alloc_blocks_for_inode_goal(stream_ino, hint, reserve_count, flags, goal_phys);
        if matches!(&allocated, Err(MountError::NoSpace)) && group_prealloc {
            // A stripe-rounded locality request is a preference. Retry with
            // progressively smaller group PAs before accepting an exact run;
            // Linux mballoc can shorten a PA when a full group reservation
            // does not fit in one free extent.
            let mut tail = super::prealloc::group_prealloc_blocks(
                m.sb.block_size as u64, 0) / 2;
            while tail >= 32 {
                let candidate = count.saturating_add(tail);
                allocated = m.alloc_blocks_for_inode_goal(stream_ino, hint, candidate, flags, goal_phys);
                if allocated.is_ok() { break; }
                tail /= 2;
            }
        }
        if matches!(&allocated, Err(MountError::NoSpace)) && reserve_count != count {
            normalized = false;
            reserve_count = count;
            allocated = m.alloc_blocks_for_inode_goal(stream_ino, hint, count, flags, goal_phys);
        }
        match allocated {
            Ok(blocks) => {
                // The run's leading blocks belong to the caller only when the
                // request was normalized; the slice below has to use the same
                // offset the length is measured from. Read from one place: the
                // slice took its start from the normalized prefix while its end
                // was measured from zero, which disagreed whenever
                // normalization was off.
                // A grant shorter than the normalized shape is not that shape:
                // its blocks are all the caller's, with no leading reservation
                // to skip. Keeping the prefix here can leave nothing for the
                // request itself, and a zero-length run advances no cursor.
                let short = blocks.len() < normalized_prefix + count as usize;
                let prefix_len = if normalized && !short { normalized_prefix } else { 0 };
                // What the allocator granted. On a fragmented volume the last
                // resort hands back the longest run it could find, which is
                // shorter than what was asked for.
                let requested = core::cmp::min(
                    count as usize, blocks.len().saturating_sub(prefix_len));
                if requested == 0 {
                    for &block in blocks.iter() { let _ = m.free_block(block); }
                    return Err(MountError::NoSpace);
                }
                let request_end = prefix_len + requested;
                let prefix = blocks[..prefix_len].to_vec();
                let tail = blocks[request_end..].to_vec();
                // Linux keeps an inode PA tail free on disk and masks it only
                // in the in-memory buddy bitmap.
                for (n, &block) in prefix.iter().chain(tail.iter()).enumerate() {
                    if let Err(e) = m.free_block(block) {
                        for &rollback in &blocks[prefix_len..request_end] { let _ = m.free_block(rollback); }
                        for &rollback in prefix.iter().chain(tail.iter()).skip(n + 1) { let _ = m.free_block(rollback); }
                        return Err(e);
                    }
                }
                runs.push(ReservedRun { logical_start: start as u32,
                    blocks: blocks[prefix_len..request_end].to_vec(), from_inode_pa: false,
                    from_group_pa: false,
                    group_cpu: None,
                    prefix_start: if prefix.is_empty() || group_prealloc { None } else {
                        Some(allocation_start as u32)
                    }, prefix_blocks: if group_prealloc { Vec::new() } else { prefix },
                    tail_start: if tail.is_empty() || group_prealloc { None } else {
                        Some(start.saturating_add(u64::from(count)) as u32)
                    }, tail_blocks: if group_prealloc {
                        Vec::new()
                    } else { tail.clone() } });
                if group_prealloc && !tail.is_empty() {
                    m.add_group_prealloc_on_cpu(
                        group_owner.unwrap_or_else(crate::balloc::prealloc::locality_cpu),
                        m.group_of_block(tail[0]), count, tail);
                }
                // A short grant leaves the rest of this hole unmapped; come
                // back for it rather than reporting the whole write failed.
                if (requested as u32) < count { cursor = start + requested as u64; }
            }
            Err(e) => {
                for run in &runs {
                    if !run.from_inode_pa && !run.from_group_pa {
                        for &block in &run.blocks {
                            let _ = m.free_block(block);
                        }
                    }
                }
                restore_group_reservations(m, &runs);
                return Err(e);
            }
        }
    }
    Ok(runs)
}

fn take_reserved(runs: &[ReservedRun], offsets: &mut [usize], lb: u32)
    -> Option<(u64, bool, bool, Option<usize>)> {
    for (idx, run) in runs.iter().enumerate() {
        if lb < run.logical_start { break; }
        let at = (lb - run.logical_start) as usize;
        if at < run.blocks.len() {
            if offsets[idx] != at { return None; }
            offsets[idx] += 1;
            return Some((run.blocks[at], run.from_inode_pa, run.from_group_pa, run.group_cpu));
        }
    }
    None
}

fn restore_group_reservations(m: &Mount, runs: &[ReservedRun]) {
    for run in runs {
        if !run.from_group_pa || run.blocks.is_empty() { continue; }
        let cpu = run.group_cpu.unwrap_or_else(crate::balloc::prealloc::locality_cpu);
        m.restore_group_prealloc_on_cpu(cpu, m.group_of_block(run.blocks[0]), run.blocks.clone());
    }
}

impl Mount {
    fn rollback_allocated_logical_blocks(&self, ino: u32, old_size: u64, blocks: &[u32])
        -> Result<(), MountError>
    {
        let bs = self.sb.block_size as u64;
        let mut first_err = None;
        for &lb in blocks.iter().rev() {
            let before_sectors = self.read_inode(ino).map(|i| i.i_blocks).ok();
            if let Err(e) = self.punch_hole_inode(ino, lb as u64 * bs, bs) {
                let mut err = e;
                if let (Some(before), Ok(after)) = (before_sectors, self.read_inode(ino)) {
                    if before <= u32::MAX as u64 && after.i_blocks <= u32::MAX as u64 {
                        if let Err(qe) = self.account_i_blocks_delta(ino, before as u32, after.i_blocks as u32) { err = qe; }
                    }
                }
                if first_err.is_none() { first_err = Some(err); }
            }
        }
        if let Err(e) = self.set_inode_size(ino, old_size) {
            if first_err.is_none() { first_err = Some(e); }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
    /// Write a list of `(physical_block, block_bytes)` in COALESCED runs: sort
    /// by physical block, then issue ONE `write_byte_range` per maximal run of
    /// contiguous physical blocks (capped at the device's max request so the
    /// virtio-blk bounce buffer isn't overrun). Collapses a fresh sequential
    /// file's per-4KB-block writes (contiguous by the allocator) into ~one
    /// request per 128KB — the systemd-hwdb fsync-stall fix. Data-only: callers
    /// must have already mapped the WRITTEN extents (data=ordered — the writes
    /// land before the batch commit persists the metadata).
    /// # C: O(N log N) sort + O(N/COALESCE) device requests
    fn flush_pending_data_writes(&self, mut pending: alloc::vec::Vec<(u64, alloc::vec::Vec<u8>)>) -> Result<(), MountError> {
        if pending.is_empty() { return Ok(()); }
        let bs = self.sb.block_size as u64;
        // Match the virtio-blk single-request data cap (BOUNCE_DATA_BYTES) so
        // one coalesced write is one device op; a larger run splits here.
        let max_blocks = ((super::DATA_WRITE_CLUSTER_BYTES as u64) / bs).max(1);
        // The stable slice sort is correct for duplicate physical blocks
        // (last submission wins), but its driftsort scratch frame is several
        // KiB and is live through this already deep UMH/ext4 path. A tree
        // gives the same ordered, last-write-wins result without putting the
        // sorting algorithm's frame on the kernel stack.
        let mut ordered = BTreeMap::new();
        for (phys, data) in pending.drain(..) { ordered.insert(phys, data); }
        pending = ordered.into_iter().collect();
        let mut i = 0usize;
        while i < pending.len() {
            let start = pending[i].0;
            let mut buf = core::mem::take(&mut pending[i].1);
            let mut next = start + 1;
            let mut j = i + 1;
            while j < pending.len() && pending[j].0 == next && (next - start) < max_blocks {
                buf.extend_from_slice(&pending[j].1);
                next += 1;
                j += 1;
            }
            self.write_data_byte_range(start * bs, &buf)?;
            i = j;
        }
        Ok(())
    }

    /// Patch the on-disk inode `i_size` field directly.
    /// # C: O(1) I/O
    pub fn set_inode_size(&self, ino: u32, size: u64) -> Result<(), MountError> {
        self.set_inode_size_with_meta(ino, size, None)
    }

    pub(crate) fn set_inode_size_with_meta(&self, ino: u32, size: u64, meta: Option<InodeMetaUpdate>)
        -> Result<(), MountError>
    {
        let (mut bytes, _off) = self.read_inode_bytes(ino)?;
        bytes[0x04..0x08].copy_from_slice(&((size & 0xFFFF_FFFF) as u32).to_le_bytes());
        bytes[0x6C..0x70].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
        if let Some(meta) = meta { self.stamp_inode_meta_fields(&mut bytes, meta); }
        self.write_inode_bytes_data(ino, &bytes)
    }

    /// Random-access write: `data` lands at byte offset `off` in
    /// the file at `ino`, extending the file (with zero-filled
    /// blocks if needed) when `off + data.len() > i_size`. Existing
    /// blocks touched by the write are RMW'd in-place. The trailing
    /// `i_size` is set to `max(prev_size, off + data.len())`.
    /// Caller invalidates any page cache.
    /// # C: O(file growth + N_blocks_in_range) I/O
    pub fn write_at(&self, ino: u32, off: u64, data: &[u8]) -> Result<(), MountError> {
        self.run_journaled(|m| m.write_at_inner(ino, off, data, None))
    }

    /// Allocate the blocks touched by a buffered write when delayed allocation
    /// is disabled. Keep them unwritten until page writeback supplies data, so
    /// metadata publication cannot expose stale media contents. Carry the
    /// journal-visible inode image through the range: the old loop reread the
    /// inode table once per block. # C: O(N_blocks × N_extents) + 1 inode read
    pub(crate) fn prepare_nodelalloc(&self, ino: u32, off: u64, len: usize) -> Result<(), MountError> {
        if len == 0 { return Ok(()); }
        let flags = self.read_inode(ino)?.i_flags;
        if flags & (inode::EXT4_INLINE_DATA_FL | inode::EXT4_EXTENTS_FL) == 0 {
            // Legacy indirect writeback owns allocation at write time through
            // `write_legacy_at_inner`; it has no unwritten-extent state to
            // pre-install here. Do not send its pointer array to the extent
            // parser merely because nodelalloc is enabled.
            return Ok(());
        }
        if flags & inode::EXT4_INLINE_DATA_FL != 0 { return Ok(()); }
        let bs = self.sb.block_size as u64;
        let end = off.checked_add(len as u64).ok_or(MountError::Inode(inode::InodeError::BadLen))?;
        let first = off / bs;
        let last = (end - 1) / bs;
        if last > u32::MAX as u64 { return Err(MountError::Inode(inode::InodeError::BadLen)); }
        self.run_journaled(|m| {
            let (mut inode_bytes, inode_byte_off) = m.read_inode_bytes(ino)?;
            for logical in first..=last {
                let inode = inode::Inode::parse(&inode_bytes, &m.sb)?;
                let mapped = m.collect_phys_extents(&inode.i_block)?.iter().any(|run|
                    logical >= u64::from(run.logical)
                        && logical < u64::from(run.logical) + u64::from(run.len));
                if !mapped {
                    m.map_unwritten_block_inner_with_inode_bytes(
                        ino, &mut inode_bytes, inode_byte_off, logical as u32,
                        core::cmp::max(inode.size, end), None)?;
                }
            }
            Ok(())
        })
    }

    /// Allocate backing blocks through `offset + len`. With `keep_size`, the
    /// original `i_size` is restored after allocation without freeing extents.
    /// # C: O(file growth)
    pub fn fallocate_inode(&self, ino: u32, offset: u64, len: u64, keep_size: bool) -> Result<(), MountError> {
        let end = offset.checked_add(len).ok_or(MountError::Inode(inode::InodeError::BadLen))?;
        if len == 0 { return Ok(()); }
        self.run_journaled(|m| {
            let mut current = m.read_inode(ino)?;
            // Linux ext4 converts inline data before entering any fallocate
            // mode. Inline payload bytes are not an indirect pointer tree.
            if current.i_flags & inode::EXT4_INLINE_DATA_FL != 0 {
                m.convert_inline_data(ino, &current, 0, &[])?;
                current = m.read_inode(ino)?;
            }
            if current.i_flags & inode::EXT4_EXTENTS_FL == 0 {
                return m.fallocate_legacy_inode_inner(ino, offset, len, keep_size);
            }
            let old_size = current.size;
            let bs = m.sb.block_size as u64;
            let first_lb64 = offset / bs;
            let last_lb64 = (end - 1) / bs;
            if first_lb64 > u32::MAX as u64 || last_lb64 > u32::MAX as u64 {
                return Err(MountError::Inode(inode::InodeError::BadLen));
            }
            let first_lb = first_lb64 as u32;
            let last_lb = last_lb64 as u32;
            let final_size = if keep_size { old_size } else { core::cmp::max(old_size, end) };

            // Linux fallocate: map the range as UNWRITTEN extents — allocate the
            // blocks but do NOT zero them (reads serve zeros via the unwritten
            // flag; a later write converts the touched subrange). This replaces
            // the O(range) eager zero-write that made journald's multi-MB journal
            // preallocation a per-block alloc+write storm.
            let mut allocated = alloc::vec::Vec::new();
            // One fallocate request can contain both mapped and hole blocks.
            // Linux mballoc reserves the missing part as one request; do not
            // turn a partial range back into one bitmap scan per hole.
            let (mut inode_bytes, inode_byte_off) = m.read_inode_bytes(ino)?;
            let initial = inode::Inode::parse(&inode_bytes, &m.sb)?;
            let extents = m.collect_phys_extents(&initial.i_block)?;
            let reserved = reserve_hole_runs(m, first_lb, last_lb, &extents, ino, old_size, false)?;
            let mut reserved_at = vec![0usize; reserved.len()];
            for lb in first_lb..=last_lb {
                // `insert_logical_block_with_inode_bytes` updates this image
                // after each successful mapping. Keep extent membership local
                // to the request instead of issuing one inode-table read per
                // block (the old loop made fallocate O(N) metadata reads).
                let inode = inode::Inode::parse(&inode_bytes, &m.sb)?;
                let was_mapped = m.collect_phys_extents(&inode.i_block)?
                    .iter()
                    .any(|r| lb >= r.logical && lb < r.logical + r.len);
                let visible_size = core::cmp::max(inode.size, (lb as u64 + 1) * bs);
                let physical = if was_mapped { None } else {
                    take_reserved(&reserved, &mut reserved_at, lb).map(|(block, _, _, _)| block)
                };
                if let Err(e) = m.map_unwritten_block_inner_with_inode_bytes(
                    ino, &mut inode_bytes, inode_byte_off, lb, visible_size, physical) {
                    let _ = m.rollback_allocated_logical_blocks(ino, old_size, &allocated);
                    for (idx, run) in reserved.iter().enumerate() {
                        for &block in run.blocks.iter().skip(reserved_at[idx]) {
                            let _ = m.free_block(block);
                        }
                    }
                    return Err(e);
                }
                if !was_mapped { allocated.push(lb); }
            }
            if let Err(e) = m.set_inode_size(ino, final_size) {
                let _ = m.rollback_allocated_logical_blocks(ino, old_size, &allocated);
                return Err(e);
            }
            Ok(())
        })
    }

    pub(super) fn write_at_inner(&self, ino: u32, off: u64, data: &[u8], meta: Option<InodeMetaUpdate>)
        -> Result<(), MountError>
    {
        let bs = self.sb.block_size as u64;
        let bs_us = bs as usize;
        if data.is_empty() { return Ok(()); }
        let inode = self.read_inode(ino)?;
        if super::super::mount::inline::write_inline_data(self, ino, &inode, off, data)? {
            return Ok(());
        }
        if inode.i_flags & inode::EXT4_EXTENTS_FL == 0 {
            return self.write_legacy_at_inner(ino, off, data, meta);
        }
        let cur_size = inode.size;
        let end = off + data.len() as u64;
        let new_size = core::cmp::max(cur_size, end);
        let cur_blocks = (cur_size + bs - 1) / bs;
        let new_blocks = (new_size + bs - 1) / bs;
        // NO eager zero-extend: the gap between the old EOF and the write offset
        // is left as a HOLE (Linux sparse-file semantics — reads serve zeros via
        // read_file_block). The old code appended a zero block for EVERY block in
        // `cur_blocks..new_blocks`, so a write landing far past EOF (e.g.
        // out-of-order page-cache writeback) allocated + zero-wrote the whole
        // span — the O(file-size) writeback stall the `[WAEXT]` probe hunted.
        let _ = (cur_blocks, new_blocks);
        // DIAG (debug-wakelat): flag a write landing far past the current EOF.
        #[cfg(feature = "debug-wakelat")]
        {
            use core::sync::atomic::{AtomicU64, Ordering};
            static WA: AtomicU64 = AtomicU64::new(0);
            let span = new_blocks.saturating_sub(cur_blocks);
            let k = WA.fetch_add(1, Ordering::Relaxed);
            if span > 4 || (new_size >> 24) != (cur_size >> 24) || k < 8 {
                klog::write_raw(b"[WAEXT ino="); klog::write_dec_u64(ino as u64);
                klog::write_raw(b" off="); klog::write_hex_u64(off);
                klog::write_raw(b" cursz="); klog::write_dec_u64(cur_size);
                klog::write_raw(b" newsz="); klog::write_dec_u64(new_size);
                klog::write_raw(b" span="); klog::write_dec_u64(span);
                klog::write_raw(b"]\n");
            }
        }
        // RMW / map each touched block; blocks in the gap are never mapped.
        // Each block's assembled bytes + its physical block are collected into
        // `pending`, then written in COALESCED runs (contiguous physical blocks
        // in ONE device request, up to a device-request cap). Under the
        // single-inflight virtio-blk driver a fresh large file (systemd-hwdb's
        // 13.5MB) was ~3456 serialised 4KB writes; the allocator hands out
        // contiguous blocks (find_first_clear), so coalescing collapses them to
        // ~1 request per 128KB. Data blocks are written direct-to-target
        // (data=ordered), so deferring + coalescing the writes is correct: they
        // all land before the batch commit persists the (already-WRITTEN)
        // extents. Partial-block edges keep the per-block RMW.
        let first_lb = (off / bs) as u32;
        let last_lb64 = (end - 1) / bs;
        if last_lb64 > u32::MAX as u64 {
            return Err(MountError::Inode(inode::InodeError::BadLen));
        }
        let last_lb = last_lb64 as u32;
        // (phys_block, assembled block bytes) in logical order.
        let mut pending: alloc::vec::Vec<(u64, alloc::vec::Vec<u8>)> = alloc::vec::Vec::new();
        let mut allocated = alloc::vec::Vec::new();
        // `inode` is the live snapshot read at the top of this operation.  It
        // is still the authoritative extent tree here; no metadata mutation
        // occurs before the reservation plan is built.  Re-reading the same
        // inode added one serialized metadata lookup to every writeback
        // cluster and kept the caller's inode lock held across it.
        // The write path also serves legacy indirect inodes.  Linux resolves
        // their mapping through ext4_ind_map_blocks; do not parse the legacy
        // i_block pointer array as an extent root here.  The collected runs
        // are only the reservation snapshot, while the per-block resolver
        // below remains the authoritative mapping owner.
        let initial_extents = self.collect_inode_phys_extents(&inode)?;
        // A write that starts beyond the current EOF is a sparse write, not a
        // stream allocation. Linux leaves that gap unallocated; inode PA is
        // eligible only when the request reaches the current file tail.
        // Linux data PAs belong to regular-file allocation contexts. Directory
        // block writes use ordinary metadata allocation and must never seed a
        // data PA that a later file could consume.
        let allow_prealloc = inode.is_reg() && u64::from(first_lb) <= cur_blocks;
        let reserved = reserve_hole_runs(
            self, first_lb, last_lb, &initial_extents, ino, cur_size, allow_prealloc
        )?;
        let mut reserved_at = vec![0usize; reserved.len()];
        // Keep the inode/extent snapshot in-core for the common mapped-block
        // path. Linux writeback carries one inode context through the extent
        // walk; rereading the inode-table block for every logical block turns
        // a clustered writeback BIO into serialized metadata I/O. Refresh it
        // only after an operation that actually changes the extent state.
        let mut current_inode = inode;
        let mut written = 0usize;
        for lb in first_lb..=last_lb {
            // An UNWRITTEN (fallocate-preallocated) extent must be converted to a
            // written extent before write_file_block (else it rejects with
            // NotFound). No-op for a written extent or a hole.
            let converted = self.convert_unwritten_at_cached(ino, lb, &current_inode)?;
            if converted { current_inode = self.read_inode(ino)?; }
            let inode2 = current_inode;
            let blk_start_byte = (lb as u64) * bs;
            let in_blk_off = if blk_start_byte >= off { 0usize }
                             else { (off - blk_start_byte) as usize };
            let blk_end_byte = blk_start_byte + bs;
            let copy_end_in_blk = if end >= blk_end_byte { bs_us }
                                  else { (end - blk_start_byte) as usize };
            let copy_len = copy_end_in_blk - in_blk_off;
            let full_block = in_blk_off == 0 && copy_len == bs_us;
            // Resolve once and retain the physical result.  The old path
            // walked the same extent tree again after assembling the block,
            // and worse, collapsed every lookup error into "hole".  A real
            // corrupt-tree/I/O error must not turn into a fresh allocation.
            let mapped_phys = match self.resolve_pblock(&inode2, lb) {
                Ok(phys) => Some(phys),
                Err(MountError::NotFound) => None,
                Err(error) => return Err(error),
            };
            // Base contents: the existing block if mapped, else zeros (a hole /
            // partial-block write starts from zeros — Linux sparse semantics).
            // A full-block write fully specifies the block, so skip the read.
            let mut blk = if full_block {
                alloc::vec![0u8; bs_us]
            } else if mapped_phys.is_some() {
                self.read_file_block(&inode2, lb)?
            } else {
                alloc::vec![0u8; bs_us]
            };
            if blk.len() < bs_us { blk.resize(bs_us, 0); }
            blk[in_blk_off..in_blk_off + copy_len]
                .copy_from_slice(&data[written .. written + copy_len]);
            let phys = if let Some(mapped_phys) = mapped_phys {
                mapped_phys
            } else {
                // Allocate + map THIS logical block as a WRITTEN extent (leaving
                // the gap holes) WITHOUT writing the data now — deferred to the
                // coalesced flush below. `extent_vec_contains` guards a re-map.
                let vis = core::cmp::max(inode2.size, blk_end_byte);
                let (mut ib, ioff) = self.read_inode_bytes(ino)?;
                let physical = take_reserved(&reserved, &mut reserved_at, lb);
                let pa_phys = physical.and_then(|(block, from_inode_pa, from_group_pa, group_cpu)|
                    (from_inode_pa || from_group_pa).then_some((block, from_inode_pa, from_group_pa, group_cpu)));
                if let Some((block, _, _, _)) = pa_phys {
                    if let Err(e) = self.claim_prealloc_block(block) {
                        let rollback = self.rollback_allocated_logical_blocks(ino, cur_size, &allocated);
                        restore_group_reservations(self, &reserved);
                        if let Err(rb) = rollback { return Err(rb); }
                        return Err(e);
                    }
                }
                if let Err(e) = self.alloc_written_block_defer_with_physical(
                    ino, &mut ib, ioff, lb, vis, physical.map(|(block, _, _, _)| block)) {
                    if let Some((block, from_inode_pa, from_group_pa, _group_cpu)) = pa_phys {
                        // The extent inserter owns cleanup of the claimed
                        // physical block on every post-selection error.
                        if from_inode_pa {
                            let _ = self.rollback_inode_prealloc_claim(ino, lb, block);
                        }
                        if from_group_pa {
                            let _ = self.free_block(block);
                        }
                    }
                    let rollback = self.rollback_allocated_logical_blocks(ino, cur_size, &allocated);
                    restore_group_reservations(self, &reserved);
                    for (idx, run) in reserved.iter().enumerate() {
                        for &block in run.blocks.iter().skip(reserved_at[idx]) {
                            if !run.from_inode_pa && !run.from_group_pa { let _ = self.free_block(block); }
                        }
                    }
                    if let Err(rb) = rollback { return Err(rb); }
                    return Err(e);
                }
                // The inserter updates `ib` through the same journal-visible
                // inode image it publishes. Re-parse that image directly;
                // rereading the inode table here duplicated one metadata read
                // for every newly mapped block in a clustered writeback.
                current_inode = inode::Inode::parse(&ib, &self.sb)?;
                if let Some((block, from_inode_pa, from_group_pa, group_cpu)) = pa_phys {
                    if from_inode_pa { let _ = self.consume_inode_prealloc(ino, lb); }
                    if from_group_pa {
                        let cpu = group_cpu.unwrap_or_else(crate::balloc::prealloc::locality_cpu);
                        let _ = self.consume_group_prealloc_on_cpu(cpu, self.group_of_block(block), block);
                    }
                }
                allocated.push(lb);
                self.resolve_pblock(&current_inode, lb)?
            };
            pending.push((phys, blk));
            written += copy_len;
        }
        if let Err(e) = self.flush_pending_data_writes(pending) {
            let rollback = self.rollback_allocated_logical_blocks(ino, cur_size, &allocated);
            restore_group_reservations(self, &reserved);
            if let Err(rb) = rollback { return Err(rb); }
            return Err(e);
        }
        // Persist the (potentially partial-block) i_size.
        if let Err(e) = self.set_inode_size_with_meta(ino, new_size, meta) {
            let rollback = self.rollback_allocated_logical_blocks(ino, cur_size, &allocated);
            restore_group_reservations(self, &reserved);
            if let Err(rb) = rollback { return Err(rb); }
            return Err(e);
        }
        for run in &reserved {
            if let Some(start) = run.prefix_start {
                self.add_inode_prealloc(ino, start, run.prefix_blocks.clone());
            }
            if let Some(start) = run.tail_start {
                self.add_inode_prealloc(ino, start, run.tail_blocks.clone());
            }
        }
        Ok(())
    }
}
