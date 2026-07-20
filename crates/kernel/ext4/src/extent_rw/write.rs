use crate::inode;
use crate::extent_rw::meta::InodeMetaUpdate;
use crate::mount::{Mount, MountError};

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
        pending.sort_by_key(|(p, _)| *p);
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
        self.run_journaled(|m| m.write_at_inner(ino, off, data, None))
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

            // Linux fallocate: map the range as UNWRITTEN extents — allocate the
            // blocks but do NOT zero them (reads serve zeros via the unwritten
            // flag; a later write converts the touched subrange). This replaces
            // the O(range) eager zero-write that made journald's multi-MB journal
            // preallocation a per-block alloc+write storm.
            let mut allocated = alloc::vec::Vec::new();
            for lb in first_lb..=last_lb {
                let inode = m.read_inode(ino)?;
                let was_mapped = m.collect_phys_extents(&inode.i_block)?
                    .iter()
                    .any(|r| lb >= r.logical && lb < r.logical + r.len);
                let visible_size = core::cmp::max(inode.size, (lb as u64 + 1) * bs);
                if let Err(e) = m.map_unwritten_block_inner(ino, lb, visible_size) {
                    let _ = m.rollback_allocated_logical_blocks(ino, old_size, &allocated);
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
        let last_lb  = ((end - 1) / bs) as u32;
        // (phys_block, assembled block bytes) in logical order.
        let mut pending: alloc::vec::Vec<(u64, alloc::vec::Vec<u8>)> = alloc::vec::Vec::new();
        let mut allocated = alloc::vec::Vec::new();
        let mut written = 0usize;
        for lb in first_lb..=last_lb {
            // An UNWRITTEN (fallocate-preallocated) extent must be converted to a
            // written extent before write_file_block (else it rejects with
            // NotFound). No-op for a written extent or a hole.
            self.convert_unwritten_at(ino, lb)?;
            let inode2 = self.read_inode(ino)?;
            let blk_start_byte = (lb as u64) * bs;
            let in_blk_off = if blk_start_byte >= off { 0usize }
                             else { (off - blk_start_byte) as usize };
            let blk_end_byte = blk_start_byte + bs;
            let copy_end_in_blk = if end >= blk_end_byte { bs_us }
                                  else { (end - blk_start_byte) as usize };
            let copy_len = copy_end_in_blk - in_blk_off;
            let full_block = in_blk_off == 0 && copy_len == bs_us;
            // Is this logical block already mapped to a real (written) block?
            let mapped = self.resolve_pblock(&inode2, lb).is_ok();
            // Base contents: the existing block if mapped, else zeros (a hole /
            // partial-block write starts from zeros — Linux sparse semantics).
            // A full-block write fully specifies the block, so skip the read.
            let mut blk = if full_block {
                alloc::vec![0u8; bs_us]
            } else if mapped {
                self.read_file_block(&inode2, lb)?
            } else {
                alloc::vec![0u8; bs_us]
            };
            if blk.len() < bs_us { blk.resize(bs_us, 0); }
            blk[in_blk_off..in_blk_off + copy_len]
                .copy_from_slice(&data[written .. written + copy_len]);
            let phys = if mapped {
                self.resolve_pblock(&inode2, lb)?
            } else {
                // Allocate + map THIS logical block as a WRITTEN extent (leaving
                // the gap holes) WITHOUT writing the data now — deferred to the
                // coalesced flush below. `extent_vec_contains` guards a re-map.
                let vis = core::cmp::max(inode2.size, blk_end_byte);
                let (mut ib, ioff) = self.read_inode_bytes(ino)?;
                self.alloc_written_block_defer(ino, &mut ib, ioff, lb, vis)?;
                let inode3 = self.read_inode(ino)?;
                allocated.push(lb);
                self.resolve_pblock(&inode3, lb)?
            };
            pending.push((phys, blk));
            written += copy_len;
        }
        if let Err(e) = self.flush_pending_data_writes(pending) {
            if let Err(rb) = self.rollback_allocated_logical_blocks(ino, cur_size, &allocated) { return Err(rb); }
            return Err(e);
        }
        // Persist the (potentially partial-block) i_size.
        if let Err(e) = self.set_inode_size_with_meta(ino, new_size, meta) {
            if let Err(rb) = self.rollback_allocated_logical_blocks(ino, cur_size, &allocated) { return Err(rb); }
            return Err(e);
        }
        Ok(())
    }
}
