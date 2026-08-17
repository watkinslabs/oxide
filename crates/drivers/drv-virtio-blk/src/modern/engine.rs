// The synchronous single-turn request path and the `BlockDevice` surface.
// Asynchronous posting lives in `post.rs`, completion walking in `drain.rs`,
// queue selection in `queues.rs`, teardown in `teardown.rs`.

use super::*;

impl BlkState {
    pub fn serial(&self) -> &[u8; blk::BLK_SERIAL_LEN] { &self.serial }

    /// Every programmed request queue: the interrupt-driven default queue
    /// first, then the interrupt-free poll queue when the device gave one.
    pub(super) fn queues(&self) -> impl Iterator<Item = &BlkQueue> {
        core::iter::once(&self.requestq).chain(self.pollq.iter())
    }

    /// Where one request goes. A request that asked to be polled goes to the
    /// interrupt-free queue when the device provided one, so its completion
    /// costs no interrupt; everything else goes to the queue whose completions
    /// the device signals. A polled request on a device with no poll queue
    /// still goes to that queue — better a saved wait than a request nothing
    /// completes.
    pub(super) fn queue_for(&self, polled: bool) -> &BlkQueue {
        match (polled, self.pollq.as_ref()) {
            (true, Some(q)) => q,
            _ => &self.requestq,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn do_request(&self, h: u64, type_: u32, sector: u64, data: &mut [u8],
                  is_in: bool, is_flush: bool, data_len: u32) -> KResult<InHeader> {
        let bounce = h.wrapping_add(self.bounce_pa) as *mut u8;
        // Zone append answers with the sector its data landed at ahead of the
        // status byte, so its device-writable tail is wider. Declaring one
        // byte would have the device write eight past the descriptor.
        let in_len = virtio::blk::zoned::in_header_bytes(type_);
        let mut hdr = [0u8; 16];
        blk::encode_header(&mut hdr, type_, sector);
        // No descriptor referencing this block has been published yet, so the
        // device cannot be reading these bytes concurrently.
        // SAFETY: `bounce` is the HHDM view of this driver's own shared
        // `alloc_contig(BOUNCE_ORDER)` block spanning DATA_OFF+BOUNCE_DATA_BYTES;
        // `acquire_turn` made this task its sole owner and `submit` rejected any
        // `data.len()` above BOUNCE_DATA_BYTES, so every offset is in bounds.
        unsafe {
            for (i, b) in hdr.iter().enumerate() {
                core::ptr::write_volatile(bounce.add(HDR_OFF + i), *b);
            }
            if !is_in && !is_flush {
                for (i, b) in data.iter().enumerate() {
                    core::ptr::write_volatile(bounce.add(DATA_OFF + i), *b);
                }
            }
            for i in 0..in_len { core::ptr::write_volatile(bounce.add(STATUS_OFF + i), 0xFFu8); }
        }

        let hdr_dma = self.bounce_dma + HDR_OFF as u64;
        let data_dma = self.bounce_dma + DATA_OFF as u64;
        let status_dma = self.bounce_dma + STATUS_OFF as u64;
        let (descs, n) = blk::build_chain_with_in_header(
            is_in, hdr_dma, data_dma, data_len, status_dma, in_len as u32);

        let desc_tbl = h.wrapping_add(self.requestq.res.desc_pa) as *mut u64;
        // `acquire_turn` gives this task sole ownership of heads 0..n, and the
        // device only reads them once the `avail.idx` store below publishes them.
        // SAFETY: `desc_pa` is the queue's own descriptor frame via HHDM, sized
        // by the `size` that `program_queue` negotiated down to one frame's
        // worth of descriptors; `n` is `build_chain`'s count, capped at
        // MAX_REQUEST_DESCRIPTORS = 3, so `i*2 + 1` stays inside the frame.
        unsafe {
            for (i, d) in descs.iter().take(n).enumerate() {
                let (w0, w1) = blk::pack_desc(d);
                core::ptr::write_volatile(desc_tbl.add(i * 2), w0);
                core::ptr::write_volatile(desc_tbl.add(i * 2 + 1), w1);
            }
        }

        let avail = h.wrapping_add(self.requestq.res.driver_pa) as *mut u16;
        let qsz = self.requestq.res.size;
        let target = {
            let mut g = self.requestq.lock();
            let slot = g.avail_idx % qsz;
            // `inflight` is held, and the Release fence orders the ring-entry
            // store before the `idx` store that hands the entry to the device.
            // SAFETY: `driver_pa` is the queue's own avail frame via HHDM, whose
            // u16 layout is flags, idx, ring[qsz] (Virtio 1.2 §2.7.6); `slot` is
            // reduced mod `qsz` and `qsz` is capped at one frame's worth of
            // descriptors, so `2 + slot` is an in-bounds aligned u16 index.
            unsafe {
                core::ptr::write_volatile(avail.add(2 + slot as usize), 0u16);
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                g.avail_idx = g.avail_idx.wrapping_add(1);
                core::ptr::write_volatile(avail.add(1), g.avail_idx);
            }
            g.avail_idx
        };
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

        if self.requestq.res.notify_va != 0 {
            // The Release fence above published the ring before this doorbell.
            // SAFETY: `notify_va` is this queue's doorbell inside the device's
            // Device-attr-mapped notify BAR window, computed at probe from
            // `queue_notify_off` and checked non-zero here; a u16 store of the
            // queue index is its defined access (Virtio 1.2 §4.1.4.4).
            unsafe {
                core::ptr::write_volatile(
                    self.requestq.res.notify_va as *mut u16,
                    self.requestq.res.index,
                );
            }
        }

        self.wait_for_completion(h, target)?;
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);

        let mut in_header: InHeader = [0u8; VIRTIO_BLK_MAX_IN_HEADER_BYTES];
        // SAFETY: same owned bounce block; the in-header occupies
        // STATUS_OFF..STATUS_OFF+in_len, which `in_header_bytes` caps at
        // VIRTIO_BLK_MAX_IN_HEADER_BYTES and DATA_OFF places a whole page
        // past. The used-ring entry retired the chain, so the device has
        // finished writing every one of those bytes.
        unsafe {
            for i in 0..in_len {
                in_header[i] = core::ptr::read_volatile(bounce.add(STATUS_OFF + i));
            }
        }
        // The status is the LAST byte of the in-header at every width, which
        // is what lets one decode path serve the plain and the wide form.
        let status = in_header[in_len - 1];
        if let Err(st) = blk::decode_status(status) {
            #[cfg(feature = "debug-boot")]
            log_status_error(type_, sector, data_len, status);
            return Err(block_error_for_status(st));
        }
        if is_in {
            // SAFETY: read-back of the same owned bounce block; `data.len()`
            // was bounded by `BOUNCE_DATA_BYTES` in `submit`, so
            // `DATA_OFF + i` stays inside it. The used-ring entry retired the
            // descriptor chain, so the device is done writing the payload.
            unsafe {
                for (i, b) in data.iter_mut().enumerate() {
                    *b = core::ptr::read_volatile(bounce.add(DATA_OFF + i));
                }
            }
        }
        Ok(in_header)
    }

    /// Issue the device barrier, or skip it when the negotiated cache mode is
    /// write-through.
    ///
    /// A device with no volatile write cache has nothing to fence, so `Ok(())`
    /// is a truthful durability answer here, not a swallowed error. Sending
    /// `T_FLUSH` anyway violates Virtio 1.2 §5.2.6 — the request type is valid
    /// only under a negotiated `F_FLUSH` — and earns `S_UNSUPP` from a
    /// conforming device. # C: O(1) or one request
    pub(super) fn issue_flush(&self) -> KResult<()> {
        if !self.write_cache { return Ok(()); }
        self.submit(blk::VIRTIO_BLK_T_FLUSH, 0, &mut [])
    }

    pub(super) fn get_id(&self) -> KResult<[u8; blk::BLK_SERIAL_LEN]> {
        let mut id = [0u8; blk::BLK_SERIAL_LEN];
        self.submit(blk::VIRTIO_BLK_T_GET_ID, 0, &mut id)?;
        Ok(id)
    }
}

impl BlockDevice for BlkState {
    fn block_size(&self) -> u32 { self.blk_size }

    /// The topology, carrying the negotiated cache mode as a queue FACT.
    ///
    /// Publishing it is what lets a filesystem above decide whether its commit
    /// record needs a barrier. Without it the layer that sequences durability
    /// reads "no volatile cache" for a write-back device and issues nothing, so
    /// an `fsync` returns while the data is still in the device's cache — the
    /// driver knowing the mode privately is not enough. Forced-unit-access is
    /// deliberately absent: virtio has no per-request equivalent, so the
    /// promise is kept by a flush after the write instead.
    /// # C: O(1)
    fn queue_limits(&self) -> KResult<block::QueueLimits> {
        topology(self.blk_size, self.write_cache)
    }

    fn capacity_blocks(&self) -> u64 {
        blk::capacity_blocks(self.capacity, self.blk_size)
    }

    fn submit(&self, mut request: BlockRequest, completion: BlockCompletion) {
        if let Some((type_, sector, is_in, is_flush, data_len)) = self.owned_request_plan(&mut request) {
            let q = self.queue_for(request.polled);
            match self.post_owned_request(q, request, completion, type_, sector, is_in, is_flush, data_len) {
                Ok(()) => return,
                Err((request, completion, error)) => {
                    completion(request, Err(error));
                    return;
                }
            }
        }
        let result = self.submit_sync(&mut request);
        completion(request, result);
    }

    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        let sec = blk::VIRTIO_BLK_SECTOR_BYTES as usize;
        match req.op {
            BlockOp::Flush => self.issue_flush(),
            BlockOp::Read | BlockOp::Write => {
                let bs = self.blk_size as usize;
                let nbytes = (req.len_blocks as usize)
                    .checked_mul(bs).ok_or(BlockError::Einval)?;
                if req.op == BlockOp::Read {
                    if req.buffer.len() < nbytes { req.buffer.resize(nbytes, 0); }
                } else if req.buffer.len() < nbytes {
                    return Err(BlockError::Einval);
                }
                let (base_sector, total_sectors) =
                    blk::sector_plan(req.start_block, req.len_blocks, self.blk_size)
                        .ok_or(BlockError::Einval)?;
                let type_ = if req.op == BlockOp::Read {
                    blk::VIRTIO_BLK_T_IN
                } else {
                    blk::VIRTIO_BLK_T_OUT
                };
                // A run that crosses a zone boundary is CUT here, never sent
                // whole: its tail would land at the head of a zone whose
                // write pointer is somewhere else, which a host-managed drive
                // refuses. The reference expresses the same rule as a queue
                // limit the block layer splits on; with no splitter above,
                // the cut belongs here. `zone_sectors` is 0 on a drive with
                // no zones, which imposes no boundary at all.
                let zone_sectors = self.zone_sectors();
                let mut tmp: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
                let mut at = base_sector;
                let mut left = total_sectors;
                let mut off = 0usize;
                while let Some(chunk_sectors) = virtio::blk::zoned::zone_bounded_chunk(
                    at, left, blk::BOUNCE_DATA_SECTORS, zone_sectors,
                ) {
                    let clen = chunk_sectors as usize * sec;
                    tmp.resize(clen, 0);
                    if req.op == BlockOp::Write {
                        tmp.copy_from_slice(&req.buffer[off..off + clen]);
                    }
                    self.submit(type_, at, &mut tmp[..clen])?;
                    if req.op == BlockOp::Read {
                        req.buffer[off..off + clen].copy_from_slice(&tmp[..clen]);
                    }
                    at += chunk_sectors;
                    left -= chunk_sectors;
                    off += clen;
                }
                Ok(())
            }
            BlockOp::Discard | BlockOp::WriteZeroes { .. } => Err(BlockError::Eopnotsupp),
        }
    }

    fn flush(&self) -> KResult<()> {
        self.issue_flush()
    }

    /// A disk is pollable exactly when this device gave it a virtqueue that
    /// carries no interrupt. That is what a poll saves over a wait: a request
    /// on the poll queue is completed by the poller and signals nothing, so
    /// admitting a poll against a queue the device still interrupts would
    /// promise a cost saving that does not exist. # C: O(1)
    fn can_poll(&self) -> bool { self.queues().any(poll_drains) }

    /// Reap the interrupt-free queues, and only those — the queues the
    /// completion softirq does not own. Zero means "polled, none ready"; a
    /// device with no poll queue answers zero here and `false` above, and the
    /// two together are what a caller keys its refusal on.
    /// # C: O(completions reaped)
    fn poll_completions(&self) -> usize {
        self.queues().filter(|q| poll_drains(q)).map(|q| self.drain_owned_completions(q)).sum()
    }

    /// # C: O(zones)
    fn zone_report(&self) -> Option<block::zoned::ZoneReport> { self.read_zone_report() }

    /// # C: one request
    fn zone_mgmt(&self, op: block::zoned::ZoneMgmtOp, start_block: u64) -> KResult<()> {
        self.issue_zone_mgmt(op, start_block)
    }

    /// # C: one request
    fn zone_append(&self, start_block: u64, buffer: &[u8]) -> KResult<u64> {
        self.issue_zone_append(start_block, buffer)
    }
}

/// `S_UNSUPP` is an unsupported-operation answer, not an I/O error. Collapsing
/// both into `Eio` is what made a flush issued against an un-negotiated
/// `F_FLUSH` indistinguishable from a real media failure. # C: O(1)
pub(super) fn block_error_for_status(status: u8) -> BlockError {
    zoned::zone_block_error(status)
}

/// The queue topology this device publishes, as a function of the two facts it
/// has: its logical block size and its post-negotiation cache mode.
///
/// Ungated and separate from the trait method so the mapping can be checked
/// without a live device. What it decides is not cosmetic: the layer that
/// sequences a filesystem's durability promises reads `WRITE_CACHE` from here,
/// and a device that failed to publish it would have every barrier above it
/// optimised away — an `fsync` would return with the data still in the device's
/// cache. `FUA` is deliberately never set: virtio has no per-request
/// forced-unit-access, so that promise is kept by a flush after the write.
/// # C: O(1)
pub(super) fn topology(blk_size: u32, write_cache: bool) -> KResult<block::QueueLimits> {
    let mut f = block::QueueFeatures::empty();
    if write_cache { f |= block::QueueFeatures::WRITE_CACHE; }
    Ok(block::QueueLimits::for_logical_block_size(blk_size)?.with_features(f))
}

#[cfg(test)]
mod topology_tests {
    use super::topology;

    /// A write-back device must SAY it holds acknowledged writes in a cache.
    /// The cache mode is already known privately; publishing it is what lets a
    /// filesystem's commit record be fenced.
    #[test]
    fn a_writeback_device_publishes_its_volatile_cache() {
        let l = topology(512, true).unwrap();
        assert!(l.write_cache());
        assert!(!l.fua(), "virtio has no per-request forced unit access to claim");
    }

    /// A write-through device has no cache to empty, and saying it had one would
    /// cost a barrier per commit for nothing.
    #[test]
    fn a_writethrough_device_publishes_no_cache() {
        assert!(!topology(4096, false).unwrap().write_cache());
    }

    #[test]
    fn the_logical_block_size_is_carried_through_either_way() {
        assert_eq!(topology(4096, true).unwrap().logical_block_size(), 4096);
        assert_eq!(topology(512, false).unwrap().logical_block_size(), 512);
    }
}
