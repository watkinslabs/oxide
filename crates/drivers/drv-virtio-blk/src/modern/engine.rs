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
                  is_in: bool, is_flush: bool, data_len: u32) -> KResult<()> {
        let bounce = h.wrapping_add(self.bounce_pa) as *mut u8;
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
            core::ptr::write_volatile(bounce.add(STATUS_OFF), 0xFFu8);
        }

        let hdr_pa = self.bounce_pa + HDR_OFF as u64;
        let data_pa = self.bounce_pa + DATA_OFF as u64;
        let status_pa = self.bounce_pa + STATUS_OFF as u64;
        let (descs, n) = blk::build_chain(is_in, hdr_pa, data_pa, data_len, status_pa);

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

        // SAFETY: same owned bounce block; STATUS_OFF is its in-bounds status
        // byte. `wait_for_completion` observed this request's used-ring entry,
        // so the device has finished writing the byte, and the Acquire fence
        // above orders that device write before this load.
        let status = unsafe { core::ptr::read_volatile(bounce.add(STATUS_OFF)) };
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
        Ok(())
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
                let mut tmp: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
                let mut chunk_idx = 0u64;
                while let Some((chunk_base, chunk_sectors, off)) = blk::chunk_plan(
                    base_sector, total_sectors, chunk_idx, blk::BOUNCE_DATA_SECTORS,
                ) {
                    let clen = chunk_sectors as usize * sec;
                    tmp.resize(clen, 0);
                    if req.op == BlockOp::Write {
                        tmp.copy_from_slice(&req.buffer[off..off + clen]);
                    }
                    self.submit(type_, chunk_base, &mut tmp[..clen])?;
                    if req.op == BlockOp::Read {
                        req.buffer[off..off + clen].copy_from_slice(&tmp[..clen]);
                    }
                    chunk_idx += 1;
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
}

/// `S_UNSUPP` is an unsupported-operation answer, not an I/O error. Collapsing
/// both into `Eio` is what made a flush issued against an un-negotiated
/// `F_FLUSH` indistinguishable from a real media failure. # C: O(1)
pub(super) fn block_error_for_status(status: u8) -> BlockError {
    match status {
        blk::VIRTIO_BLK_S_UNSUPP => BlockError::Eopnotsupp,
        _ => BlockError::Eio,
    }
}
