use super::*;

impl BlkState {
    pub fn serial(&self) -> &[u8; blk::BLK_SERIAL_LEN] { &self.serial }

    pub(super) fn remove(&self) {
        self.freeze_new_io();
        let idle = self.wait_idle_for_remove();
        let reset_confirmed = self.reset_common_cfg();
        self.cancel_owned_requests(reset_confirmed);
        if !idle { return; }
        // Corruption-hunt fix (state.md): only free the shared bounce buffer
        // if the device's reset was actually confirmed quiescent. An
        // unconfirmed reset means QEMU's backend may still be mid-DMA into
        // this frame; freeing it would return a live frame to the buddy
        // free list, which kalloc_grow (or anything else) could then carve
        // into a live heap object the device keeps writing into.
        if self.bounce_pa != 0 && reset_confirmed {
            // SAFETY: `bounce_pa` is this driver's own `alloc_contig(BOUNCE_ORDER)`
            // block, freed exactly once here; `reset_confirmed` proves the device
            // read status==0 after reset, so no in-flight DMA targets the frames,
            // and `idle` proves no request still references them.
            unsafe { pmm::setup::free_contig(self.bounce_pa, pmm::Order(BOUNCE_ORDER)); }
        } else if self.bounce_pa != 0 {
            klog::write_raw(b"[BLK-REMOVE] reset unconfirmed, leaking bounce buffer\n");
        }
        #[cfg(target_os = "oxide-kernel")]
        wake_all_blk_waiters();
    }

    pub(super) fn shutdown(&self) {
        self.freeze_new_io();
        let idle = self.wait_idle_for_remove();
        let reset_confirmed = self.reset_common_cfg();
        self.cancel_owned_requests(reset_confirmed);
        if !idle {
            klog::write_raw(b"[BLK-SHUTDOWN] reset with busy request quarantined\n");
        }
        #[cfg(target_os = "oxide-kernel")]
        wake_all_blk_waiters();
    }

    fn wait_idle_for_remove(&self) -> bool {
        #[cfg(target_os = "oxide-kernel")]
        let deadline = now_ns().saturating_add(IO_TIMEOUT_NS);
        #[cfg(not(target_os = "oxide-kernel"))]
        let mut spun: u64 = 0;
        loop {
            {
                let ring = self.inflight.lock_bh::<sched::bh::SchedBh>();
                if !ring.busy && ring.pending.is_empty() && ring.deferred.is_empty() {
                    return true;
                }
            }
            #[cfg(target_os = "oxide-kernel")]
            {
                if now_ns() >= deadline {
                    return false;
                }
                // Register-then-recheck (B1426): see wait.rs::acquire_turn.
                park_blk_checked(&BLK_TURN, deadline, || {
                    let ring = self.inflight.lock_bh::<sched::bh::SchedBh>();
                    !ring.busy && ring.pending.is_empty() && ring.deferred.is_empty()
                });
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            {
                spun += 1;
                if spun > IO_FALLBACK_SPINS {
                    return false;
                }
                core::hint::spin_loop();
            }
        }
    }

    fn freeze_new_io(&self) {
        self.poisoned.store(true, core::sync::atomic::Ordering::Release);
        #[cfg(target_os = "oxide-kernel")]
        wake_all_blk_waiters();
    }

    #[must_use]
    fn reset_common_cfg(&self) -> bool {
        virtio::reset_device(self.cfg_va)
    }

    /// After transport reset the device cannot access the request DMA areas
    /// — PROVIDED `reset_confirmed` is true. Drain both posted and deferred
    /// ownership so every accepted request gets one terminal `EIO`
    /// completion; only free each request's DMA buffer when reset was
    /// actually confirmed quiescent (state.md corruption hunt) — otherwise
    /// leak it rather than risk handing a still-live frame back to the
    /// buddy allocator.
    fn cancel_owned_requests(&self, reset_confirmed: bool) {
        let (pending, deferred) = {
            let mut ring = self.inflight.lock_bh::<sched::bh::SchedBh>();
            (core::mem::take(&mut ring.pending), core::mem::take(&mut ring.deferred))
        };
        for request in pending {
            if reset_confirmed {
                // SAFETY: reset_common_cfg confirmed status==0 before this
                // call, so the device has actually stopped DMA and cannot
                // retain this request buffer.
                unsafe { pmm::setup::free_contig(request.bounce_pa, pmm::Order(BOUNCE_ORDER)); }
            } else {
                klog::write_raw(b"[BLK-CANCEL] reset unconfirmed, leaking request buffer\n");
            }
            (request.completion)(request.request, Err(BlockError::Eio));
        }
        for request in deferred {
            (request.completion)(request.request, Err(BlockError::Eio));
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

        let desc_tbl = h.wrapping_add(self.requestq.desc_pa) as *mut u64;
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

        let avail = h.wrapping_add(self.requestq.driver_pa) as *mut u16;
        let qsz = self.requestq.size;
        let target = {
            let mut g = self.inflight.lock_bh::<sched::bh::SchedBh>();
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

        if self.requestq.notify_va != 0 {
            // The Release fence above published the ring before this doorbell.
            // SAFETY: `notify_va` is this queue's doorbell inside the device's
            // Device-attr-mapped notify BAR window, computed at probe from
            // `queue_notify_off` and checked non-zero here; a u16 store of the
            // queue index is its defined access (Virtio 1.2 §4.1.4.4).
            unsafe {
                core::ptr::write_volatile(
                    self.requestq.notify_va as *mut u16,
                    self.requestq.index,
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
    /// Linux's equivalent is structural rather than a branch: without
    /// `F_FLUSH` it calls `blk_queue_write_cache(q, false, false)`
    /// (`virtio_blk.c:1084` → `virtblk_probe`), after which `blk_insert_flush`
    /// (`block/blk-flush.c`) retires a flush-only request immediately and
    /// `virtblk_setup_cmd` is never reached with `REQ_OP_FLUSH`. Same outcome,
    /// and it is the CORRECT outcome: a device with no volatile write cache has
    /// nothing to fence, so `Ok(())` here is a truthful durability answer, not
    /// a swallowed error. Sending `T_FLUSH` anyway violates Virtio 1.2 §5.2.6
    /// and earns `S_UNSUPP` from a conforming device. # C: O(1) or one request
    pub(super) fn issue_flush(&self) -> KResult<()> {
        if !self.write_cache { return Ok(()); }
        self.submit(blk::VIRTIO_BLK_T_FLUSH, 0, &mut [])
    }

    /// Describe an owned request that fits in one hardware chain. Larger
    /// requests retain the synchronous chunking path until the queued engine
    /// can chain their chunks under one completion continuation.
    fn owned_request_plan(&self, request: &mut BlockRequest) -> Option<(u32, u64, bool, bool, u32)> {
        match request.op {
            // A write-through device has no volatile cache and did not negotiate
            // `F_FLUSH`; `None` sends this down `submit_sync`, which completes it
            // without a wire request (Linux `blk_insert_flush`).
            BlockOp::Flush if !self.write_cache => None,
            BlockOp::Flush => Some((blk::VIRTIO_BLK_T_FLUSH, 0, false, true, 0)),
            BlockOp::Read | BlockOp::Write => {
                let bytes = (request.len_blocks as usize).checked_mul(self.blk_size as usize)?;
                if bytes > blk::BOUNCE_DATA_BYTES { return None; }
                if request.op == BlockOp::Read {
                    if request.buffer.len() < bytes { request.buffer.resize(bytes, 0); }
                } else if request.buffer.len() < bytes {
                    return None;
                }
                let (sector, sectors) = blk::sector_plan(request.start_block, request.len_blocks, self.blk_size)?;
                if sectors > blk::BOUNCE_DATA_SECTORS { return None; }
                let type_ = if request.op == BlockOp::Read { blk::VIRTIO_BLK_T_IN } else { blk::VIRTIO_BLK_T_OUT };
                Some((type_, sector, request.op == BlockOp::Read, false, bytes as u32))
            }
            BlockOp::Discard | BlockOp::WriteZeroes { .. } => None,
        }
    }

    fn post_owned_request(
        &self,
        request: BlockRequest,
        completion: BlockCompletion,
        type_: u32,
        sector: u64,
        is_in: bool,
        is_flush: bool,
        data_len: u32,
    ) -> Result<(), (BlockRequest, BlockCompletion, BlockError)> {
        self.post_owned_request_inner(request, completion, type_, sector, is_in, is_flush, data_len, false)
    }

    /// Submit one request whose position at the deferred queue head has
    /// already established FIFO ownership. Direct callers must not bypass
    /// queued work; the deferred-drain owner may do so to make that head live.
    #[allow(clippy::too_many_arguments)]
    fn post_owned_request_inner(
        &self,
        request: BlockRequest,
        completion: BlockCompletion,
        type_: u32,
        sector: u64,
        is_in: bool,
        is_flush: bool,
        data_len: u32,
        deferred_head: bool,
    ) -> Result<(), (BlockRequest, BlockCompletion, BlockError)> {
        if self.poisoned.load(core::sync::atomic::Ordering::Acquire) || hhdm() == 0 || !self.requestq.is_runtime_valid() {
            return Err((request, completion, BlockError::Eio));
        }
        let Some(bounce_pa) = pmm::setup::alloc_contig(pmm::Order(BOUNCE_ORDER)) else {
            return Err((request, completion, BlockError::Enomem));
        };
        let h = hhdm();
        let mut ring = self.inflight.lock_bh::<sched::bh::SchedBh>();
        if self.poisoned.load(core::sync::atomic::Ordering::Acquire) {
            drop(ring);
            // SAFETY: this allocation has not been published to the device.
            unsafe { pmm::setup::free_contig(bounce_pa, pmm::Order(BOUNCE_ORDER)); }
            return Err((request, completion, BlockError::Eio));
        }
        if ring.busy || ring.free_heads.is_empty() || (!deferred_head && !ring.deferred.is_empty()) {
            drop(ring);
            // SAFETY: this allocation has not been published to a device or
            // another CPU; returning it immediately satisfies PMM ownership.
            unsafe { pmm::setup::free_contig(bounce_pa, pmm::Order(BOUNCE_ORDER)); }
            let mut ring = self.inflight.lock_bh::<sched::bh::SchedBh>();
            if self.poisoned.load(core::sync::atomic::Ordering::Acquire) {
                return Err((request, completion, BlockError::Eio));
            }
            ring.deferred.push(DeferredRequest {
                request, completion, type_, sector, is_in, is_flush, data_len,
                queued_ns: timekeeper::monotonic_ns(),
            });
            return Ok(());
        }
        let Some(head) = ring.free_heads.pop() else {
            drop(ring);
            // SAFETY: no descriptor was published, so this remains private.
            unsafe { pmm::setup::free_contig(bounce_pa, pmm::Order(BOUNCE_ORDER)); }
            return Err((request, completion, BlockError::Eio));
        };
        let bounce = h.wrapping_add(bounce_pa) as *mut u8;
        let mut header = [0u8; VIRTIO_BLK_REQUEST_HEADER_BYTES];
        blk::encode_header(&mut header, type_, sector);
        // Not yet published to any descriptor, so no other CPU and not the
        // device can reach this block while these stores run.
        // SAFETY: `bounce` is the HHDM view of the `alloc_contig(BOUNCE_ORDER)`
        // block allocated for THIS request above, spanning
        // DATA_OFF+BOUNCE_DATA_BYTES, and `owned_request_plan` capped `data_len`
        // at BOUNCE_DATA_BYTES, so every offset written is inside it.
        unsafe {
            for (offset, byte) in header.iter().enumerate() {
                core::ptr::write_volatile(bounce.add(HDR_OFF + offset), *byte);
            }
            if !is_in && !is_flush {
                for (offset, byte) in request.buffer[..data_len as usize].iter().enumerate() {
                    core::ptr::write_volatile(bounce.add(DATA_OFF + offset), *byte);
                }
            }
            core::ptr::write_volatile(bounce.add(STATUS_OFF), u8::MAX);
        }
        let (descs, descriptor_count) = blk::build_chain(
            is_in,
            bounce_pa + HDR_OFF as u64,
            bounce_pa + DATA_OFF as u64,
            data_len,
            bounce_pa + STATUS_OFF as u64,
        );
        let desc_table = h.wrapping_add(self.requestq.desc_pa) as *mut u64;
        // `head` came from `free_heads` (entries `slot * MAX_REQUEST_DESCRIPTORS`
        // for `slot < size / 3`), so this request exclusively owns descriptors
        // `head..head+3` until its used-ring entry retires them. `ring` is held
        // across both writes; the Release fence orders the avail ring-entry store
        // before the `avail.idx` publish.
        // SAFETY: descriptor and avail frames of this queue via HHDM, sized by
        // the `size` `program_queue` negotiated down to one frame; with
        // `descriptor_count <= MAX_REQUEST_DESCRIPTORS` and `head + 3 <= size`,
        // and `avail_slot < size`, every index written is in bounds and aligned.
        unsafe {
            for (offset, descriptor) in descs.iter().take(descriptor_count).enumerate() {
                let mut descriptor = *descriptor;
                if descriptor.flags & virtio::queue::VRING_DESC_F_NEXT != 0 {
                    descriptor.next = head + offset as u16 + 1;
                }
                let (word0, word1) = blk::pack_desc(&descriptor);
                let index = (head as usize + offset) * 2;
                core::ptr::write_volatile(desc_table.add(index), word0);
                core::ptr::write_volatile(desc_table.add(index + 1), word1);
            }
            let avail = h.wrapping_add(self.requestq.driver_pa) as *mut u16;
            let avail_slot = ring.avail_idx % self.requestq.size;
            core::ptr::write_volatile(avail.add(2 + avail_slot as usize), head);
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            ring.avail_idx = ring.avail_idx.wrapping_add(1);
            core::ptr::write_volatile(avail.add(1), ring.avail_idx);
        }
        ring.pending.push(PendingRequest { head, bounce_pa, request, completion, is_in, data_len });
        drop(ring);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        // SAFETY: `notify_va` is this queue's doorbell in the Device-attr notify
        // BAR window; `is_runtime_valid()` at the top of this fn proved it
        // non-zero. A u16 store of the queue index is the doorbell's defined
        // access, and the Release fence published the rings before it.
        unsafe { core::ptr::write_volatile(self.requestq.notify_va as *mut u16, self.requestq.index); }
        Ok(())
    }

    /// Consume every used-ring entry published by the device and run owned
    /// completions after releasing queue state. This is called from BlockIo
    /// softirq, never from the hard IRQ that merely raised that softirq.
    pub(super) fn drain_owned_completions(&self) {
        let h = hhdm();
        if h == 0 || self.requestq.device_pa == 0 || self.requestq.size == 0 { return; }
        // A synchronous request owns its descriptor and waits on `used.idx`
        // itself. Its interrupt still raises this softirq, but the completion
        // is not an owned asynchronous request and must not be consumed here.
        // Leaving it in the used ring lets the synchronous waiter observe it;
        // `run_completion_bottom_half` wakes that waiter after this returns.
        if self.inflight.lock_bh::<sched::bh::SchedBh>().busy { return; }
        loop {
            let pending = {
                let mut ring = self.inflight.lock_bh::<sched::bh::SchedBh>();
                let used = h.wrapping_add(self.requestq.device_pa) as *const u8;
                // SAFETY: `device_pa` is this queue's used frame via HHDM,
                // non-zero per the guard above. Virtio 1.2 §2.7.8 puts `idx` at
                // byte 2 as an aligned u16; the volatile load re-reads the
                // device's publish rather than caching it.
                let used_index = unsafe { core::ptr::read_volatile(used.add(core::mem::size_of::<u16>()) as *const u16) };
                if ring.used_seen == used_index { return; }
                let slot = (ring.used_seen % self.requestq.size) as usize;
                let entry = core::mem::size_of::<u16>() * 2 + slot * (core::mem::size_of::<u32>() * 2);
                // SAFETY: same used frame; `slot < size` and `size` is capped to
                // one frame, so `4 + slot*8` is an in-bounds, u32-aligned
                // `used.ring[slot].id`. `used_seen != used_index` proves the
                // device already published this entry.
                let head = unsafe { core::ptr::read_volatile(used.add(entry) as *const u32) as u16 };
                ring.used_seen = ring.used_seen.wrapping_add(1);
                let Some(position) = ring.pending.iter().position(|request| request.head == head) else {
                    self.poisoned.store(true, core::sync::atomic::Ordering::Release);
                    continue;
                };
                ring.free_heads.push(head);
                ring.pending.remove(position)
            };
            let mut request = pending.request;
            let bounce = h.wrapping_add(pending.bounce_pa) as *const u8;
            // SAFETY: the per-request `alloc_contig(BOUNCE_ORDER)` block, still
            // owned by this `PendingRequest` (removed from `pending` above, not
            // yet freed). Its descriptor head came back in the used ring, so the
            // device has finished with it. STATUS_OFF is in bounds.
            let status = unsafe { core::ptr::read_volatile(bounce.add(STATUS_OFF)) };
            let result = match blk::decode_status(status) {
                Ok(()) if pending.is_in => {
                    if request.buffer.len() < pending.data_len as usize {
                        Err(BlockError::Eio)
                    } else {
                        // SAFETY: same retired bounce block; the length check
                        // above bounds `data_len` by the caller's buffer, and
                        // `owned_request_plan` bounded it by BOUNCE_DATA_BYTES,
                        // so `DATA_OFF + offset` is inside the block.
                        unsafe {
                            for (offset, byte) in request.buffer[..pending.data_len as usize].iter_mut().enumerate() {
                                *byte = core::ptr::read_volatile(bounce.add(DATA_OFF + offset));
                            }
                        }
                        Ok(())
                    }
                }
                Ok(()) => Ok(()),
                Err(st) => Err(block_error_for_status(st)),
            };
            // SAFETY: the device returned this descriptor head in used.ring;
            // the DMA region is no longer reachable by the device.
            unsafe { pmm::setup::free_contig(pending.bounce_pa, pmm::Order(BOUNCE_ORDER)); }
            (pending.completion)(request, result);
            self.start_deferred_requests();
        }
    }

    /// Post deferred owned requests while descriptor chains are available.
    /// A queue-full condition simply leaves the request queued; only a real
    /// transport or PMM error reaches its completion.
    ///
    /// Which of several waiting requests goes next is the block layer's
    /// I/O-priority dispatch order, not arrival order: this is the one point
    /// where the queue is congested and a priority can therefore matter. With
    /// a single class waiting the order it produces IS arrival order.
    fn start_deferred_requests(&self) {
        loop {
            let deferred = {
                let mut ring = self.inflight.lock_bh::<sched::bh::SchedBh>();
                if ring.busy || ring.free_heads.is_empty() || ring.deferred.is_empty() {
                    return;
                }
                let now = timekeeper::monotonic_ns();
                let waiting: alloc::vec::Vec<block::elevator::Waiting> = ring.deferred.iter()
                    .map(|d| block::elevator::Waiting { ioprio: d.request.ioprio, queued_ns: d.queued_ns })
                    .collect();
                let Some(idx) = block::elevator::select(&waiting, now,
                    block::elevator::PRIO_AGING_EXPIRE_NS) else { return; };
                ring.deferred.remove(idx)
            };
            if let Err((request, completion, error)) = self.post_owned_request_inner(
                deferred.request,
                deferred.completion,
                deferred.type_,
                deferred.sector,
                deferred.is_in,
                deferred.is_flush,
                deferred.data_len,
                true,
            ) {
                completion(request, Err(error));
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn remove_for_tests(&self) {
        self.remove();
    }

    #[cfg(test)]
    pub(crate) fn shutdown_for_tests(&self) {
        self.shutdown();
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
            match self.post_owned_request(request, completion, type_, sector, is_in, is_flush, data_len) {
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
}

/// `virtblk_result` (Linux `virtio_blk.c:107-118`): `S_UNSUPP` is
/// `BLK_STS_NOTSUPP`, not an I/O error. Collapsing both into `Eio` is what made
/// a flush issued against an un-negotiated `F_FLUSH` indistinguishable from a
/// real media failure. # C: O(1)
fn block_error_for_status(status: u8) -> BlockError {
    match status {
        blk::VIRTIO_BLK_S_UNSUPP => BlockError::Eopnotsupp,
        _ => BlockError::Eio,
    }
}
