// Posting an owned asynchronous request onto one request queue, and the
// dispatch of requests that had to wait for a free descriptor chain.

use super::*;

impl BlkState {
    /// Describe an owned request that fits in one hardware chain. Larger
    /// requests retain the synchronous chunking path until the queued engine
    /// can chain their chunks under one completion continuation.
    pub(super) fn owned_request_plan(&self, request: &mut BlockRequest)
        -> Option<(u32, u64, bool, bool, u32)>
    {
        match request.op {
            // A write-through device has no volatile cache and did not negotiate
            // `F_FLUSH`; `None` sends this down `submit_sync`, which completes it
            // without a wire request.
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

    #[allow(clippy::too_many_arguments)]
    pub(super) fn post_owned_request(
        &self,
        q: &BlkQueue,
        request: BlockRequest,
        completion: BlockCompletion,
        type_: u32,
        sector: u64,
        is_in: bool,
        is_flush: bool,
        data_len: u32,
    ) -> Result<(), (BlockRequest, BlockCompletion, BlockError)> {
        self.post_owned_request_inner(q, request, completion, type_, sector, is_in, is_flush, data_len, false)
    }

    /// Submit one request whose position at the deferred queue head has
    /// already established FIFO ownership. Direct callers must not bypass
    /// queued work; the deferred-drain owner may do so to make that head live.
    #[allow(clippy::too_many_arguments)]
    fn post_owned_request_inner(
        &self,
        q: &BlkQueue,
        request: BlockRequest,
        completion: BlockCompletion,
        type_: u32,
        sector: u64,
        is_in: bool,
        is_flush: bool,
        data_len: u32,
        deferred_head: bool,
    ) -> Result<(), (BlockRequest, BlockCompletion, BlockError)> {
        if self.poisoned.load(core::sync::atomic::Ordering::Acquire) || hhdm() == 0 || !q.res.is_runtime_valid() {
            return Err((request, completion, BlockError::Eio));
        }
        let Some(bounce_pa) = pmm::setup::alloc_contig(pmm::Order(BOUNCE_ORDER)) else {
            return Err((request, completion, BlockError::Enomem));
        };
        let Some(bounce_dma) = iommu::map_dma(self.bdf, bounce_pa, BOUNCE_BYTES) else {
            // SAFETY: mapping failed before a descriptor could name this run.
            unsafe { pmm::setup::free_contig(bounce_pa, pmm::Order(BOUNCE_ORDER)); }
            return Err((request, completion, BlockError::Enomem));
        };
        let h = hhdm();
        let mut ring = q.lock();
        if self.poisoned.load(core::sync::atomic::Ordering::Acquire) {
            drop(ring);
            if !iommu::unmap_dma(self.bdf, bounce_dma, BOUNCE_BYTES) {
                return Err((request, completion, BlockError::Eio));
            }
            // SAFETY: this allocation has not been published to the device.
            unsafe { pmm::setup::free_contig(bounce_pa, pmm::Order(BOUNCE_ORDER)); }
            return Err((request, completion, BlockError::Eio));
        }
        if ring.busy || ring.free_heads.is_empty() || (!deferred_head && !ring.deferred.is_empty()) {
            drop(ring);
            if !iommu::unmap_dma(self.bdf, bounce_dma, BOUNCE_BYTES) {
                return Err((request, completion, BlockError::Eio));
            }
            // SAFETY: this allocation has not been published to a device or
            // another CPU; returning it immediately satisfies PMM ownership.
            unsafe { pmm::setup::free_contig(bounce_pa, pmm::Order(BOUNCE_ORDER)); }
            let mut ring = q.lock();
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
            if !iommu::unmap_dma(self.bdf, bounce_dma, BOUNCE_BYTES) {
                return Err((request, completion, BlockError::Eio));
            }
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
            bounce_dma + HDR_OFF as u64,
            bounce_dma + DATA_OFF as u64,
            data_len,
            bounce_dma + STATUS_OFF as u64,
        );
        let desc_table = h.wrapping_add(q.res.desc_pa) as *mut u64;
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
            let avail = h.wrapping_add(q.res.driver_pa) as *mut u16;
            let avail_slot = ring.avail_idx % q.res.size;
            core::ptr::write_volatile(avail.add(2 + avail_slot as usize), head);
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            ring.avail_idx = ring.avail_idx.wrapping_add(1);
            core::ptr::write_volatile(avail.add(1), ring.avail_idx);
        }
        ring.pending.push(PendingRequest { head, bounce_pa, bounce_dma, request, completion, is_in, data_len });
        drop(ring);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        // SAFETY: `notify_va` is this queue's doorbell in the Device-attr notify
        // BAR window; `is_runtime_valid()` at the top of this fn proved it
        // non-zero. A u16 store of the queue index is the doorbell's defined
        // access, and the Release fence published the rings before it.
        unsafe { core::ptr::write_volatile(q.res.notify_va as *mut u16, q.res.index); }
        Ok(())
    }

    /// Post deferred owned requests on `q` while descriptor chains are
    /// available. A queue-full condition simply leaves the request queued; only
    /// a real transport or PMM error reaches its completion.
    ///
    /// Which of several waiting requests goes next is the block layer's
    /// I/O-priority dispatch order, not arrival order: this is the one point
    /// where the queue is congested and a priority can therefore matter. With
    /// a single class waiting the order it produces IS arrival order.
    pub(super) fn start_deferred_requests(&self, q: &BlkQueue) {
        loop {
            let deferred = {
                let mut ring = q.lock();
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
                q,
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
}
