// Device removal and shutdown: freeze, quiesce every request queue, reset the
// transport, and give each accepted request one terminal completion.

use super::*;

impl BlkState {
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

    /// Every programmed queue must be idle, not just the default one: a polled
    /// request in flight on the poll queue owns a DMA buffer exactly as an
    /// interrupt-driven one does.
    fn all_queues_idle(&self) -> bool {
        self.queues().all(|q| {
            let ring = q.lock();
            !ring.busy && ring.pending.is_empty() && ring.deferred.is_empty()
        })
    }

    fn wait_idle_for_remove(&self) -> bool {
        #[cfg(target_os = "oxide-kernel")]
        let deadline = now_ns().saturating_add(IO_TIMEOUT_NS);
        #[cfg(not(target_os = "oxide-kernel"))]
        let mut spun: u64 = 0;
        loop {
            if self.all_queues_idle() { return true; }
            #[cfg(target_os = "oxide-kernel")]
            {
                if now_ns() >= deadline {
                    return false;
                }
                // Register-then-recheck (B1426): see wait.rs::acquire_turn.
                park_blk_checked(&BLK_TURN, deadline, || self.all_queues_idle());
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
    /// ownership on EVERY queue so every accepted request gets one terminal
    /// `EIO` completion; only free each request's DMA buffer when reset was
    /// actually confirmed quiescent (state.md corruption hunt) — otherwise
    /// leak it rather than risk handing a still-live frame back to the
    /// buddy allocator.
    fn cancel_owned_requests(&self, reset_confirmed: bool) {
        for q in self.queues() {
            let (pending, deferred) = {
                let mut ring = q.lock();
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
    }

    #[cfg(test)]
    pub(crate) fn remove_for_tests(&self) {
        self.remove();
    }

    #[cfg(test)]
    pub(crate) fn shutdown_for_tests(&self) {
        self.shutdown();
    }
}
