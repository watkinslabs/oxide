use super::*;

impl BlkState {
    pub(super) fn wait_for_completion(&self, h: u64, target: u16) -> KResult<()> {
        let used = h.wrapping_add(self.requestq.device_pa) as *const u16;
        #[cfg(not(target_os = "oxide-kernel"))]
        {
            let mut spun: u64 = 0;
            loop {
                // SAFETY: virtio owns the used-ring index at this DMA address.
                let uidx = unsafe { core::ptr::read_volatile(used.add(1)) };
                if uidx == target { self.inflight.lock_bh::<sched::bh::SchedBh>().used_seen = uidx; return Ok(()); }
                spun += 1;
                if spun > IO_FALLBACK_SPINS { return Err(BlockError::Eio); }
                core::hint::spin_loop();
            }
        }
        #[cfg(target_os = "oxide-kernel")]
        {
            let deadline = now_ns().saturating_add(IO_TIMEOUT_NS);
            loop {
                // Linux's ordinary submit-and-wait path checks completion and
                // sleeps; only a request explicitly created as polled enters
                // the block polling loop. Syscall and process-fault dispatch now
                // run with IRQs enabled, so the local virtio completion can wake
                // this task without a driver-owned delivery bridge.
                // SAFETY: virtio owns the used-ring index at this DMA address.
                if unsafe { core::ptr::read_volatile(used.add(1)) } == target {
                    self.inflight.lock_bh::<sched::bh::SchedBh>().used_seen = target;
                    return Ok(());
                }
                if now_ns() >= deadline {
                    self.poisoned.store(true, core::sync::atomic::Ordering::Release);
                    klog::write_raw(b"[BLK-TIMEOUT] device poisoned, used stuck\n");
                    return Err(BlockError::Eio);
                }
                // Park off-CPU on the completion condition immediately. The
                // register-then-recheck closes the SMP lost-wakeup window, and
                // the deadline wakes us even if the device interrupt is lost.
                park_blk_checked(&BLK_COMPL, deadline, || {
                    // SAFETY: virtio owns the used-ring index at this DMA address.
                    unsafe { core::ptr::read_volatile(used.add(1)) == target }
                });
            }
        }
    }

    pub(super) fn acquire_turn(&self) {
        loop {
            if self.poisoned.load(core::sync::atomic::Ordering::Acquire) { return; }
            {
                let mut g = self.inflight.lock_bh::<sched::bh::SchedBh>();
                if !g.busy && g.pending.is_empty() && g.deferred.is_empty() { g.busy = true; return; }
            }
            #[cfg(target_os = "oxide-kernel")]
            {
                // Park on BLK_TURN (turn availability), NOT BLK_COMPL: a
                // request completion must not wake every turn-waiter.
                // Register-then-recheck under `inflight` (same B1426 gap:
                // `release_turn` can run on another cpu between our last poll
                // and the park registration).
                park_blk_checked(&BLK_TURN, 0, || {
                    self.poisoned.load(core::sync::atomic::Ordering::Acquire) || {
                        let g = self.inflight.lock_bh::<sched::bh::SchedBh>();
                        !g.busy && g.pending.is_empty() && g.deferred.is_empty()
                    }
                });
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            { core::hint::spin_loop(); }
        }
    }

    pub(super) fn release_turn(&self) {
        self.inflight.lock_bh::<sched::bh::SchedBh>().busy = false;
        // A synchronous owner can have accumulated async requests behind it.
        // Re-run dispatch before waking a synchronous turn waiter: queue
        // release is the completion event those requests were waiting for,
        // and no device completion exists to dispatch them later.
        self.start_deferred_requests();
        // Hand a still-free turn to exactly ONE FIFO waiter (no herd). The
        // woken task re-checks the condition and re-parks if dispatch above
        // consumed the turn or populated the async pending queue.
        #[cfg(target_os = "oxide-kernel")]
        BLK_TURN.wake_one();
    }
}
