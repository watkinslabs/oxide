use super::*;

impl BlkState {
    #[inline(never)]
    pub(super) fn wait_for_completion(&self, h: u64, target: u16) -> KResult<()> {
        let used = h.wrapping_add(self.requestq.res.device_pa) as *const u16;
        #[cfg(not(target_os = "oxide-kernel"))]
        {
            let mut spun: u64 = 0;
            loop {
                // SAFETY: virtio owns the used-ring index at this DMA address.
                let uidx = unsafe { core::ptr::read_volatile(used.add(1)) };
                if uidx == target { self.requestq.lock().used_seen = uidx; return Ok(()); }
                spun += 1;
                if spun > IO_FALLBACK_SPINS { return Err(BlockError::Eio); }
                core::hint::spin_loop();
            }
        }
        #[cfg(target_os = "oxide-kernel")]
        {
            // A completion is waited for, never given up on. The reference's
            // synchronous block wait re-waits around its timeout for as long as
            // the transfer takes; the timeout exists only to keep the hung-task
            // detector quiet, and there is no path by which the wait reports an
            // error of its own. `park_blk_checked` still takes a deadline so a
            // lost device interrupt cannot park this task forever -- expiry
            // re-polls the used ring and parks again.
            let warn_at = now_ns().saturating_add(IO_WARN_NS);
            let mut warned = false;
            // A park returns on every completion fan-out, so a wait that is
            // progressing normally goes round this loop thousands of times a
            // second. Only a wait that is not progressing is worth reporting.
            #[cfg(feature = "debug-blk-verify")]
            let started = now_ns();
            #[cfg(feature = "debug-blk-verify")]
            let mut next_report = started.saturating_add(STALL_REPORT_NS);
            loop {
                let deadline = now_ns().saturating_add(IO_TIMEOUT_NS);
                // Linux's ordinary submit-and-wait path checks completion and
                // sleeps; only a request explicitly created as polled enters
                // the block polling loop. Syscall and process-fault dispatch now
                // run with IRQs enabled, so the local virtio completion can wake
                // this task without a driver-owned delivery bridge.
                // SAFETY: virtio owns the used-ring index at this DMA address.
                virtio::dma::invalidate_from_device(used as u64, core::mem::size_of::<u16>() * 2);
                if unsafe { core::ptr::read_volatile(used.add(1)) } == target {
                    self.requestq.lock().used_seen = target;
                    return Ok(());
                }
                if !warned && now_ns() >= warn_at {
                    // The hung-task equivalent: a synchronous transfer that has
                    // taken this long is worth naming once, and is not worth
                    // abandoning. A deadline here used to poison the device and
                    // return an I/O error, which made one slow transfer fail
                    // every later request on the device -- and a failed
                    // filesystem read reaches a faulting process as SIGBUS.
                    warned = true;
                    klog::write_raw(b"[BLK-SLOW] transfer outstanding past 10s, still waiting\n");
                }
                // Park off-CPU on the completion condition immediately. The
                // register-then-recheck closes the SMP lost-wakeup window, and
                // the deadline wakes us even if the device interrupt is lost.
                let waiter = sched::current();
                if let Some(task) = waiter { task.begin_iowait(); }
                park_blk_checked(&BLK_COMPL, deadline, || {
                    // SAFETY: virtio owns the used-ring index at this DMA address.
                    virtio::dma::invalidate_from_device(used as u64, core::mem::size_of::<u16>() * 2);
                    unsafe { core::ptr::read_volatile(used.add(1)) == target }
                });
                if let Some(task) = waiter { task.end_iowait(); }
                #[cfg(feature = "debug-blk-verify")]
                if now_ns() >= next_report {
                    // This wait has gone a full report interval with the used
                    // ring still short of its target. Whether the device
                    // stopped notifying us or the softirq stopped running is
                    // the whole question, and the counters answer it: both
                    // climbing means neither stopped.
                    next_report = now_ns().saturating_add(STALL_REPORT_NS);
                    klog::write_raw(b"[BLK-STALL] waited_ms=");
                    klog::write_dec_u64(now_ns().saturating_sub(started) / 1_000_000);
                    klog::write_raw(b" irq=");
                    klog::write_dec_u64(block::IRQ_RAISES.load(Ordering::Relaxed));
                    klog::write_raw(b" bh_runs=");
                    klog::write_dec_u64(block::BH_RUNS.load(Ordering::Relaxed));
                    klog::write_raw(b" bh_reaped=");
                    klog::write_dec_u64(block::BH_REAPED.load(Ordering::Relaxed));
                    klog::write_raw(b"\n");
                }
            }
        }
    }

    pub(super) fn acquire_turn(&self) {
        loop {
            if self.poisoned.load(core::sync::atomic::Ordering::Acquire) { return; }
            {
                let mut g = self.requestq.lock();
                if !g.busy && g.pending.is_empty() && g.deferred.is_empty() { g.busy = true; return; }
            }
            #[cfg(target_os = "oxide-kernel")]
            {
                // Park on this device's turn wait list, not the shared
                // completion fan-out: a completion on another device must
                // not consume this queue's only turn wake.
                // Register-then-recheck under `inflight` (same B1426 gap:
                // `release_turn` can run on another cpu between our last poll
                // and the park registration).
                park_blk_checked(&self.turn_wait, 0, || {
                    self.poisoned.load(core::sync::atomic::Ordering::Acquire) || {
                        let g = self.requestq.lock();
                        !g.busy && g.pending.is_empty() && g.deferred.is_empty()
                    }
                });
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            { core::hint::spin_loop(); }
        }
    }

    pub(super) fn release_turn(&self) {
        self.requestq.lock().busy = false;
        // Queue release is a block-dispatch event, not a reason to recurse
        // into request posting on the caller's filesystem stack. Linux
        // blk-mq schedules hardware-queue dispatch separately; the registered
        // completion bottom half owns the same deferred-dispatch transition.
        // Raising it here also covers a synchronous owner whose completion
        // was observed directly by its waiter rather than by the walker.
        block::completion::raise();
        // Hand a still-free turn to exactly ONE FIFO waiter (no herd). The
        // woken task re-checks the condition and re-parks if dispatch has
        // consumed the turn or populated the async pending queue.
        #[cfg(target_os = "oxide-kernel")]
        self.turn_wait.wake_one();
    }
}
