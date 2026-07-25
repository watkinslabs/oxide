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
                if uidx == target { self.inflight.lock().used_seen = uidx; return Ok(()); }
                spun += 1;
                if spun > IO_FALLBACK_SPINS { return Err(BlockError::Eio); }
                core::hint::spin_loop();
            }
        }
        #[cfg(target_os = "oxide-kernel")]
        {
            let deadline = now_ns().saturating_add(IO_TIMEOUT_NS);
            loop {
                // The kernel runs this syscall/fault IF=0; a long busy-poll here
                // would freeze the timer tick + every wakeup for the whole I/O
                // (B1386 root cause: I/O-storm tick stalls up to seconds). Poll
                // the lock-free used-ring with IRQs ENABLED so the tick + the
                // BlockIo completion softirq keep firing. IRQs are restored to
                // IF=0 before touching `inflight` (the completion softirq also
                // takes it) and before `park_blk` (schedule()/rq.inner are not
                // IRQ-safe). The poll below holds NO lock. See 06§3.1 + the
                // lock-safety audit: no ext4/block caller holds a plain lock
                // across this wait.
                let irq = irq_save_enable();
                let mut spun: u64 = 0;
                let mut seen = false;
                let mut timed_out = false;
                while spun < IO_SPIN_BUDGET {
                    // SAFETY: virtio owns the used-ring index at this DMA address.
                    let uidx = unsafe { core::ptr::read_volatile(used.add(1)) };
                    if uidx == target { seen = true; break; }
                    if now_ns() >= deadline { timed_out = true; break; }
                    spun += 1;
                    core::hint::spin_loop();
                }
                irq_restore(irq);
                if seen {
                    self.inflight.lock().used_seen = target;
                    return Ok(());
                }
                if timed_out || now_ns() >= deadline {
                    self.poisoned.store(true, core::sync::atomic::Ordering::Release);
                    klog::write_raw(b"[BLK-TIMEOUT] device poisoned, used stuck\n");
                    return Err(BlockError::Eio);
                }
                // Spin budget exhausted without completion: park off-CPU (IF=0)
                // on the COMPLETION condition — not the shared list, so a freed
                // engine turn doesn't rouse this waiter.
                park_blk(&BLK_COMPL);
            }
        }
    }

    pub(super) fn acquire_turn(&self) {
        loop {
            if self.poisoned.load(core::sync::atomic::Ordering::Acquire) { return; }
            {
                let mut g = self.inflight.lock();
                if !g.busy && g.pending.is_empty() && g.deferred.is_empty() { g.busy = true; return; }
            }
            #[cfg(target_os = "oxide-kernel")]
            {
                // Wait for the turn with IRQs ENABLED across the lock-free spin
                // (holds no lock), IF=0 for the `inflight` probe above and the
                // park below, so a nested tick never contends `inflight` with
                // the BlockIo softirq. Same B1386 rationale as wait_for_completion.
                let irq = irq_save_enable();
                let mut spun: u64 = 0;
                while spun < IO_SPIN_BUDGET {
                    if self.poisoned.load(core::sync::atomic::Ordering::Acquire) { break; }
                    spun += 1;
                    core::hint::spin_loop();
                }
                irq_restore(irq);
                // Park on BLK_TURN (turn availability), NOT BLK_COMPL: a
                // request completion must not wake every turn-waiter.
                if spun >= IO_SPIN_BUDGET { park_blk(&BLK_TURN); }
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            { core::hint::spin_loop(); }
        }
    }

    pub(super) fn release_turn(&self) {
        self.inflight.lock().busy = false;
        // Hand the freed turn to exactly ONE FIFO waiter (no herd). The woken
        // task re-checks `acquire_turn`'s condition and re-parks if a concurrent
        // async request took the turn first.
        #[cfg(target_os = "oxide-kernel")]
        BLK_TURN.wake_one();
    }
}
