use super::*;

impl BlkState {
    pub(super) fn wait_for_completion(&self, h: u64, target: u16) -> KResult<()> {
        let used = h.wrapping_add(self.requestq.device_pa) as *const u16;
        #[cfg(target_os = "oxide-kernel")]
        let deadline = now_ns().saturating_add(IO_TIMEOUT_NS);
        let mut spun: u64 = 0;
        loop {
            // SAFETY: virtio owns the used-ring index at this DMA address.
            let uidx = unsafe { core::ptr::read_volatile(used.add(1)) };
            if uidx == target {
                self.inflight.lock().used_seen = uidx;
                return Ok(());
            }
            #[cfg(target_os = "oxide-kernel")]
            {
                if now_ns() >= deadline {
                    self.poisoned.store(true, core::sync::atomic::Ordering::Release);
                    klog::write_raw(b"[BLK-TIMEOUT] device poisoned, used stuck\n");
                    return Err(BlockError::Eio);
                }
                if spun < IO_SPIN_BUDGET { spun += 1; core::hint::spin_loop(); }
                else { park_blk(); }
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            {
                spun += 1;
                if spun > IO_FALLBACK_SPINS { return Err(BlockError::Eio); }
                core::hint::spin_loop();
            }
        }
    }

    pub(super) fn acquire_turn(&self) {
        #[cfg(target_os = "oxide-kernel")]
        let mut spun: u64 = 0;
        loop {
            if self.poisoned.load(core::sync::atomic::Ordering::Acquire) { return; }
            {
                let mut g = self.inflight.lock();
                if !g.busy && g.pending.is_empty() && g.deferred.is_empty() { g.busy = true; return; }
            }
            #[cfg(target_os = "oxide-kernel")]
            { if spun < IO_SPIN_BUDGET { spun += 1; core::hint::spin_loop(); } else { park_blk(); } }
            #[cfg(not(target_os = "oxide-kernel"))]
            { core::hint::spin_loop(); }
        }
    }

    pub(super) fn release_turn(&self) {
        self.inflight.lock().busy = false;
        #[cfg(target_os = "oxide-kernel")]
        BLK_COMPL.wake_all();
    }
}
