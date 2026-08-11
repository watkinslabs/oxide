//! NVMe request serialization and MSI completion waits.

use super::*;

impl NvmeBlk {
    fn chunk_bytes(&self) -> usize { Nvme::MAX_XFER as usize }

    pub(super) fn chunk_blocks(&self) -> u64 { (self.chunk_bytes() as u64) / (self.blk_size as u64) }

    pub(super) fn unavailable(&self) -> bool {
        self.removed.load(Ordering::Acquire) || self.poisoned.load(Ordering::Acquire)
    }

    fn acquire_turn(&self) -> bool {
        let deadline = wait::now_ns().saturating_add(wait::IO_TIMEOUT_NS);
        loop {
            if self.unavailable() { return false; }
            if self.turn_busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                if !self.unavailable() { return true; }
                self.release_turn();
                return false;
            }
            if wait::now_ns() >= deadline {
                self.poisoned.store(true, Ordering::Release);
                return false;
            }
            if !wait::poll_enabled(|| self.unavailable() || !self.turn_busy.load(Ordering::Acquire), deadline) {
                if wait::now_ns() >= deadline {
                    self.poisoned.store(true, Ordering::Release);
                    return false;
                }
                wait::park_checked(&self.turn_wait, deadline, || self.unavailable() || !self.turn_busy.load(Ordering::Acquire));
            }
        }
    }

    fn release_turn(&self) {
        self.turn_busy.store(false, Ordering::Release);
        self.turn_wait.wake_one();
    }

    fn wait_for_irq(&self) -> bool {
        let deadline = wait::now_ns().saturating_add(wait::IO_TIMEOUT_NS);
        loop {
            if self.unavailable() { return false; }
            if self.irq.completed() { return true; }
            if wait::now_ns() >= deadline {
                self.poisoned.store(true, Ordering::Release);
                return false;
            }
            if wait::poll_enabled(|| self.unavailable() || self.irq.completed(), deadline) { continue; }
            if wait::now_ns() >= deadline {
                self.poisoned.store(true, Ordering::Release);
                return false;
            }
            wait::park_checked(&self.completion, deadline, || self.unavailable() || self.irq.completed());
        }
    }

    pub(super) fn rw_chunk(&self, req: &mut BlockRequest, write: bool, lba: u64, count: u16, off: usize, len: usize) -> bool {
        if !self.acquire_turn() { return false; }
        self.irq.prepare_command();
        let pending = {
            let mut ctrl = self.ctrl.lock();
            if self.unavailable() { None } else {
                let bounce = ctrl.prp_va() as *mut u8;
                if bounce.is_null() { None } else {
                    if write {
                        // SAFETY: the turn exclusively owns the one-page PRP bounce frame; len is chunk-bounded.
                        unsafe { for i in 0..len { core::ptr::write_volatile(bounce.add(i), req.buffer[off + i]); } }
                    }
                    ctrl.rw_submit(write, lba, count - 1)
                }
            }
        };
        let mut ok = pending.is_some() && self.wait_for_irq();
        if let Some(pending) = pending {
            if ok {
                let mut ctrl = self.ctrl.lock();
                ok = !self.unavailable() && ctrl.try_reap_io(pending) == Some(0);
                if ok && !write {
                    let bounce = ctrl.prp_va() as *const u8;
                    // SAFETY: a matching completed CQE establishes DMA completion; the turn still owns the bounce frame.
                    unsafe { for i in 0..len { req.buffer[off + i] = core::ptr::read_volatile(bounce.add(i)); } }
                }
            }
        }
        if pending.is_some() && !ok { self.poisoned.store(true, Ordering::Release); }
        self.release_turn();
        ok
    }

    pub(super) fn flush_command(&self) -> bool {
        if !self.acquire_turn() { return false; }
        self.irq.prepare_command();
        let pending = {
            let mut ctrl = self.ctrl.lock();
            if self.unavailable() { None } else { ctrl.flush_submit() }
        };
        let mut ok = pending.is_some() && self.wait_for_irq();
        if let Some(pending) = pending {
            if ok {
                let mut ctrl = self.ctrl.lock();
                ok = !self.unavailable() && ctrl.try_reap_io(pending) == Some(0);
            }
        }
        if pending.is_some() && !ok { self.poisoned.store(true, Ordering::Release); }
        self.release_turn();
        ok
    }

    /// Wake completion waiters from the process-safe block softirq. # C: O(waiters)
    pub(crate) fn completion_bottom_half(&self) {
        if self.irq.take_wake() { self.completion.wake_all(); }
    }
}
