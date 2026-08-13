//! AHCI block-device serialization, interrupt wait, and teardown.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::{AtomicBool, Ordering};

use block::{BlockDevice, BlockError, BlockOp, BlockRequest, KResult};
use sched::live::wait_list::WaitList;
use sync::{Spinlock, TaskList as DriverLockClass};

use crate::irq::IrqBinding;
use crate::lifecycle::{self, ControllerCleanupStep};
use crate::port::Ahci;
use crate::wait;

pub struct AhciBlk {
    ctrl:       Spinlock<Ahci, DriverLockClass>,
    irq:        IrqBinding,
    turn_wait:  WaitList,
    turn_busy:  AtomicBool,
    blk_size:   u32,
    capacity:   u64,
    removed:    AtomicBool,
    poisoned:   AtomicBool,
}

impl AhciBlk {
    /// Build one unpublished block device from a bound controller. # C: O(1)
    pub(crate) fn new(
        ctrl: Ahci,
        irq: IrqBinding,
        blk_size: u32,
        capacity: u64,
    ) -> Self {
        Self {
            ctrl: Spinlock::new(ctrl),
            irq,
            turn_wait: WaitList::new(),
            turn_busy: AtomicBool::new(false),
            blk_size,
            capacity,
            removed: AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
        }
    }

    fn unavailable(&self) -> bool {
        self.removed.load(Ordering::Acquire)
            || self.poisoned.load(Ordering::Acquire)
    }

    fn chunk_blocks(&self) -> u64 {
        (Ahci::MAX_XFER / self.blk_size as u64).max(1)
    }

    fn acquire_turn(&self) -> bool {
        let deadline = wait::now_ns().saturating_add(wait::IO_TIMEOUT_NS);
        loop {
            if self.unavailable() { return false; }
            if self
                .turn_busy
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                if !self.unavailable() { return true; }
                self.release_turn();
                return false;
            }
            if wait::now_ns() >= deadline {
                self.poisoned.store(true, Ordering::Release);
                return false;
            }
            if !wait::poll_enabled(
                || self.unavailable() || !self.turn_busy.load(Ordering::Acquire),
                deadline,
            ) {
                if wait::now_ns() >= deadline {
                    self.poisoned.store(true, Ordering::Release);
                    return false;
                }
                wait::park_checked(&self.turn_wait, deadline, || {
                    self.unavailable() || !self.turn_busy.load(Ordering::Acquire)
                });
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
            if self.irq.completed() { return !self.irq.failed(); }
            if wait::now_ns() >= deadline {
                self.poisoned.store(true, Ordering::Release);
                klog::write_raw(b"[AHCI-TIMEOUT] interrupt completion missing\n");
                return false;
            }
            if wait::poll_enabled(
                || self.unavailable() || self.irq.completed(),
                deadline,
            ) { continue; }
            // `sti` admits an IRQ after poll_enabled's predicate load and
            // before it restores the caller's prior mask. Recheck after the
            // restore before publishing a sleeper so that completion does
            // not fall through to a needless park.
            if self.unavailable() || self.irq.completed() { continue; }
            if wait::now_ns() >= deadline {
                self.poisoned.store(true, Ordering::Release);
                klog::write_raw(b"[AHCI-TIMEOUT] interrupt completion missing\n");
                return false;
            }
            wait::park_checked(self.irq.waiters(), deadline, || {
                self.unavailable() || self.irq.completed()
            });
        }
    }

    fn rw_chunk(
        &self,
        req: &mut BlockRequest,
        write: bool,
        lba: u64,
        count: u16,
        off: usize,
        len: usize,
    ) -> bool {
        if !self.acquire_turn() { return false; }
        self.irq.prepare_command();
        let deadline = wait::now_ns().saturating_add(wait::IO_TIMEOUT_NS);
        let waiter_prepared = wait::prepare_command_wait(self.irq.waiters(), deadline);
        let (started, bootstrap_complete) = {
            let mut ctrl = self.ctrl.lock();
            if self.unavailable() {
                (false, false)
            } else {
                let data = ctrl.data_va() as *mut u8;
                if data.is_null() {
                    (false, false)
                } else {
                    if write {
                        // SAFETY: the turn exclusively owns the controller's
                        // contiguous DMA run and len is chunk-bounded.
                        unsafe {
                            for i in 0..len {
                                core::ptr::write_volatile(
                                    data.add(i),
                                    req.buffer[off + i],
                                );
                            }
                        }
                        pmm::dma::clean_to_device(ctrl.data_va(), len);
                    }
                    let started = ctrl.start_rw(write, lba, count);
                    let complete = started && !waiter_prepared
                        && ctrl.poll_command_completion();
                    (started, complete)
                }
            }
        };
        if started && waiter_prepared && !self.irq.completed() {
            wait::yield_prepared_command_wait();
        }
        if waiter_prepared { self.irq.waiters().cancel_current_park(); }
        let mut ok = started && (bootstrap_complete || self.wait_for_irq());
        if ok {
            let ctrl = self.ctrl.lock();
            if self.unavailable() || !ctrl.command_finished_ok() {
                ok = false;
            } else if !write {
                let data = ctrl.data_va() as *const u8;
                pmm::dma::invalidate_from_device(data as u64, len);
                // SAFETY: terminal IRQ plus command_finished_ok establish DMA
                // completion; the turn retains exclusive DMA-run ownership.
                unsafe {
                    for i in 0..len {
                        req.buffer[off + i] =
                            core::ptr::read_volatile(data.add(i));
                    }
                }
            }
        }
        if started && !ok { self.poisoned.store(true, Ordering::Release); }
        self.release_turn();
        ok
    }

    fn flush_command(&self) -> bool {
        if !self.acquire_turn() { return false; }
        self.irq.prepare_command();
        let deadline = wait::now_ns().saturating_add(wait::IO_TIMEOUT_NS);
        let waiter_prepared = wait::prepare_command_wait(self.irq.waiters(), deadline);
        let (started, bootstrap_complete) = {
            let mut ctrl = self.ctrl.lock();
            let started = !self.unavailable() && ctrl.start_flush();
            let complete = started && !waiter_prepared
                && ctrl.poll_command_completion();
            (started, complete)
        };
        if started && waiter_prepared && !self.irq.completed() {
            wait::yield_prepared_command_wait();
        }
        if waiter_prepared { self.irq.waiters().cancel_current_park(); }
        let mut ok = started && (bootstrap_complete || self.wait_for_irq());
        if ok {
            let ctrl = self.ctrl.lock();
            ok = !self.unavailable() && ctrl.command_finished_ok();
        }
        if started && !ok { self.poisoned.store(true, Ordering::Release); }
        self.release_turn();
        ok
    }

    /// Wake the command owner when its hard handler requested fanout. # C: O(waiters)
    pub(crate) fn completion_bottom_half(&self) {
        if self.irq.take_wake() { self.irq.waiters().wake_all(); }
    }

    #[cfg(feature = "debug-boot")]
    /// Count terminal hardware IRQ completions for boot verification. # C: O(1)
    pub(crate) fn irq_completion_count(&self) -> u64 {
        self.irq.completion_count()
    }

    fn quiesce_and_free(&self) {
        if self.removed.swap(true, Ordering::AcqRel) { return; }
        self.irq.waiters().wake_all();
        self.turn_wait.wake_all();
        let mut ctrl = self.ctrl.lock();
        for step in lifecycle::controller_cleanup_steps() {
            match step {
                ControllerCleanupStep::MaskAndFreeIrq => {
                    self.irq.begin_release(&ctrl);
                }
                ControllerCleanupStep::SynchronizeIrq => {
                    self.irq.synchronize_and_release();
                }
                ControllerCleanupStep::ReleaseController => {
                    ctrl.shutdown_and_free();
                }
            }
        }
    }

    /// Mask/synchronize IRQs, stop DMA, and release owned resources. # C: O(stop)
    pub(crate) fn remove(&self) { self.quiesce_and_free(); }

    /// Quiesce for terminal shutdown with publication retained. # C: O(stop)
    pub(crate) fn shutdown(&self) { self.quiesce_and_free(); }
}

impl BlockDevice for AhciBlk {
    fn block_size(&self) -> u32 { self.blk_size }

    fn capacity_blocks(&self) -> u64 { self.capacity }

    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        if self.unavailable() { return Err(BlockError::Eio); }
        match req.op {
            BlockOp::Flush => {
                if self.flush_command() { Ok(()) } else { Err(BlockError::Eio) }
            }
            BlockOp::Discard | BlockOp::WriteZeroes { .. } => {
                Err(BlockError::Eopnotsupp)
            }
            BlockOp::Read | BlockOp::Write => {
                let bs = self.blk_size as usize;
                let nbytes = (req.len_blocks as usize)
                    .checked_mul(bs)
                    .ok_or(BlockError::Einval)?;
                if req.op == BlockOp::Read {
                    if req.buffer.len() < nbytes { req.buffer.resize(nbytes, 0); }
                } else if req.buffer.len() < nbytes {
                    return Err(BlockError::Einval);
                }
                let write = req.op == BlockOp::Write;
                let mut done = 0u64;
                while done < req.len_blocks as u64 {
                    let count = core::cmp::min(
                        self.chunk_blocks(),
                        req.len_blocks as u64 - done,
                    );
                    let off = done as usize * bs;
                    let len = count as usize * bs;
                    if !self.rw_chunk(
                        req,
                        write,
                        req.start_block + done,
                        count as u16,
                        off,
                        len,
                    ) {
                        return Err(BlockError::Eio);
                    }
                    done += count;
                }
                Ok(())
            }
        }
    }

    fn flush(&self) -> KResult<()> {
        if self.flush_command() { Ok(()) } else { Err(BlockError::Eio) }
    }
}
