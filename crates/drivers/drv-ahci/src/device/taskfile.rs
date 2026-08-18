//! Interrupt-driven raw ATA taskfile execution below the SAT owner.

use core::sync::atomic::Ordering;

use block::{BlockError, KResult};

use super::AhciBlk;
use crate::port::Ahci;
use crate::{limits, wait};

impl AhciBlk {
    fn wait_for_taskfile(&self, deadline: u64) -> bool {
        loop {
            if self.unavailable() { return false; }
            if self.irq.completed() { return true; }
            if wait::now_ns() >= deadline { return false; }
            if wait::poll_enabled(|| self.unavailable() || self.irq.completed(), deadline) { continue; }
            if self.unavailable() || self.irq.completed() { continue; }
            if wait::now_ns() >= deadline { return false; }
            wait::park_checked(self.irq.waiters(), deadline, || self.unavailable() || self.irq.completed());
        }
    }

    fn taskfile_deadline(timeout_ms: u32) -> u64 {
        const NS_PER_MS: u64 = 1_000_000;
        let timeout = if timeout_ms == 0 { limits::COMMAND_TIMEOUT_NS }
            else { u64::from(timeout_ms).saturating_mul(NS_PER_MS) };
        wait::now_ns().saturating_add(timeout)
    }
}

impl ata::Device for AhciBlk {
    fn identify_page(&self) -> Option<[u8; ata::IDENTIFY_BYTES]> {
        if self.unavailable() { return None; }
        let page = self.ctrl.lock().identity_page();
        if self.unavailable() { None } else { Some(page) }
    }

    fn execute_taskfile(&self, taskfile: ata::Taskfile, data: &mut [u8], timeout_ms: u32)
        -> KResult<ata::TaskfileResult>
    {
        if self.unavailable() || data.len() > Ahci::MAX_XFER as usize { return Err(BlockError::Eio); }
        if !self.acquire_turn() { return Err(BlockError::Eio); }
        self.irq.prepare_command();
        let deadline = Self::taskfile_deadline(timeout_ms);
        let waiter_prepared = wait::prepare_command_wait(self.irq.waiters(), deadline);
        let (started, bootstrap_complete) = {
            let mut ctrl = self.ctrl.lock();
            if self.unavailable() || (!data.is_empty() && ctrl.data_va() == 0) {
                (false, false)
            } else {
                let data_va = ctrl.data_va();
                if taskfile.protocol.writes() && !data.is_empty() {
                    // SAFETY: this port turn exclusively owns the contiguous
                    // DMA run and the caller's length is bounded above.
                    unsafe {
                        for (index, byte) in data.iter().enumerate() {
                            core::ptr::write_volatile((data_va as *mut u8).add(index), *byte);
                        }
                    }
                    pmm::dma::clean_to_device(data_va, data.len());
                }
                let started = ctrl.start_taskfile(&taskfile, data.len());
                if started {
                    self.irq.command_issued();
                    if let Some(tfd) = ctrl.command_terminal_tfd() { self.irq.complete_from_poll(tfd); }
                }
                let complete = started && !waiter_prepared && ctrl.poll_command_completion().is_some_and(|tfd| {
                    self.irq.complete_from_poll(tfd);
                    true
                });
                (started, complete)
            }
        };
        if started && waiter_prepared && !self.irq.completed() { wait::yield_prepared_command_wait(); }
        if waiter_prepared { self.irq.waiters().cancel_current_park(); }
        let completed = started && (bootstrap_complete || self.wait_for_taskfile(deadline));
        let result = if completed {
            let ctrl = self.ctrl.lock();
            if self.unavailable() {
                None
            } else {
                if !taskfile.protocol.writes() && !data.is_empty() {
                    pmm::dma::invalidate_from_device(ctrl.data_va(), data.len());
                    // SAFETY: terminal command completion establishes the DMA
                    // read buffer; the port turn retains exclusive ownership.
                    unsafe {
                        for (index, byte) in data.iter_mut().enumerate() {
                            *byte = core::ptr::read_volatile((ctrl.data_va() as *const u8).add(index));
                        }
                    }
                }
                Some(ctrl.taskfile_result(taskfile.extend))
            }
        } else {
            if !self.recover_failed_command() { self.poisoned.store(true, Ordering::Release); }
            None
        };
        self.release_turn();
        result.ok_or(BlockError::Eio)
    }

    fn max_transfer_bytes(&self) -> usize { Ahci::MAX_XFER as usize }
}
