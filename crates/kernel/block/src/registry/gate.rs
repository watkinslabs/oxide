//! Registry-owned I/O admission, destructive quiesce, and live-reset freeze.

use alloc::boxed::Box;
use alloc::sync::Arc;
use sync::{Devices as DevicesClass, Spinlock};
use crate::blockdev::{BlockCompletion, BlockDevice, BlockRequest};
use crate::queue_limits::QueueLimits;
use crate::types::{BlockError, KResult};
use super::core::{Disk, DISK_REMOVE_HOOK, TABLE, by_name, release_number};

/// Holder/open state is separate from both exclusive removal and reset queue
/// freeze. A reset keeps the published disk, its `dev_t`, and its users live.
pub(super) struct DiskLifecycle {
    pub(super) holders: u32,
    pub(super) openers: u32,
    pub(super) lifecycle_held: bool,
    pub(super) reset_frozen: bool,
    pub(super) detached: bool,
}
pub(super) struct DiskIo {
    pub(super) in_flight: u32,
    pub(super) closed: bool,
    pub(super) detached: bool,
    pub(super) max_discard_sectors: u32,
    #[cfg(target_os = "oxide-kernel")]
    pub(super) drain_wait: Arc<sched::live::WaitList>,
}

struct SubmissionToken {
    io: Arc<Spinlock<DiskIo, DevicesClass>>,
    #[cfg(target_os = "oxide-kernel")]
    drain_wait: Arc<sched::live::WaitList>,
}
impl Drop for SubmissionToken {
    fn drop(&mut self) {
        let mut io = self.io.lock_bh::<crate::bh_gate::BlockBh>();
        hal::kassert!(io.in_flight != 0, "block submission underflow");
        io.in_flight -= 1;
        drop(io);
        #[cfg(target_os = "oxide-kernel")]
        self.drain_wait.wake_all();
    }
}

/// Registry-owned submission decorator. `Disk::dev` exposes this wrapper, so
/// every synchronous and asynchronous request shares this one gate.
pub(super) struct AdmissionDev {
    pub(super) inner: Arc<dyn BlockDevice>,
    pub(super) io: Arc<Spinlock<DiskIo, DevicesClass>>,
}
impl AdmissionDev {
    fn admit(&self) -> KResult<SubmissionToken> {
        let mut io = self.io.lock_bh::<crate::bh_gate::BlockBh>();
        if io.detached { return Err(BlockError::Eio); }
        if io.closed { return Err(BlockError::Ebusy); }
        let Some(next) = io.in_flight.checked_add(1) else { return Err(BlockError::Ebusy); };
        io.in_flight = next;
        Ok(SubmissionToken {
            io: Arc::clone(&self.io),
            #[cfg(target_os = "oxide-kernel")]
            drain_wait: Arc::clone(&io.drain_wait),
        })
    }

    fn submit_discard_sync(&self, request: &mut BlockRequest) -> KResult<()> {
        let limits = self.queue_limits()?;
        if !self.inner.supports_discard() || limits.max_discard_sectors() == 0 { return Err(BlockError::Eopnotsupp); }
        let max_blocks = u64::from(limits.max_discard_sectors()) * u64::from(crate::LINUX_SECTOR_BYTES)
            / u64::from(self.inner.block_size());
        if max_blocks == 0 { return Err(BlockError::Einval); }
        let mut start = request.start_block;
        let mut remaining = request.len_blocks;
        while remaining != 0 {
            let chunk = remaining.min(u32::try_from(max_blocks).unwrap_or(u32::MAX));
            let mut part = BlockRequest::new_discard(start, chunk);
            self.inner.submit_sync(&mut part)?;
            start = start.checked_add(u64::from(chunk)).ok_or(BlockError::Einval)?;
            remaining -= chunk;
        }
        Ok(())
    }
}
impl BlockDevice for AdmissionDev {
    fn block_size(&self) -> u32 { self.inner.block_size() }
    fn queue_limits(&self) -> KResult<QueueLimits> {
        let limits = self.inner.queue_limits()?;
        limits.with_discard(limits.max_hw_discard_sectors(), self.io.lock_bh::<crate::bh_gate::BlockBh>().max_discard_sectors,
            limits.discard_granularity())
    }
    fn supports_discard(&self) -> bool { self.inner.supports_discard() }
    fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }
    fn submit(&self, mut request: BlockRequest, completion: BlockCompletion) {
        request.ioprio = crate::elevator::stamp(request.ioprio, sched::current_ioprio());
        let token = match self.admit() { Ok(token) => token, Err(error) => { completion(request, Err(error)); return; } };
        if request.op == crate::BlockOp::Discard {
            let result = self.submit_discard_sync(&mut request);
            completion(request, result);
            drop(token);
            return;
        }
        self.inner.submit(request, Box::new(move |request, result| { completion(request, result); drop(token); }));
    }
    fn submit_sync(&self, request: &mut BlockRequest) -> KResult<()> {
        request.ioprio = crate::elevator::stamp(request.ioprio, sched::current_ioprio());
        let token = self.admit()?;
        let result = if request.op == crate::BlockOp::Discard { self.submit_discard_sync(request) } else { self.inner.submit_sync(request) };
        drop(token);
        result
    }
    fn flush(&self) -> KResult<()> {
        let token = self.admit()?;
        let result = self.inner.flush();
        drop(token);
        result
    }
    fn can_poll(&self) -> bool { self.inner.can_poll() }
    /// Completion polling has no admission token: it can only retire a request
    /// that the freeze is waiting to drain. # C: O(reaped)
    fn poll_completions(&self) -> usize { self.inner.poll_completions() }
    fn swap_slot_free_notify(&self, start_block: u64, len_blocks: u32) -> KResult<()> {
        let token = self.admit()?;
        let result = self.inner.swap_slot_free_notify(start_block, len_blocks);
        drop(token);
        result
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum GateKind { Lifecycle, Reset }

/// Held queue state. `try_quiesce` creates the destructive lifecycle form;
/// `try_freeze_for_reset` preserves all openers, holders, and publication.
pub struct DiskQuiesce { disk: Arc<Disk>, active: bool, kind: GateKind }
impl DiskQuiesce {
    /// Name of the disk whose admission gate this token owns. # C: O(1)
    pub fn name(&self) -> &str { &self.disk.name }
    /// True only after requests admitted before the gate closed have retired. # C: O(1)
    pub fn is_drained(&self) -> bool { self.disk.io.lock_bh::<crate::bh_gate::BlockBh>().in_flight == 0 }
    /// Wait for the pre-freeze request population to retire. Reset callers must
    /// wait before touching controller state. # Ctx: process # Sleeps: yes
    pub fn wait_for_drain(&self) {
        #[cfg(target_os = "oxide-kernel")]
        {
            let wait = Arc::clone(&self.disk.io.lock_bh::<crate::bh_gate::BlockBh>().drain_wait);
            // SAFETY: process context owns this live freeze token and holds no queue lock while asleep.
            unsafe { sched::live::wait_event_uninterruptible(&wait, || self.is_drained()); }
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        while !self.is_drained() {
            #[cfg(any(test, feature = "hosted"))]
            std::thread::yield_now();
            #[cfg(not(any(test, feature = "hosted")))]
            core::hint::spin_loop();
        }
    }

    /// Atomically remove a disk only from the idle-only lifecycle form. # C: O(N_disks)
    pub fn unregister(mut self) -> bool {
        if self.kind != GateKind::Lifecycle { return false; }
        let disk = self.disk.clone();
        let name = disk.name.clone();
        let removed = {
            // SAFETY: destructive disk lifecycle runs in process context; no completion path takes this mutex.
            let mut table = unsafe { TABLE.lock() };
            let Some(pos) = table.iter().position(|d| Arc::ptr_eq(d, &disk)) else { return false; };
            table.remove(pos);
            true
        };
        if !removed { return false; }
        disk.io.lock_bh::<crate::bh_gate::BlockBh>().detached = true;
        // SAFETY: lifecycle token owns exclusive destructive state.
        unsafe { disk.life.lock() }.detached = true;
        disk.mapping.invalidate_clean();
        super::partition::unpublish_partitions(&disk);
        crate::devbridge::unpublish(disk.number);
        release_number(disk.driver, disk.number);
        if let Some(dev) = drv::devices().into_iter().find(|d| d.bus == "block" && d.addr == name) { drv::device_del(&dev); }
        // SAFETY: removal copies the process-context hook before calling it unlocked.
        let hook = *unsafe { DISK_REMOVE_HOOK.lock() };
        if let Some(f) = hook { f(&name); }
        self.active = false;
        true
    }
}
impl Drop for DiskQuiesce {
    fn drop(&mut self) {
        if !self.active { return; }
        self.disk.io.lock_bh::<crate::bh_gate::BlockBh>().closed = false;
        // SAFETY: reopen the matching state only after I/O admission is live.
        let mut life = unsafe { self.disk.life.lock() };
        match self.kind {
            GateKind::Lifecycle => life.lifecycle_held = false,
            GateKind::Reset => life.reset_frozen = false,
        }
        self.active = false;
    }
}

/// Acquire the idle-only destructive lifecycle gate. # C: O(N_disks)
pub fn try_quiesce(name: &str) -> Option<DiskQuiesce> {
    if let Some(disk) = by_name(name) { let _ = disk.mapping.write_and_wait(); }
    let disk = by_name(name)?;
    // SAFETY: lifecycle serialization is process-context work on a stable Arc.
    let mut life = unsafe { disk.life.lock() };
    if life.lifecycle_held || life.reset_frozen || life.detached || life.holders != 0 || life.openers != 0 { return None; }
    life.lifecycle_held = true;
    drop(life);
    let mut io = disk.io.lock_bh::<crate::bh_gate::BlockBh>();
    if io.in_flight != 0 {
        drop(io);
        // SAFETY: this unsuccessful owner alone reverses its lifecycle hold.
        unsafe { disk.life.lock() }.lifecycle_held = false;
        return None;
    }
    io.closed = true;
    drop(io);
    Some(DiskQuiesce { disk, active: true, kind: GateKind::Lifecycle })
}

/// Start a live reset freeze. It closes request admission without treating
/// holders or open files as removal blockers; call `wait_for_drain` before
/// resetting hardware, then retain the token until hardware is usable. # C: O(N_disks)
pub fn try_freeze_for_reset(name: &str) -> Option<DiskQuiesce> {
    let disk = by_name(name)?;
    // SAFETY: reset and removal serialize through one process-context lifecycle state.
    let mut life = unsafe { disk.life.lock() };
    if life.lifecycle_held || life.reset_frozen || life.detached { return None; }
    life.reset_frozen = true;
    drop(life);
    disk.io.lock_bh::<crate::bh_gate::BlockBh>().closed = true;
    Some(DiskQuiesce { disk, active: true, kind: GateKind::Reset })
}
