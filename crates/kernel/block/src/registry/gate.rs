//! Registry-owned I/O admission, destructive quiesce, and live-reset freeze.

use alloc::boxed::Box;
use alloc::sync::Arc;
use sync::{Devices as DevicesClass, Spinlock};
use crate::blockdev::{BlockCompletion, BlockDevice, BlockRequest};
use crate::queue_limits::QueueLimits;
use crate::types::{BlockError, KResult};
use super::core::{Disk, DISK_CLOSE_HOOK, DISK_REMOVE_HOOK, TABLE, by_name, disk_for_dev, release_number};

/// Holder/open state is separate from both exclusive removal and reset queue
/// freeze. A reset keeps the published disk, its `dev_t`, and its users live.
pub(super) struct DiskLifecycle {
    pub(super) holders: u32,
    pub(super) openers: u32,
    pub(super) closing: bool,
    pub(super) lifecycle_held: bool,
    pub(super) reset_frozen: bool,
    pub(super) detached: bool,
}

/// Why a canonical block open was not admitted.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OpenFailure { Missing, Closing }

/// A live-device lifecycle owner that excludes new file opens while retaining
/// a bounded population of existing openers. It mirrors the MD control path:
/// the control file remains usable while all additional device opens fail.
pub struct OpenSeal { disk: Arc<Disk>, active: bool }
impl OpenSeal {
    /// Disk retained until the lifecycle owner releases the open seal. # C: O(1)
    pub fn disk(&self) -> &Arc<Disk> { &self.disk }
}
impl Drop for OpenSeal {
    fn drop(&mut self) {
        if !self.active { return; }
        // SAFETY: this token exclusively set the live disk's closing state.
        unsafe { self.disk.life.lock() }.closing = false;
        self.active = false;
    }
}

/// Refuse new opens while retaining at most `allowed_openers` existing files.
/// The caller keeps the returned token across its cache drain and state
/// transition, then dropping it reopens normal admission. # C: O(N_disks)
pub fn seal_openers(dev_t: u32, allowed_openers: u32) -> KResult<OpenSeal> {
    let disk = disk_for_dev(dev_t).ok_or(BlockError::Enxio)?;
    // SAFETY: a lifecycle control operation runs in process context and owns
    // the closing transition while this mutex protects opener admission.
    let mut life = unsafe { disk.life.lock() };
    if life.lifecycle_held || life.reset_frozen || life.detached || life.closing || life.openers > allowed_openers {
        return Err(BlockError::Ebusy);
    }
    life.closing = true;
    drop(life);
    Ok(OpenSeal { disk, active: true })
}

/// Controlled final-removal owner. It closes future opens and holder claims
/// while one control description completes its cache drain, then unpublishes
/// the disk after every earlier request has retired.
pub struct ControlledRemoval { disk: Arc<Disk>, active: bool }
impl ControlledRemoval {
    /// Disk held by this final lifecycle transaction. # C: O(1)
    pub fn disk(&self) -> &Arc<Disk> { &self.disk }

    /// Close submission, wait for all earlier I/O, and unpublish the disk.
    /// # C: O(N_disks + N_devices + in-flight I/O) # Ctx: process # Sleeps: yes
    pub fn unregister(mut self) -> bool {
        self.disk.io.lock_bh::<crate::bh_gate::BlockBh>().closed = true;
        self.wait_for_drain();
        let disk = self.disk.clone();
        let name = disk.name.clone();
        let removed = {
            // SAFETY: this token owns the only destructive lifecycle state.
            let mut table = unsafe { TABLE.lock() };
            let Some(pos) = table.iter().position(|entry| Arc::ptr_eq(entry, &disk)) else { return false; };
            table.remove(pos);
            true
        };
        if !removed { return false; }
        disk.io.lock_bh::<crate::bh_gate::BlockBh>().detached = true;
        // SAFETY: final removal owns the lifecycle state until publication is gone.
        unsafe { disk.life.lock() }.detached = true;
        disk.mapping.mark_dead();
        super::partition::unpublish_partitions(&disk);
        crate::devbridge::unpublish(disk.number);
        release_number(disk.driver, disk.number);
        if let Some(dev) = drv::devices().into_iter().find(|dev| dev.bus == "block" && dev.addr == name) { drv::device_del(&dev); }
        // SAFETY: removal copies the process-context hook before calling it unlocked.
        let hook = *unsafe { DISK_REMOVE_HOOK.lock() };
        if let Some(f) = hook { f(&name); }
        self.active = false;
        true
    }

    fn wait_for_drain(&self) {
        #[cfg(target_os = "oxide-kernel")]
        {
            let wait = Arc::clone(&self.disk.io.lock_bh::<crate::bh_gate::BlockBh>().drain_wait);
            // SAFETY: this process-context owner closed admission before sleeping.
            unsafe { sched::live::wait_event_uninterruptible(&wait, || self.disk.io.lock_bh::<crate::bh_gate::BlockBh>().in_flight == 0); }
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        while self.disk.io.lock_bh::<crate::bh_gate::BlockBh>().in_flight != 0 {
            #[cfg(any(test, feature = "hosted"))]
            std::thread::yield_now();
            #[cfg(not(any(test, feature = "hosted")))]
            core::hint::spin_loop();
        }
    }
}
impl Drop for ControlledRemoval {
    fn drop(&mut self) {
        if !self.active { return; }
        self.disk.io.lock_bh::<crate::bh_gate::BlockBh>().closed = false;
        // SAFETY: an aborted owner restores only the state it exclusively acquired.
        let mut life = unsafe { self.disk.life.lock() };
        life.closing = false;
        life.lifecycle_held = false;
        self.active = false;
    }
}

/// Close a live disk against new holders and opens while retaining at most the
/// caller's control descriptions until [`ControlledRemoval::unregister`].
/// # C: O(N_disks)
pub fn begin_controlled_removal(dev_t: u32, allowed_openers: u32) -> KResult<ControlledRemoval> {
    let disk = disk_for_dev(dev_t).ok_or(BlockError::Enxio)?;
    // SAFETY: the control ioctl owns this process-context lifecycle transition.
    let mut life = unsafe { disk.life.lock() };
    if life.lifecycle_held || life.reset_frozen || life.detached || life.closing
        || life.holders != 0 || life.openers > allowed_openers { return Err(BlockError::Ebusy); }
    life.closing = true;
    life.lifecycle_held = true;
    drop(life);
    Ok(ControlledRemoval { disk, active: true })
}

/// Open a registered block device by packed `dev_t`, retaining one opener.
/// # C: O(N_disks)
pub fn try_open_by_dev(dev_t: u32) -> Result<(), OpenFailure> {
    let Some(disk) = disk_for_dev(dev_t) else { return Err(OpenFailure::Missing); };
    // SAFETY: VFS open is process context; a contended lifecycle must sleep.
    let mut life = unsafe { disk.life.lock() };
    if life.closing { return Err(OpenFailure::Closing); }
    if life.lifecycle_held || life.detached { return Err(OpenFailure::Missing); }
    let Some(next) = life.openers.checked_add(1) else { return Err(OpenFailure::Missing); };
    life.openers = next;
    Ok(())
}

/// Boolean compatibility form of [`try_open_by_dev`]. # C: O(N_disks)
pub fn open_by_dev(dev_t: u32) -> bool { try_open_by_dev(dev_t).is_ok() }

/// Release the opener acquired by [`open_by_dev`]. # C: O(N_disks)
pub fn close_by_dev(dev_t: u32) -> bool {
    let Some(disk) = disk_for_dev(dev_t) else { return false; };
    close_disk(&disk)
}

/// Release an opener through a retained disk after it has been unpublished.
/// # C: O(1)
pub fn close_disk(disk: &Disk) -> bool {
    // SAFETY: VFS close is process context; it may wait for a concurrent open.
    let mut life = unsafe { disk.life.lock() };
    if life.openers == 0 { return false; }
    life.openers -= 1;
    let final_close = life.openers == 0;
    drop(life);
    if final_close {
        // SAFETY: the close hook is copied under its lifecycle lock and runs
        // after the opener count is visible as zero.
        let hook = *unsafe { DISK_CLOSE_HOOK.lock() };
        if let Some(f) = hook { f(&disk.name); }
    }
    true
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

/// Irreversible surprise-removal state for one published disk.  Construction
/// rejects all future opens, holders, and submissions before unlinking its
/// publication; retained file descriptions then observe `EIO` through the
/// admission wrapper.  The caller waits only for requests admitted before
/// this transition before releasing controller DMA state.
pub struct ForcedDetach { disk: Arc<Disk> }
impl ForcedDetach {
    /// Name retained for the driver's removal record. # C: O(1)
    pub fn name(&self) -> &str { &self.disk.name }
    /// True after every request admitted before detach has completed. # C: O(1)
    pub fn is_drained(&self) -> bool {
        self.disk.io.lock_bh::<crate::bh_gate::BlockBh>().in_flight == 0
    }
    /// Wait until the pre-detach request population has completed. # Ctx: process # Sleeps: yes
    pub fn wait_for_drain(&self) {
        #[cfg(target_os = "oxide-kernel")]
        {
            let wait = Arc::clone(&self.disk.io.lock_bh::<crate::bh_gate::BlockBh>().drain_wait);
            // SAFETY: detach closed admission before this process-context wait and holds no queue lock.
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
    if life.lifecycle_held || life.reset_frozen || life.detached || life.closing || life.holders != 0 || life.openers != 0 { return None; }
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
    if life.lifecycle_held || life.reset_frozen || life.detached || life.closing { return None; }
    life.reset_frozen = true;
    drop(life);
    disk.io.lock_bh::<crate::bh_gate::BlockBh>().closed = true;
    Some(DiskQuiesce { disk, active: true, kind: GateKind::Reset })
}

/// Mark a surprise-removed disk dead and unlink its block publication.  This
/// does not wait for arbitrary open file descriptions: retained handles stay
/// releasable and every later I/O fails.  Drivers must call
/// [`ForcedDetach::wait_for_drain`] before stopping DMA or freeing queues.
/// # C: O(N_disks + N_partitions)
pub fn begin_forced_detach(name: &str) -> Option<ForcedDetach> {
    let disk = by_name(name)?;
    {
        // SAFETY: surprise removal serializes against open, reset, and normal removal in process context.
        let mut life = unsafe { disk.life.lock() };
        if life.lifecycle_held || life.reset_frozen || life.detached { return None; }
        life.detached = true;
    }
    {
        let mut io = disk.io.lock_bh::<crate::bh_gate::BlockBh>();
        io.closed = true;
        io.detached = true;
    }
    let removed = {
        // SAFETY: this disk's detached lifecycle bit makes its publication uniquely removable.
        let mut table = unsafe { TABLE.lock() };
        let pos = table.iter().position(|entry| Arc::ptr_eq(entry, &disk))?;
        table.remove(pos);
        true
    };
    if !removed { return None; }
    disk.mapping.mark_dead();
    super::partition::unpublish_partitions(&disk);
    crate::devbridge::unpublish(disk.number);
    release_number(disk.driver, disk.number);
    if let Some(dev) = drv::devices().into_iter().find(|dev| dev.bus == "block" && dev.addr == disk.name) {
        drv::device_del(&dev);
    }
    // SAFETY: removal copies the process-context hook before calling it unlocked.
    let hook = *unsafe { DISK_REMOVE_HOOK.lock() };
    if let Some(f) = hook { f(&disk.name); }
    Some(ForcedDetach { disk })
}
