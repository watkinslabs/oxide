//! Block registration and the canonical Linux `dev_t` ownership table.

extern crate alloc;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Spinlock, Devices as DevicesClass};

// The running kernel uses the scheduler's sleepable mutex for lifecycle work.
// Host dependency builds have no runqueue, so retain a same-shaped local guard
// there; it exists only to keep model tests from manufacturing a scheduler.
#[cfg(any(target_os = "oxide-kernel", feature = "hosted"))]
use sched::live::Mutex as LifecycleMutex;
#[cfg(not(any(target_os = "oxide-kernel", feature = "hosted")))]
struct LifecycleMutex<T> { inner: Spinlock<T, DevicesClass> }
#[cfg(not(any(target_os = "oxide-kernel", feature = "hosted")))]
impl<T> LifecycleMutex<T> {
    const fn new(value: T) -> Self { Self { inner: Spinlock::new(value) } }
    unsafe fn lock(&self) -> sync::Guard<'_, T, DevicesClass> { self.inner.lock() }
}

use crate::blockdev::{BlockCompletion, BlockDevice, BlockRequest};
use crate::queue_limits::QueueLimits;
use crate::types::{BlockError, KResult};

use super::partition::Partition;

/// Linux assigns dynamic block majors from this reserved range first.
pub const DYNAMIC_MAJOR_FIRST: u32 = 240;
/// Inclusive end of Linux's preferred dynamic block-major range.
pub const DYNAMIC_MAJOR_LAST: u32 = 254;

/// A driver's request for a block major. Fixed majors are Linux UAPI values
/// owned by the respective driver; dynamic majors are allocated once per
/// driver name by this registry (Linux `register_blkdev(0, name)`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MajorRequest { Fixed(u32), Dynamic }

/// Identity of one block driver, passed explicitly at publication time.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BlockDriver { pub name: &'static str, pub major: MajorRequest }
impl BlockDriver {
    /// Make a driver with a Linux-assigned fixed major. # C: O(1)
    pub const fn fixed(name: &'static str, major: u32) -> Self { Self { name, major: MajorRequest::Fixed(major) } }
    /// Make a driver which owns a dynamically allocated Linux block major. # C: O(1)
    pub const fn dynamic(name: &'static str) -> Self { Self { name, major: MajorRequest::Dynamic } }
}

/// Canonical device number allocated to one published disk.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DevNum { pub major: u32, pub minor: u32 }

/// One registered block device.
pub struct Disk {
    pub name: String,
    pub index: u32,
    pub driver: BlockDriver,
    pub number: DevNum,
    pub serial: Option<String>,
    pub dev: Arc<dyn BlockDevice>,
    /// This disk's page cache (Linux `bdev->bd_mapping`) — what a raw
    /// `/dev/<name>` open reads and writes through, and what the device pass
    /// of `sync(2)` writes back. Every OTHER submitter reaches the device
    /// through `dev`'s coherence decorator, which reconciles with this cache
    /// first, so a mounted filesystem and a raw open cannot disagree.
    pub mapping: Arc<crate::bdev::BdevMapping>,
    pub stats: Arc<crate::stats::DiskStats>,
    partitions: LifecycleMutex<Vec<Arc<Partition>>>,
    life: LifecycleMutex<DiskLifecycle>,
    io: Arc<Spinlock<DiskIo, DevicesClass>>,
}

impl Disk {
    /// VFS open file descriptions currently holding this disk (Linux
    /// `bd_openers`). # C: O(1)
    pub fn opener_count(&self) -> u32 {
        // SAFETY: VFS file release is process context and disk lifecycle is a
        // sleepable operation; this lock is never acquired from completion.
        unsafe { self.life.lock() }.openers
    }
    /// Snapshot child partitions from the disk-owned publication table. # C: O(partitions)
    pub fn partitions(&self) -> Vec<Arc<Partition>> {
        // SAFETY: partition publication is process-context lifecycle work.
        unsafe { self.partitions.lock() }.clone()
    }
    /// Replace this disk's discovered partition set after a successful rescan.
    /// # C: O(partitions)
    pub fn publish_partitions(&self, partitions: Vec<Arc<Partition>>) {
        // SAFETY: partition rescans are process-context lifecycle operations.
        *unsafe { self.partitions.lock() } = partitions;
    }
}

/// The generic block-device lifetime state. Holders are kernel consumers such
/// as swap or a zram backing disk; openers are VFS open file descriptions.
/// They are deliberately separate: Linux's `bd_holders` and `bd_openers`
/// answer different lifecycle questions and must never share a counter.
/// `detached` is the terminal state a `del_gendisk`-equivalent leaves behind:
/// the disk is gone, so I/O through a stale handle fails `Eio` like Linux
/// failing a bio against a dead gendisk. `quiesced` is the RECOVERABLE
/// admission hold (suspend / pre-removal drain), which owes `Ebusy`. Keeping
/// them distinct is what lets a caller tell "try later" from "never again".
struct DiskLifecycle { holders: u32, openers: u32, quiesced: bool, detached: bool }
struct DiskIo { in_flight: u32, closed: bool, detached: bool, max_discard_sectors: u32 }

/// One request admitted by the canonical registry-owned queue gate.  The
/// token remains live through an asynchronous completion, so quiesce cannot
/// race a driver request that was accepted before reset/remove began.
struct SubmissionToken { io: Arc<Spinlock<DiskIo, DevicesClass>> }

impl Drop for SubmissionToken {
    fn drop(&mut self) {
        let mut io = self.io.lock_bh::<crate::bh_gate::BlockBh>();
        hal::kassert!(io.in_flight != 0, "block submission underflow");
        io.in_flight -= 1;
    }
}

/// Registry-owned submission decorator.  `Disk::dev` exposes this wrapper,
/// not the raw driver, making it the one admission authority for synchronous
/// and queued block I/O issued through a registered disk.
struct AdmissionDev {
    inner: Arc<dyn BlockDevice>,
    io: Arc<Spinlock<DiskIo, DevicesClass>>,
}

impl AdmissionDev {
    fn admit(&self) -> KResult<SubmissionToken> {
        let mut io = self.io.lock_bh::<crate::bh_gate::BlockBh>();
        if io.detached { return Err(BlockError::Eio); }
        if io.closed { return Err(BlockError::Ebusy); }
        let Some(next) = io.in_flight.checked_add(1) else { return Err(BlockError::Ebusy); };
        io.in_flight = next;
        Ok(SubmissionToken { io: Arc::clone(&self.io) })
    }

    /// Split one discard at the effective canonical queue maximum. Linux's
    /// discard granularity advertises the device allocation unit; it does not
    /// reject a shorter or edge-partial discard before the driver can apply
    /// its own full-page semantics.
    /// # C: O(discard chunks)
    fn submit_discard_sync(&self, request: &mut BlockRequest) -> KResult<()> {
        let limits = self.queue_limits()?;
        if !self.inner.supports_discard() || limits.max_discard_sectors() == 0 {
            return Err(BlockError::Eopnotsupp);
        }
        let bytes_per_block = u64::from(self.inner.block_size());
        let limit_bytes = u64::from(limits.max_discard_sectors()) * u64::from(crate::LINUX_SECTOR_BYTES);
        let max_blocks = limit_bytes / bytes_per_block;
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
        let token = match self.admit() {
            Ok(token) => token,
            Err(error) => { completion(request, Err(error)); return; }
        };
        if request.op == crate::BlockOp::Discard {
            let mut request = request;
            let result = self.submit_discard_sync(&mut request);
            completion(request, result);
            drop(token);
            return;
        }
        self.inner.submit(request, Box::new(move |request, result| {
            completion(request, result);
            drop(token);
        }));
    }
    fn submit_sync(&self, request: &mut BlockRequest) -> KResult<()> {
        request.ioprio = crate::elevator::stamp(request.ioprio, sched::current_ioprio());
        let token = self.admit()?;
        let result = if request.op == crate::BlockOp::Discard {
            self.submit_discard_sync(request)
        } else { self.inner.submit_sync(request) };
        drop(token);
        result
    }
    fn flush(&self) -> KResult<()> {
        let token = self.admit()?;
        let result = self.inner.flush();
        drop(token);
        result
    }
    /// # C: O(1)
    fn can_poll(&self) -> bool { self.inner.can_poll() }
    /// Reaping deliberately takes NO admission token, unlike every submitting
    /// op above. The gate exists to stop NEW I/O entering a disk that is being
    /// quiesced, and quiescing then waits for the in-flight population to
    /// drain; refusing the reap of already-submitted requests would be the one
    /// caller holding that drain up. Polling starts nothing. # C: O(reaped)
    fn poll_completions(&self) -> usize { self.inner.poll_completions() }
    fn swap_slot_free_notify(&self, start_block: u64, len_blocks: u32) -> KResult<()> {
        let token = self.admit()?;
        let result = self.inner.swap_slot_free_notify(start_block, len_blocks);
        drop(token);
        result
    }
}

/// Exclusive admission gate for a live disk. While held, no new holder or VFS
/// opener can be admitted; construction succeeds only after both populations
/// have drained. Reset paths retain this for their whole mutation, and removal
/// consumes it to unpublish the disk.
pub struct DiskQuiesce { disk: Arc<Disk>, active: bool }

impl DiskQuiesce {
    /// Name of the disk whose admission gate this token owns. # C: O(1)
    pub fn name(&self) -> &str { &self.disk.name }

    /// Atomically remove the quiesced disk from generic block publication.
    /// The token prevents a new VFS open or holder claim between the final
    /// busy check and `del_gendisk`-equivalent unpublication. # C: O(N_disks)
    pub fn unregister(mut self) -> bool {
        let disk = self.disk.clone();
        let name = disk.name.clone();
        let removed = {
            // SAFETY: destructive disk lifecycle runs in process context; no
            // completion path takes the publication registry mutex.
            let mut table = unsafe { TABLE.lock() };
            let Some(pos) = table.iter().position(|d| Arc::ptr_eq(d, &disk)) else { return false; };
            table.remove(pos);
            true
        };
        if !removed { return false; }
        // Linux `bdev_mark_dead`: the cache was written back when the
        // admission gate closed (`try_quiesce`); drop what is left of it, so
        // no page survives into a re-registration of the same device number
        // to serve the OLD medium's bytes.
        // The disk is detached, so reopening its admission gate is meaningless —
        // and I/O arriving on a stale handle from here on is a dead-device error,
        // not a retryable hold.
        {
            let mut io = disk.io.lock_bh::<crate::bh_gate::BlockBh>();
            io.detached = true;
        }
        // SAFETY: DiskQuiesce owns the lifecycle exclusion, in process context.
        unsafe { disk.life.lock() }.detached = true;
        disk.mapping.invalidate_clean();
        crate::devbridge::unpublish(disk.number);
        release_number(disk.driver, disk.number);
        if let Some(dev) = drv::devices().into_iter().find(|d| d.bus == "block" && d.addr == name) { drv::device_del(&dev); }
        // Copy the function pointer while locked, then invoke it unlocked: a
        // removal hook can traverse sysfs and must not serialize all registry
        // lifecycle work behind this small policy slot.
        // SAFETY: removal executes in process context after lifecycle exclusion.
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
        // SAFETY: dropping the lifecycle token is process context and reopens
        // waitable open/holder admission only after I/O admission is open.
        unsafe { self.disk.life.lock() }.quiesced = false;
    }
}

struct DriverState { driver: BlockDriver, major: u32, next_minor: u32 }
static TABLE: LifecycleMutex<Vec<Arc<Disk>>> = LifecycleMutex::new(Vec::new());
static DRIVERS: LifecycleMutex<Vec<DriverState>> = LifecycleMutex::new(Vec::new());
static NEXT_DISK_INDEX: AtomicU32 = AtomicU32::new(0);
type DiskRemoveHook = fn(&str);
static DISK_REMOVE_HOOK: LifecycleMutex<Option<DiskRemoveHook>> = LifecycleMutex::new(None);

/// Default owner for in-kernel tests and legacy module adapters. It is dynamic
/// and therefore cannot collide with physical-driver majors.
pub const GENERIC_BLOCK_DRIVER: BlockDriver = BlockDriver::dynamic("oxide-block");

/// Install the disk remove hook used by sysfs to drop stale block dentries. # C: O(1)
pub fn set_remove_hook(f: DiskRemoveHook) {
    // SAFETY: registration runs in process context; this is lifecycle policy.
    *unsafe { DISK_REMOVE_HOOK.lock() } = Some(f);
}

/// Register an explicitly-owned block device. # C: O(N_disks + N_drivers)
pub fn register_with_driver(driver: BlockDriver, name: &str, serial: Option<&str>, dev: Arc<dyn BlockDevice>) -> u32 {
    if let Some(disk) = by_name(name) { return disk.index; }
    let number = match allocate_number(driver) { Some(n) => n, None => return 0 };
    let max_discard_sectors = match dev.queue_limits() {
        Ok(limits) => limits.max_discard_sectors(),
        Err(_) => { release_number(driver, number); return 0; }
    };
    let io = Arc::new(Spinlock::new(DiskIo {
        in_flight: 0, closed: false, detached: false, max_discard_sectors,
    }));
    let admitted: Arc<dyn BlockDevice> = Arc::new(AdmissionDev {
        inner: dev, io: Arc::clone(&io),
    });
    let (accounted, stats) = crate::stats::StatsDev::wrap(admitted);
    // The cache submits through the ACCOUNTED handle and every other
    // submitter through the coherence decorator wrapped around it: cache
    // writeback is counted like any other request, and cannot recursively
    // invalidate the pages it is writing back.
    let mapping = crate::bdev::BdevMapping::new(Arc::clone(&accounted));
    let dev = crate::bdev::CoherentDev::wrap(accounted, Arc::downgrade(&mapping));
    let publication = {
        // SAFETY: publish only after all potentially slow device preparation;
        // the registry lock protects just duplicate resolution and insertion.
        let mut t = unsafe { TABLE.lock() };
        if let Some(existing) = t.iter().find(|d| d.name == name) {
            Err(existing.index)
        } else if let Some(index) = next_disk_index() {
            let disk = Arc::new(Disk {
                name: name.to_string(), index, driver, number,
                serial: serial.filter(|s| !s.is_empty()).map(ToString::to_string), dev, mapping, stats,
                partitions: LifecycleMutex::new(Vec::new()),
        life: LifecycleMutex::new(DiskLifecycle { holders: 0, openers: 0, quiesced: false, detached: false }),
                io,
            });
            t.push(disk.clone());
            Ok((index, disk))
        } else {
            Err(0)
        }
    };
    let (index, bridge_disk) = match publication {
        Ok(published) => published,
        Err(existing_index) => {
            release_number(driver, number);
            return existing_index;
        }
    };
    match drv::try_device_add(Arc::new(
        drv::Device::new("block", name.to_string(), 0, 0, 0)
            .with_devnode("block", name.to_string(), Some((number.major, number.minor))))) {
        Ok(_) => {
            crate::devbridge::publish(number, bridge_disk);
            let _ = super::partition::rescan_partitions(name);
            index
        }
        Err(_) => {
            // SAFETY: registration rollback is process-context lifecycle work.
            let mut t = unsafe { TABLE.lock() };
            if let Some(pos) = t.iter().position(|d| d.name == name && d.index == index) { t.remove(pos); }
            release_number(driver, number);
            0
        }
    }
}

/// Allocate a never-reused published-disk identity.  Linux assigns an
/// increasing disk sequence for each device lifetime; table position is not
/// an identity because removal changes it. # C: O(contention)
fn next_disk_index() -> Option<u32> {
    let mut current = NEXT_DISK_INDEX.load(Ordering::Relaxed);
    loop {
        let next = current.checked_add(1)?;
        match NEXT_DISK_INDEX.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Some(next),
            Err(observed) => current = observed,
        }
    }
}

/// Legacy registration retains a single dynamic driver, never name-prefix
/// inference. New physical and virtual drivers must call `register_with_driver`.
pub fn register(name: &str, dev: Arc<dyn BlockDevice>) -> u32 {
    register_with_driver(GENERIC_BLOCK_DRIVER, name, None, dev)
}
/// Legacy serial registration; see `register`.
pub fn register_with_serial(name: &str, serial: Option<&str>, dev: Arc<dyn BlockDevice>) -> u32 {
    register_with_driver(GENERIC_BLOCK_DRIVER, name, serial, dev)
}

pub(crate) fn allocate_number(driver: BlockDriver) -> Option<DevNum> {
    // SAFETY: driver-number allocation is process-context publication work.
    let mut ds = unsafe { DRIVERS.lock() };
    if let Some(d) = ds.iter_mut().find(|d| d.driver.name == driver.name) {
        if d.driver.major != driver.major { return None; }
        let minor = d.next_minor;
        d.next_minor = d.next_minor.checked_add(1)?;
        return Some(DevNum { major: d.major, minor });
    }
    let major = match driver.major {
        MajorRequest::Fixed(major) => {
            if ds.iter().any(|d| d.major == major) { return None; }
            major
        }
        MajorRequest::Dynamic => (DYNAMIC_MAJOR_FIRST..=DYNAMIC_MAJOR_LAST)
            .rev().find(|major| !ds.iter().any(|d| d.major == *major))?,
    };
    ds.push(DriverState { driver, major, next_minor: 1 });
    Some(DevNum { major, minor: 0 })
}

pub(crate) fn release_number(driver: BlockDriver, number: DevNum) {
    // SAFETY: driver-number release is process-context lifecycle work.
    let mut ds = unsafe { DRIVERS.lock() };
    if let Some(pos) = ds.iter().position(|d| d.driver == driver && d.major == number.major && d.next_minor == number.minor.saturating_add(1)) {
        ds[pos].next_minor = number.minor;
        if number.minor == 0 { ds.remove(pos); }
    }
}

/// Unpublish a disk and its owned device number. # C: O(N_disks + N_devices)
pub fn unregister(name: &str) -> bool {
    try_quiesce(name).is_some_and(DiskQuiesce::unregister)
}

/// Look up a registered disk by name. # C: O(N_disks)
pub fn by_name(name: &str) -> Option<Arc<Disk>> {
    // SAFETY: lookup holds the registry only long enough to clone its stable Arc.
    unsafe { TABLE.lock() }.iter().find(|d| d.name == name).cloned()
}
/// Acquire one canonical consumer reference. A claimed disk cannot disappear
/// or be reset by its control ABI until the consumer calls [`release`]. # C: O(N_disks)
pub fn claim(name: &str) -> bool {
    let Some(disk) = by_name(name) else { return false; };
    // SAFETY: holder lifecycle admission is process context and may wait behind
    // an open/remove operation; no registry lock is held while it does.
    let mut life = unsafe { disk.life.lock() };
    if life.quiesced || life.detached { return false; }
    let Some(next) = life.holders.checked_add(1) else { return false; };
    life.holders = next;
    true
}
/// Release one canonical consumer reference. # C: O(N_disks)
pub fn release(name: &str) -> bool {
    let Some(disk) = by_name(name) else { return false; };
    // SAFETY: holder lifecycle release is process context.
    let mut life = unsafe { disk.life.lock() };
    if life.holders == 0 { return false; }
    life.holders -= 1;
    true
}

/// Open one registered block device by its packed `dev_t`. The per-disk
/// lifecycle mutex serializes this increment against `unregister`, while the
/// table lock is held only long enough to acquire the disk's stable `Arc`.
/// # C: O(N_disks)
pub fn open_by_dev(dev_t: u32) -> bool {
    let Some(disk) = by_dev(dev_t) else { return false; };
    // SAFETY: VFS open is process context; a contended disk lifecycle must
    // sleep, never spin with the device registry or interrupts held.
    let mut life = unsafe { disk.life.lock() };
    if life.quiesced || life.detached { return false; }
    let Some(next) = life.openers.checked_add(1) else { return false; };
    life.openers = next;
    true
}

/// Release the opener acquired by [`open_by_dev`]. # C: O(N_disks)
pub fn close_by_dev(dev_t: u32) -> bool {
    let Some(disk) = by_dev(dev_t) else { return false; };
    // SAFETY: VFS close is process context; it may wait for a concurrent open.
    let mut life = unsafe { disk.life.lock() };
    if life.openers == 0 { return false; }
    life.openers -= 1;
    true
}
/// Acquire the exclusive gate only if the disk has no holders, open file
/// descriptions, or admitted I/O. New admissions observe this gate under the
/// same lock, including queued requests retained until completion.
/// # C: O(N_disks)
pub fn try_quiesce(name: &str) -> Option<DiskQuiesce> {
    // Write the device's page cache back BEFORE the admission gate closes —
    // Linux syncs a block device while it is still operable, because once the
    // gate is shut every request is refused and the dirty pages would have
    // nowhere to go. No registry lock is held across the I/O.
    if let Some(disk) = by_name(name) { let _ = disk.mapping.write_and_wait(); }
    let disk = by_name(name)?;
    // SAFETY: quiesce is process-context lifecycle serialization; a stable Arc
    // was acquired before this potentially blocking lock.
    let mut life = unsafe { disk.life.lock() };
    if life.quiesced || life.detached || life.holders != 0 || life.openers != 0 { return None; }
    life.quiesced = true;
    drop(life);
    let mut io = disk.io.lock_bh::<crate::bh_gate::BlockBh>();
    if io.in_flight != 0 {
        drop(io);
        // SAFETY: no new open/holder can pass while `quiesced` is true; only
        // this failed quiesce attempt may clear it.
        unsafe { disk.life.lock() }.quiesced = false;
        return None;
    }
    io.closed = true;
    drop(io);
    Some(DiskQuiesce { disk, active: true })
}

/// True when any holder or VFS opener keeps the disk busy. # C: O(N_disks)
pub fn is_claimed(name: &str) -> bool {
    by_name(name).is_some_and(|disk| {
        // SAFETY: status reads run in process context and must not spin behind
        // an in-progress disk lifecycle transaction.
        let life = unsafe { disk.life.lock() };
        life.holders != 0 || life.openers != 0
    })
}
/// Number of in-kernel block holders currently admitted. # C: O(N_disks)
pub fn holder_count(name: &str) -> Option<u32> {
    by_name(name).map(|disk| {
        // SAFETY: process-context lifecycle status query.
        unsafe { disk.life.lock() }.holders
    })
}
/// Number of VFS open file descriptions currently admitted. # C: O(N_disks)
pub fn opener_count(name: &str) -> Option<u32> {
    by_name(name).map(|disk| {
        // SAFETY: process-context lifecycle status query.
        unsafe { disk.life.lock() }.openers
    })
}
/// Return canonical limits, including the Linux-writable discard user cap. # C: O(N_disks)
pub fn queue_limits(name: &str) -> KResult<QueueLimits> { by_name(name).ok_or(BlockError::Enxio)?.dev.queue_limits() }

/// Set Linux `discard_max_bytes` as a registry-owned effective user cap. # C: O(N_disks)
pub fn set_discard_max_bytes(name: &str, bytes: u64) -> KResult<()> {
    let disk = by_name(name).ok_or(BlockError::Enxio)?;
    let limits = disk.dev.queue_limits()?;
    let granularity = u64::from(limits.discard_granularity());
    if granularity == 0 || bytes % granularity != 0
        || bytes / u64::from(crate::LINUX_SECTOR_BYTES) > u64::from(limits.max_hw_discard_sectors()) { return Err(BlockError::Einval); }
    let sectors = u32::try_from(bytes / u64::from(crate::LINUX_SECTOR_BYTES)).map_err(|_| BlockError::Einval)?;
    disk.io.lock_bh::<crate::bh_gate::BlockBh>().max_discard_sectors = sectors;
    Ok(())
}
/// Look up a registered disk by publication index. # C: O(N_disks)
pub fn by_index(index: u32) -> Option<Arc<Disk>> {
    // SAFETY: lookup holds the registry only long enough to clone its stable Arc.
    unsafe { TABLE.lock() }.iter().find(|d| d.index == index).cloned()
}
/// Look up a registered disk by serial. # C: O(N_disks)
pub fn disk_by_serial(serial: &str) -> Option<Arc<Disk>> {
    // SAFETY: lookup holds the registry only long enough to clone its stable Arc.
    unsafe { TABLE.lock() }.iter().find(|d| d.serial.as_deref() == Some(serial)).cloned()
}
/// Look up a registered block backend by serial. # C: O(N_disks)
pub fn by_serial(serial: &str) -> Option<Arc<dyn BlockDevice>> {
    disk_by_serial(serial).map(|d| d.dev.clone())
}
/// Resolve the packed Linux `dev_t` to its disk. # C: O(N_disks)
pub fn by_dev(dev_t: u32) -> Option<Arc<Disk>> {
    let (major, minor) = decode_dev(dev_t);
    // SAFETY: lookup holds the registry only long enough to clone its stable Arc.
    unsafe { TABLE.lock() }.iter().find(|d| d.number == DevNum { major, minor }).cloned()
}

fn decode_dev(dev_t: u32) -> (u32, u32) {
    ((dev_t & 0x000f_ff00) >> 8, (dev_t & 0xff) | ((dev_t >> 12) & 0x000f_ff00))
}
/// Encode a major/minor pair only when it round-trips through the canonical
/// packed device representation. # C: O(1)
pub(crate) fn decode_root_dev(major: u32, minor: u32) -> Option<u32> {
    let dev_t = encode_dev(major, minor);
    (decode_dev(dev_t) == (major, minor)).then_some(dev_t)
}
/// First published disk, boot fallback only. # C: O(1)
pub fn first_device() -> Option<Arc<dyn BlockDevice>> {
    // SAFETY: lookup holds the registry only long enough to clone the handle.
    unsafe { TABLE.lock() }.first().map(|d| d.dev.clone())
}
/// Snapshot live disks. # C: O(N_disks)
pub fn snapshot() -> Vec<Arc<Disk>> {
    // SAFETY: snapshot is process-context inspection over the publication table.
    unsafe { TABLE.lock() }.clone()
}
/// Capacity in Linux 512-byte sectors. # C: O(1)
pub fn size_512_sectors(capacity_blocks: u64, block_size: u32) -> u64 { capacity_blocks.saturating_mul((block_size as u64) / 512) }
/// Pack Linux `new_encode_dev`. # C: O(1)
pub fn encode_dev(major: u32, minor: u32) -> u32 { (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12) }
/// Packed device ID of a published disk. # C: O(1)
pub fn dev_t_of(name: &str, index: u32) -> Option<u32> {
    by_name(name).filter(|d| d.index == index).map(|d| encode_dev(d.number.major, d.number.minor))
}
