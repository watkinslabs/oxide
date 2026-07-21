//! Block registration and the canonical Linux `dev_t` ownership table.

extern crate alloc;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Spinlock, Devices as DevicesClass};

use crate::blockdev::{BlockCompletion, BlockDevice, BlockRequest};
use crate::queue_limits::QueueLimits;
use crate::types::{BlockError, KResult};

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
    pub stats: Arc<crate::stats::DiskStats>,
    state: Arc<Spinlock<DiskState, DevicesClass>>,
}

/// The generic block-device lifetime state. Holders are kernel consumers such
/// as swap or a zram backing disk; openers are VFS open file descriptions.
/// They are deliberately separate: Linux's `bd_holders` and `bd_openers`
/// answer different lifecycle questions and must never share a counter.
struct DiskState { holders: u32, openers: u32, in_flight: u32, quiesced: bool, max_discard_sectors: u32 }

/// One request admitted by the canonical registry-owned queue gate.  The
/// token remains live through an asynchronous completion, so quiesce cannot
/// race a driver request that was accepted before reset/remove began.
struct SubmissionToken { state: Arc<Spinlock<DiskState, DevicesClass>> }

impl Drop for SubmissionToken {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        hal::kassert!(state.in_flight != 0, "block submission underflow");
        state.in_flight -= 1;
    }
}

/// Registry-owned submission decorator.  `Disk::dev` exposes this wrapper,
/// not the raw driver, making it the one admission authority for synchronous
/// and queued block I/O issued through a registered disk.
struct AdmissionDev {
    inner: Arc<dyn BlockDevice>,
    state: Arc<Spinlock<DiskState, DevicesClass>>,
}

impl AdmissionDev {
    fn admit(&self) -> KResult<SubmissionToken> {
        let mut state = self.state.lock();
        if state.quiesced { return Err(BlockError::Ebusy); }
        let Some(next) = state.in_flight.checked_add(1) else { return Err(BlockError::Ebusy); };
        state.in_flight = next;
        Ok(SubmissionToken { state: Arc::clone(&self.state) })
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
        limits.with_discard(limits.max_hw_discard_sectors(), self.state.lock().max_discard_sectors,
            limits.discard_granularity())
    }
    fn supports_discard(&self) -> bool { self.inner.supports_discard() }
    fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }
    fn submit(&self, request: BlockRequest, completion: BlockCompletion) {
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
            let mut table = TABLE.lock();
            let Some(pos) = table.iter().position(|d| Arc::ptr_eq(d, &disk)) else { return false; };
            table.remove(pos);
            true
        };
        if !removed { return false; }
        crate::devbridge::unpublish(disk.number);
        release_number(disk.driver, disk.number);
        if let Some(dev) = drv::devices().into_iter().find(|d| d.bus == "block" && d.addr == name) { drv::device_del(&dev); }
        if let Some(f) = *DISK_REMOVE_HOOK.lock() { f(&name); }
        // The disk is detached, so reopening its admission gate is meaningless.
        self.active = false;
        true
    }
}

impl Drop for DiskQuiesce {
    fn drop(&mut self) {
        if self.active { self.disk.state.lock().quiesced = false; }
    }
}

struct DriverState { driver: BlockDriver, major: u32, next_minor: u32 }
static TABLE: Spinlock<Vec<Arc<Disk>>, DevicesClass> = Spinlock::new(Vec::new());
static DRIVERS: Spinlock<Vec<DriverState>, DevicesClass> = Spinlock::new(Vec::new());
type DiskRemoveHook = fn(&str);
static DISK_REMOVE_HOOK: Spinlock<Option<DiskRemoveHook>, DevicesClass> = Spinlock::new(None);

/// Default owner for in-kernel tests and legacy module adapters. It is dynamic
/// and therefore cannot collide with physical-driver majors.
pub const GENERIC_BLOCK_DRIVER: BlockDriver = BlockDriver::dynamic("oxide-block");

/// Install the disk remove hook used by sysfs to drop stale block dentries. # C: O(1)
pub fn set_remove_hook(f: DiskRemoveHook) { *DISK_REMOVE_HOOK.lock() = Some(f); }

/// Register an explicitly-owned block device. # C: O(N_disks + N_drivers)
pub fn register_with_driver(driver: BlockDriver, name: &str, serial: Option<&str>, dev: Arc<dyn BlockDevice>) -> u32 {
    let (index, number, bridge_disk) = {
        let mut t = TABLE.lock();
        if let Some(d) = t.iter().find(|d| d.name == name) { return d.index; }
        let number = match allocate_number(driver) { Some(n) => n, None => return 0 };
        let index = (t.len() as u32).saturating_add(1);
        if index == 0 { return 0; }
        let max_discard_sectors = match dev.queue_limits() { Ok(limits) => limits.max_discard_sectors(), Err(_) => return 0 };
        let state = Arc::new(Spinlock::new(DiskState {
            holders: 0, openers: 0, in_flight: 0, quiesced: false, max_discard_sectors,
        }));
        let admitted: Arc<dyn BlockDevice> = Arc::new(AdmissionDev {
            inner: dev, state: Arc::clone(&state),
        });
        let (dev, stats) = crate::stats::StatsDev::wrap(admitted);
        let disk = Arc::new(Disk {
            name: name.to_string(), index, driver, number,
            serial: serial.filter(|s| !s.is_empty()).map(ToString::to_string), dev, stats,
            state,
        });
        t.push(disk.clone());
        (index, number, disk)
    };
    match drv::try_device_add(Arc::new(
        drv::Device::new("block", name.to_string(), 0, 0, 0)
            .with_devnode("block", name.to_string(), Some((number.major, number.minor))))) {
        Ok(_) => { crate::devbridge::publish(number, bridge_disk); index }
        Err(_) => {
            let mut t = TABLE.lock();
            if let Some(pos) = t.iter().position(|d| d.name == name && d.index == index) { t.remove(pos); }
            release_number(driver, number);
            0
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
    let mut ds = DRIVERS.lock();
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
    let mut ds = DRIVERS.lock();
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
pub fn by_name(name: &str) -> Option<Arc<Disk>> { TABLE.lock().iter().find(|d| d.name == name).cloned() }
/// Acquire one canonical consumer reference. A claimed disk cannot disappear
/// or be reset by its control ABI until the consumer calls [`release`]. # C: O(N_disks)
pub fn claim(name: &str) -> bool {
    let table = TABLE.lock();
    let Some(disk) = table.iter().find(|disk| disk.name == name) else { return false; };
    let mut state = disk.state.lock();
    if state.quiesced { return false; }
    let Some(next) = state.holders.checked_add(1) else { return false; };
    state.holders = next;
    true
}
/// Release one canonical consumer reference. # C: O(N_disks)
pub fn release(name: &str) -> bool {
    let table = TABLE.lock();
    let Some(disk) = table.iter().find(|disk| disk.name == name) else { return false; };
    let mut state = disk.state.lock();
    if state.holders == 0 { return false; }
    state.holders -= 1;
    true
}

/// Open one registered block device by its packed `dev_t`. The table lock
/// serializes this increment against `unregister`, so a VFS open cannot race
/// a zram reset/remove into a detached but still-operable block device.
/// # C: O(N_disks)
pub fn open_by_dev(dev_t: u32) -> bool {
    let (major, minor) = decode_dev(dev_t);
    let table = TABLE.lock();
    let Some(disk) = table.iter().find(|disk| disk.number == DevNum { major, minor }) else { return false; };
    let mut state = disk.state.lock();
    if state.quiesced { return false; }
    let Some(next) = state.openers.checked_add(1) else { return false; };
    state.openers = next;
    true
}

/// Release the opener acquired by [`open_by_dev`]. # C: O(N_disks)
pub fn close_by_dev(dev_t: u32) -> bool {
    let (major, minor) = decode_dev(dev_t);
    let table = TABLE.lock();
    let Some(disk) = table.iter().find(|disk| disk.number == DevNum { major, minor }) else { return false; };
    let mut state = disk.state.lock();
    if state.openers == 0 { return false; }
    state.openers -= 1;
    true
}
/// Acquire the exclusive gate only if the disk has no holders, open file
/// descriptions, or admitted I/O. New admissions observe this gate under the
/// same lock, including queued requests retained until completion.
/// # C: O(N_disks)
pub fn try_quiesce(name: &str) -> Option<DiskQuiesce> {
    let table = TABLE.lock();
    let disk = table.iter().find(|disk| disk.name == name)?.clone();
    let mut state = disk.state.lock();
    if state.quiesced || state.holders != 0 || state.openers != 0 || state.in_flight != 0 { return None; }
    state.quiesced = true;
    drop(state);
    Some(DiskQuiesce { disk, active: true })
}

/// True when any holder or VFS opener keeps the disk busy. # C: O(N_disks)
pub fn is_claimed(name: &str) -> bool {
    by_name(name).is_some_and(|disk| {
        let state = disk.state.lock();
        state.holders != 0 || state.openers != 0
    })
}
/// Number of in-kernel block holders currently admitted. # C: O(N_disks)
pub fn holder_count(name: &str) -> Option<u32> {
    by_name(name).map(|disk| disk.state.lock().holders)
}
/// Number of VFS open file descriptions currently admitted. # C: O(N_disks)
pub fn opener_count(name: &str) -> Option<u32> {
    by_name(name).map(|disk| disk.state.lock().openers)
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
    disk.state.lock().max_discard_sectors = sectors;
    Ok(())
}
/// Look up a registered disk by publication index. # C: O(N_disks)
pub fn by_index(index: u32) -> Option<Arc<Disk>> { TABLE.lock().iter().find(|d| d.index == index).cloned() }
/// Look up a registered disk by serial. # C: O(N_disks)
pub fn by_serial(serial: &str) -> Option<Arc<dyn BlockDevice>> {
    TABLE.lock().iter().find(|d| d.serial.as_deref() == Some(serial)).map(|d| d.dev.clone())
}
/// Resolve the packed Linux `dev_t` to its disk. # C: O(N_disks)
pub fn by_dev(dev_t: u32) -> Option<Arc<Disk>> {
    let (major, minor) = decode_dev(dev_t);
    TABLE.lock().iter().find(|d| d.number == DevNum { major, minor }).cloned()
}

fn decode_dev(dev_t: u32) -> (u32, u32) {
    ((dev_t & 0x000f_ff00) >> 8, (dev_t & 0xff) | ((dev_t >> 12) & 0x000f_ff00))
}
/// First published disk, boot fallback only. # C: O(1)
pub fn first_device() -> Option<Arc<dyn BlockDevice>> { TABLE.lock().first().map(|d| d.dev.clone()) }
/// Snapshot live disks. # C: O(N_disks)
pub fn snapshot() -> Vec<Arc<Disk>> { TABLE.lock().clone() }
/// Capacity in Linux 512-byte sectors. # C: O(1)
pub fn size_512_sectors(capacity_blocks: u64, block_size: u32) -> u64 { capacity_blocks.saturating_mul((block_size as u64) / 512) }
/// Pack Linux `new_encode_dev`. # C: O(1)
pub fn encode_dev(major: u32, minor: u32) -> u32 { (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12) }
/// Packed device ID of a published disk. # C: O(1)
pub fn dev_t_of(name: &str, index: u32) -> Option<u32> {
    by_name(name).filter(|d| d.index == index).map(|d| encode_dev(d.number.major, d.number.minor))
}
