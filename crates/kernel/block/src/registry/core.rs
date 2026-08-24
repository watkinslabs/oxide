//! Block registration and the canonical Linux `dev_t` ownership table.

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use sync::{Spinlock, Devices as DevicesClass};
use sched::live::Mutex as LifecycleMutex;

use crate::blockdev::BlockDevice;
use crate::queue_limits::QueueLimits;
use crate::types::{BlockError, KResult};
use super::gate::{AdmissionDev, DiskIo, DiskLifecycle, DiskQuiesce};

use super::partition::Partition;

/// Linux assigns dynamic block majors from this reserved range first.
pub const DYNAMIC_MAJOR_FIRST: u32 = 240;
/// Inclusive end of Linux's preferred dynamic block-major range.
pub const DYNAMIC_MAJOR_LAST: u32 = 254;
/// Whole disks reserve the Linux-compatible first partition-minor range.
pub const PARTITION_MINOR_COUNT: u32 = 16;

/// A driver's request for a block major. Fixed majors are Linux UAPI values
/// owned by the respective driver; dynamic majors are allocated once per
/// driver name by this registry (Linux `register_blkdev(0, name)`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MajorRequest { Fixed(u32), Dynamic }

/// Identity of one block driver, passed explicitly at publication time.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BlockDriver {
    pub name: &'static str,
    pub major: MajorRequest,
    /// Distance between whole-disk minors. Partitionable disks reserve one
    /// Linux partition-minor window; virtual devices that do not expose
    /// partition minors may allocate every minor.
    pub minor_stride: u32,
    /// Whether the published disks may be scanned for child partitions.
    pub partitions: bool,
}
impl BlockDriver {
    /// Make a driver with a Linux-assigned fixed major. # C: O(1)
    pub const fn fixed(name: &'static str, major: u32) -> Self {
        Self { name, major: MajorRequest::Fixed(major), minor_stride: PARTITION_MINOR_COUNT, partitions: true }
    }
    /// Make a driver which owns a dynamically allocated Linux block major. # C: O(1)
    pub const fn dynamic(name: &'static str) -> Self {
        Self { name, major: MajorRequest::Dynamic, minor_stride: PARTITION_MINOR_COUNT, partitions: true }
    }
    /// Make an unpartitioned virtual block driver. Its caller can reserve an
    /// individual minor, so an ABI-visible virtual-device number never shares
    /// a partition window with a different published device. # C: O(1)
    pub const fn unpartitioned_fixed(name: &'static str, major: u32) -> Self {
        Self { name, major: MajorRequest::Fixed(major), minor_stride: 1, partitions: false }
    }
}

/// Canonical device number allocated to one published disk.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DevNum { pub major: u32, pub minor: u32 }

/// One registered block device.
pub struct Disk {
    pub name: String,
    /// Devtmpfs-relative block-node path. It may differ from `name`: mapper
    /// devices are indexed as `dm-N` but published as `mapper/<name>`.
    pub node_name: LifecycleMutex<String>,
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
    pub(super) cache_disabled: Arc<AtomicBool>,
    pub(super) cache_capable: bool,
    partitions: LifecycleMutex<Vec<Arc<Partition>>>,
    pub(super) life: LifecycleMutex<DiskLifecycle>,
    pub(super) io: Arc<Spinlock<DiskIo, DevicesClass>>,
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

/// Exclusive partition-table lifecycle gate. Unlike removal it leaves I/O
/// admitted, because reading the table is itself disk I/O. # C: O(1)
pub(crate) struct PartitionRescan { disk: Arc<Disk>, active: bool }
impl PartitionRescan {
    /// Disk whose partition table is exclusively being replaced. # C: O(1)
    pub(crate) fn disk(&self) -> &Arc<Disk> { &self.disk }
}
impl Drop for PartitionRescan {
    fn drop(&mut self) {
        if !self.active { return; }
        // SAFETY: this token owns the partition lifecycle exclusion.
        unsafe { self.disk.life.lock() }.lifecycle_held = false;
        self.active = false;
    }
}

struct DriverState { driver: BlockDriver, major: u32, allocated_minors: Vec<u32> }
pub(super) static TABLE: LifecycleMutex<Vec<Arc<Disk>>> = LifecycleMutex::new(Vec::new());
static DRIVERS: LifecycleMutex<Vec<DriverState>> = LifecycleMutex::new(Vec::new());
static NEXT_DISK_INDEX: AtomicU32 = AtomicU32::new(0);
type DiskRemoveHook = fn(&str);
pub(super) static DISK_REMOVE_HOOK: LifecycleMutex<Option<DiskRemoveHook>> = LifecycleMutex::new(None);
pub type DiskCloseHook = fn(&str);
pub(super) static DISK_CLOSE_HOOK: LifecycleMutex<Option<DiskCloseHook>> = LifecycleMutex::new(None);

/// Default owner for in-kernel tests and legacy module adapters. It is dynamic
/// and therefore cannot collide with physical-driver majors.
pub const GENERIC_BLOCK_DRIVER: BlockDriver = BlockDriver::dynamic("oxide-block");

/// Install the disk remove hook used by sysfs to drop stale block dentries. # C: O(1)
pub fn set_remove_hook(f: DiskRemoveHook) {
    // SAFETY: registration runs in process context; this is lifecycle policy.
    *unsafe { DISK_REMOVE_HOOK.lock() } = Some(f);
}

/// Install the owner hook notified when a disk reaches its final opener close.
/// # C: O(1)
pub fn set_close_hook(f: DiskCloseHook) {
    // SAFETY: registration runs in process context; this is lifecycle policy.
    *unsafe { DISK_CLOSE_HOOK.lock() } = Some(f);
}

/// Register an explicitly-owned block device. # C: O(N_disks + N_drivers)
pub fn register_with_driver(driver: BlockDriver, name: &str, serial: Option<&str>, dev: Arc<dyn BlockDevice>) -> u32 {
    register_with_driver_at(driver, name, name, serial, None, dev)
}

/// Register one disk with an explicit devtmpfs path and, optionally, a
/// caller-owned minor. The block registry remains the sole owner of the
/// resulting `(major,minor)` and VFS block-node dispatch; this entry point is
/// for virtual drivers whose ABI names and devtmpfs names differ from their
/// internal disk identity. # C: O(N_disks + N_minors)
pub fn register_with_driver_at(driver: BlockDriver, name: &str, node_name: &str,
                               serial: Option<&str>, requested_minor: Option<u32>,
                               dev: Arc<dyn BlockDevice>) -> u32 {
    if let Some(disk) = by_name(name) { return disk.index; }
    let number = match allocate_number_at(driver, requested_minor) { Some(n) => n, None => return 0 };
    let base_limits = match dev.queue_limits() {
        Ok(limits) => limits,
        Err(_) => { release_number(driver, number); return 0; }
    };
    let max_discard_sectors = base_limits.max_discard_sectors();
    let cache_capable = base_limits.write_cache();
    let cache_disabled = Arc::new(AtomicBool::new(false));
    let io = Arc::new(Spinlock::new(DiskIo {
        in_flight: 0, closed: false, detached: false, max_discard_sectors,
        #[cfg(target_os = "oxide-kernel")]
        drain_wait: Arc::new(sched::live::WaitList::new()),
    }));
    let admitted: Arc<dyn BlockDevice> = Arc::new(AdmissionDev {
        inner: dev, io: Arc::clone(&io), cache_disabled: Arc::clone(&cache_disabled),
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
                name: name.to_string(), node_name: LifecycleMutex::new(node_name.to_string()), index, driver, number,
                serial: serial.filter(|s| !s.is_empty()).map(ToString::to_string), dev, mapping, stats,
                cache_disabled, cache_capable,
                partitions: LifecycleMutex::new(Vec::new()),
        life: LifecycleMutex::new(DiskLifecycle { holders: 0, openers: 0, closing: false, lifecycle_held: false, reset_frozen: false, detached: false }),
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
            .with_devnode("block", node_name.to_string(), Some((number.major, number.minor))))) {
        Ok(_) => {
            crate::devbridge::publish(number, bridge_disk);
            if driver.partitions { super::partition::scan_after_registration(name); }
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

#[cfg(test)]
pub(crate) fn allocate_number(driver: BlockDriver) -> Option<DevNum> {
    allocate_number_at(driver, None)
}

/// Reserve either the lowest free driver-compatible minor or an exact minor.
/// The allocation set is explicit rather than a rollback-only cursor: removal
/// of `loop0` or a mapper device must make THAT minor available again without
/// ever aliasing another live disk. # C: O(N_drivers + N_minors)
pub(crate) fn allocate_number_at(driver: BlockDriver, requested_minor: Option<u32>) -> Option<DevNum> {
    if driver.minor_stride == 0 { return None; }
    // SAFETY: driver-number allocation is process-context publication work.
    let mut ds = unsafe { DRIVERS.lock() };
    let position = match ds.iter().position(|d| d.driver.name == driver.name) {
        Some(pos) if ds[pos].driver == driver => pos,
        Some(_) => return None,
        None => {
            let major = match driver.major {
                MajorRequest::Fixed(major) => {
                    if ds.iter().any(|d| d.major == major) { return None; }
                    major
                }
                MajorRequest::Dynamic => (DYNAMIC_MAJOR_FIRST..=DYNAMIC_MAJOR_LAST)
                    .rev().find(|major| !ds.iter().any(|d| d.major == *major))?,
            };
            ds.push(DriverState { driver, major, allocated_minors: Vec::new() });
            ds.len() - 1
        }
    };
    let state = &mut ds[position];
    let minor = match requested_minor {
        Some(minor) if minor < (1 << vfs::MINORBITS) && minor % driver.minor_stride == 0
            && !state.allocated_minors.iter().any(|used| *used == minor) => minor,
        Some(_) => return None,
        None => (0..(1 << vfs::MINORBITS))
            .step_by(driver.minor_stride as usize)
            .find(|minor| !state.allocated_minors.iter().any(|used| *used == *minor))?,
    };
    state.allocated_minors.push(minor);
    Some(DevNum { major: state.major, minor })
}

pub(crate) fn release_number(driver: BlockDriver, number: DevNum) {
    // SAFETY: driver-number release is process-context lifecycle work.
    let mut ds = unsafe { DRIVERS.lock() };
    if let Some(pos) = ds.iter().position(|d| d.driver == driver && d.major == number.major) {
        let state = &mut ds[pos];
        if let Some(minor) = state.allocated_minors.iter().position(|minor| *minor == number.minor) {
            state.allocated_minors.remove(minor);
        }
        if state.allocated_minors.is_empty() { ds.remove(pos); }
    }
}

/// Move one published disk's devtmpfs node without changing its block identity
/// or VFS dispatch. The new node is published only after the old model node
/// is removed, and an add failure restores the old path. # C: O(N_devices)
pub fn republish_node(name: &str, node_name: &str) -> bool {
    let Some(disk) = by_name(name) else { return false; };
    // SAFETY: node republishing is process-context device lifecycle work.
    let old_node = unsafe { disk.node_name.lock() }.clone();
    if old_node == node_name { return true; }
    let Some(model) = drv::devices().into_iter().find(|d| d.bus == "block" && d.addr == name) else { return false; };
    let number = disk.number;
    drv::device_del(&model);
    let publish = |path: &str| drv::try_device_add(Arc::new(
        drv::Device::new("block", name.to_string(), 0, 0, 0)
            .with_devnode("block", path.to_string(), Some((number.major, number.minor)))));
    if publish(node_name).is_ok() {
        // SAFETY: node republishing is process-context device lifecycle work.
        *unsafe { disk.node_name.lock() } = node_name.to_string();
        return true;
    }
    let _ = publish(&old_node);
    false
}

/// Unpublish a disk and its owned device number. # C: O(N_disks + N_devices)
pub fn unregister(name: &str) -> bool {
    super::gate::try_quiesce(name).is_some_and(DiskQuiesce::unregister)
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
    if life.lifecycle_held || life.detached { return false; }
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

pub(super) fn disk_for_dev(dev_t: u32) -> Option<Arc<Disk>> {
    if let Some(disk) = by_dev(dev_t) { return Some(disk); }
    let (major, minor) = decode_dev(dev_t);
    snapshot().into_iter().find(|disk| disk.partitions().into_iter()
        .any(|part| part.number_dev == DevNum { major, minor }))
}

/// Close partition-table publication against new partition file opens while
/// allowing the table-read I/O needed to discover its replacement. # C: O(N)
pub(crate) fn try_partition_rescan(name: &str) -> Option<PartitionRescan> {
    let disk = by_name(name)?;
    // SAFETY: partition rescans serialize with open and removal lifecycle work.
    let mut life = unsafe { disk.life.lock() };
    if life.lifecycle_held || life.reset_frozen || life.detached || life.closing || life.holders != 0 || life.openers != 0 { return None; }
    life.lifecycle_held = true;
    drop(life);
    Some(PartitionRescan { disk, active: true })
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

/// Whether this disk currently advertises a volatile write cache. # C: O(1)
pub fn write_cache(name: &str) -> KResult<bool> {
    let disk = by_name(name).ok_or(BlockError::Enxio)?;
    Ok(disk.cache_capable && !disk.cache_disabled.load(Ordering::Acquire))
}

/// Apply Linux's queue `write_cache` control to the canonical disk owner. # C: O(1)
pub fn set_write_cache(name: &str, write_back: bool) -> KResult<()> {
    let disk = by_name(name).ok_or(BlockError::Enxio)?;
    if write_back && !disk.cache_capable { return Err(BlockError::Eopnotsupp); }
    disk.cache_disabled.store(!write_back, Ordering::Release);
    Ok(())
}

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

pub(crate) fn decode_dev(dev_t: u32) -> (u32, u32) {
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
