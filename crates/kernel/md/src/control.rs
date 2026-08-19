//! MD ioctl state and lifecycle control derived from each published array.

extern crate alloc;

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use sync::{Spinlock, StackedBlock as MdControlClass};

use crate::{Array, MD_DRIVER, uapi};
use crate::lifecycle::StopStart;
use block::{BlockError, KResult};

pub(crate) struct Metadata {
    pub(crate) minor_version: i32,
    pub(crate) ctime: u64,
    pub(crate) utime: u64,
    pub(crate) level: i32,
    pub(crate) layout: u32,
    pub(crate) chunk_sectors: u32,
    pub(crate) raid_disks: u32,
    pub(crate) members: Vec<Member>,
}

pub(crate) struct Member { pub(crate) number: u32, pub(crate) number_dev: block::registry::DevNum, pub(crate) raid_disk: i32 }

struct Entry { minor: u32, array: Weak<Array> }
static ARRAYS: Spinlock<Vec<Entry>, MdControlClass> = Spinlock::new(Vec::new());

/// True only for a live canonical MD block publication. # C: O(disks)
pub fn is_md_device(dev_t: u32) -> bool { block::registry::by_dev(dev_t).is_some_and(|disk| disk.driver == MD_DRIVER) }

/// Query one live assembled MD array by its canonical packed device number.
/// The weak index contains no duplicate metadata; its array remains the sole
/// owner of the immutable values while the block registry proves liveness.
/// # C: O(disks + arrays)
pub fn array_info(dev_t: u32) -> Option<uapi::ArrayInfo> {
    let disk = block::registry::by_dev(dev_t)?;
    if disk.driver != MD_DRIVER { return None; }
    lookup(disk.number.minor)?.array_info(disk.number.minor)
}

/// Query one persistent member descriptor, or report the Linux `REMOVED`
/// descriptor when that member number is not part of a live array. # C: O(disks + members)
pub fn disk_info(dev_t: u32, number: i32) -> Option<uapi::DiskInfo> {
    let disk = block::registry::by_dev(dev_t)?;
    if disk.driver != MD_DRIVER { return None; }
    Some(lookup(disk.number.minor)?.disk_info(number))
}

/// Put a live assembled array into read-only service. New opens and writes
/// close before the block-device mapping drains its existing dirty pages;
/// later writes observe `EROFS` until [`restart_array_read_write`].
/// # C: O(dirty pages + in-flight writes) # Ctx: process # Sleeps: yes
pub fn stop_array_read_only(dev_t: u32) -> KResult<()> {
    let (_disk, array) = live_array(dev_t)?;
    // Retain the ioctl file's one opener while excluding every new opener.
    let seal = block::registry::seal_openers(dev_t, 1)?;
    let disk = seal.disk();
    // The mapping lock orders this boundary after every raw write that became
    // dirty before the seal and before every write attempted after it.
    disk.mapping.seal_writes();
    if let Err(error) = array.begin_read_only() {
        // Another lifecycle operation owns the sealing boundary, or this
        // array is already read-only and must remain sealed.
        return Err(error);
    }
    array.wait_for_writers();
    if let Err(error) = disk.mapping.write_and_wait() {
        array.cancel_read_only();
        disk.mapping.unseal_writes();
        return Err(error);
    }
    if let Err(error) = array.finish_read_only() {
        array.cancel_read_only();
        disk.mapping.unseal_writes();
        return Err(error);
    }
    Ok(())
}

/// Fully stop an MD array. The control description remains the sole opener
/// through cache writeback; then the canonical MD node is unpublished. Closing
/// that retained control description releases the final member claims.
/// # C: O(dirty pages + in-flight I/O + disks) # Ctx: process # Sleeps: yes
pub fn stop_array(dev_t: u32) -> KResult<()> {
    let (_disk, array) = live_array(dev_t)?;
    let removal = block::registry::begin_controlled_removal(dev_t, 1)?;
    let disk = Arc::clone(removal.disk());
    disk.mapping.seal_writes();
    let start = match array.begin_stop() {
        Ok(start) => start,
        Err(error) => { disk.mapping.unseal_writes(); return Err(error); }
    };
    if start == StopStart::Sealing { array.wait_for_writers(); }
    if let Err(error) = disk.mapping.write_and_wait() {
        if start == StopStart::Sealing { array.cancel_read_only(); }
        disk.mapping.unseal_writes();
        return Err(error);
    }
    if start == StopStart::Sealing { if let Err(error) = array.finish_read_only() {
        array.cancel_read_only();
        disk.mapping.unseal_writes();
        return Err(error);
    } }
    if !removal.unregister() {
        if start == StopStart::Sealing { array.cancel_read_only(); }
        disk.mapping.unseal_writes();
        return Err(BlockError::Ebusy);
    }
    Ok(())
}

/// Return a live read-only array to read-write service. # C: O(disks + arrays)
pub fn restart_array_read_write(dev_t: u32) -> KResult<()> {
    let (disk, array) = live_array(dev_t)?;
    array.restart_read_write()?;
    disk.mapping.unseal_writes();
    Ok(())
}

pub(crate) fn publish(minor: u32, array: &Arc<Array>) {
    let mut arrays = ARRAYS.lock();
    arrays.retain(|entry| entry.array.strong_count() != 0);
    if array.metadata.is_none() {
        arrays.retain(|entry| entry.minor != minor);
        return;
    }
    match arrays.iter_mut().find(|entry| entry.minor == minor) {
        Some(entry) => entry.array = Arc::downgrade(array),
        None => arrays.push(Entry { minor, array: Arc::downgrade(array) }),
    }
}

fn lookup(minor: u32) -> Option<Arc<Array>> {
    let mut arrays = ARRAYS.lock();
    let index = arrays.iter().position(|entry| entry.minor == minor)?;
    match arrays[index].array.upgrade() {
        Some(array) => Some(array),
        None => { arrays.remove(index); None }
    }
}

fn live_array(dev_t: u32) -> KResult<(Arc<block::registry::Disk>, Arc<Array>)> {
    let disk = block::registry::by_dev(dev_t).ok_or(BlockError::Enxio)?;
    if disk.driver != MD_DRIVER { return Err(BlockError::Enxio); }
    let array = lookup(disk.number.minor).ok_or(BlockError::Enxio)?;
    Ok((disk, array))
}

impl Array {
    fn array_info(&self, md_minor: u32) -> Option<uapi::ArrayInfo> {
        let metadata = self.metadata.as_ref()?;
        let size = self.capacity.checked_mul(u64::from(self.block_size))?.checked_div(1024)?;
        let size = i32::try_from(size).unwrap_or(-1);
        let disks = i32::try_from(metadata.members.len()).ok()?;
        Some(uapi::ArrayInfo {
            major_version: 1, minor_version: metadata.minor_version, patch_version: uapi::MD_PATCHLEVEL_VERSION,
            ctime: u32::try_from(metadata.ctime).unwrap_or(u32::MAX), level: metadata.level, size,
            nr_disks: disks, raid_disks: i32::try_from(metadata.raid_disks).ok()?, md_minor: i32::try_from(md_minor).ok()?, not_persistent: 0,
            utime: u32::try_from(metadata.utime).unwrap_or(u32::MAX), state: 1, active_disks: disks, working_disks: disks,
            failed_disks: 0, spare_disks: 0, layout: metadata.layout as i32,
            chunk_size: i32::try_from(u64::from(metadata.chunk_sectors).checked_mul(512)?).unwrap_or(-1),
        })
    }

    fn disk_info(&self, number: i32) -> uapi::DiskInfo {
        let Some(metadata) = &self.metadata else { return removed(number); };
        let Some(member) = u32::try_from(number).ok().and_then(|number| metadata.members.iter().find(|member| member.number == number)) else {
            return removed(number);
        };
        uapi::DiskInfo { number, major: member.number_dev.major as i32, minor: member.number_dev.minor as i32,
            raid_disk: member.raid_disk, state: (1 << 1) | (1 << 2) }
    }
}

fn removed(number: i32) -> uapi::DiskInfo { uapi::DiskInfo { number, major: 0, minor: 0, raid_disk: -1, state: 1 << 3 } }
