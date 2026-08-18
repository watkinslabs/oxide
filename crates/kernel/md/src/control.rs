//! Immutable MD ioctl state derived from each published assembled array.

extern crate alloc;

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use sync::{Spinlock, StackedBlock as MdControlClass};

use crate::{Array, MD_DRIVER, uapi};

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
