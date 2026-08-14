// Canonical disk-owned zone write-plug state used while a driver reports a zone.
use crate::linux_block::types::*;
use alloc::vec::Vec;
#[cfg(test)] use alloc::boxed::Box;
#[cfg(test)] use core::ffi::c_void;
use sync::{Modules as ModulesLockClass, Spinlock};

struct ZoneWplug { start: u64, flags: u32, wp_offset: u32, cond: u8 }
struct ZoneWplugHash { entries: Spinlock<Vec<ZoneWplug>, ModulesLockClass> }

fn wp_offset(zone: &LinuxBlkZone) -> u32 {
    match zone.cond {
        BLK_ZONE_COND_IMP_OPEN | BLK_ZONE_COND_EXP_OPEN | BLK_ZONE_COND_CLOSED | BLK_ZONE_COND_ACTIVE => zone.wp.wrapping_sub(zone.start) as u32,
        BLK_ZONE_COND_EMPTY => 0,
        _ => u32::MAX,
    }
}

/// Synchronise a pending write-plug after the device supplied a fresh zone report.
/// # C: O(number of plugs on disk)
pub(crate) unsafe fn sync_reported_zone(disk: *mut LinuxGendisk, zone: *mut LinuxBlkZone) {
    if disk.is_null() || zone.is_null() { return; }
    // SAFETY: disk and zone are live for disk_report_zone; a non-null hash is installed only by this owner.
    unsafe {
        let hash = (*disk).zoned.zone_wplugs_hash as *mut ZoneWplugHash;
        if hash.is_null() { return; }
        let mut plugs = (*hash).entries.lock();
        let start = (*zone).start;
        let off = wp_offset(&*zone);
        let cap = if (*disk).zoned.nr_zones != 0 && (*disk).zoned.last_zone_capacity != 0
            && start / (*disk).zoned.zone_capacity.max(1) as u64 == ((*disk).zoned.nr_zones - 1) as u64 {
            (*disk).zoned.last_zone_capacity
        } else { (*disk).zoned.zone_capacity };
        if let Some(plug) = plugs.iter_mut().find(|p| p.start == start) {
            if plug.flags & BLK_ZONE_WPLUG_NEED_WP_UPDATE != 0 {
                plug.flags &= !BLK_ZONE_WPLUG_NEED_WP_UPDATE; plug.wp_offset = off;
                plug.cond = if off == 0 { BLK_ZONE_COND_EMPTY } else if off >= cap { BLK_ZONE_COND_FULL } else { BLK_ZONE_COND_ACTIVE };
            }
        }
    }
}

#[cfg(test)]
/// Install one pending plug for a disk-owned report synchronization test.
/// # C: O(1)
pub(crate) unsafe fn install_test_wplug(disk: *mut LinuxGendisk, start: u64) {
    // SAFETY: tests own their fresh gendisk and install this canonical state once before reporting.
    let hash = Box::new(ZoneWplugHash { entries: Spinlock::new(alloc::vec![ZoneWplug {
        start, flags: BLK_ZONE_WPLUG_NEED_WP_UPDATE, wp_offset: 0, cond: BLK_ZONE_COND_EMPTY,
    }]) });
    // SAFETY: hash is newly allocated and becomes exclusively owned by this disk's zoned ABI slot.
    unsafe { (*disk).zoned.zone_wplugs_hash = Box::into_raw(hash) as *mut c_void; }
}

#[cfg(test)]
/// Snapshot the sole plug installed by the focused synchronization test.
/// # C: O(1)
pub(crate) unsafe fn test_wplug(disk: *mut LinuxGendisk) -> (u32, u8, u32) {
    // SAFETY: test installed this hash and holds the gendisk allocation live.
    unsafe { let h = (*disk).zoned.zone_wplugs_hash as *mut ZoneWplugHash; let p = &(*h).entries.lock()[0]; (p.wp_offset, p.cond, p.flags) }
}

#[cfg(test)]
/// Release the sole plug installed by the focused synchronization test.
/// # C: O(1)
pub(crate) unsafe fn drop_test_wplug(disk: *mut LinuxGendisk) {
    // SAFETY: tests call this once for a hash installed by install_test_wplug after all reports finish.
    unsafe { drop(Box::from_raw((*disk).zoned.zone_wplugs_hash as *mut ZoneWplugHash)); (*disk).zoned.zone_wplugs_hash = core::ptr::null_mut(); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reported_zone_updates_only_a_plug_marked_for_write_pointer_refresh() {
        let mut disk: LinuxGendisk = unsafe { core::mem::zeroed() };
        disk.zoned.nr_zones = 2; disk.zoned.zone_capacity = 100; disk.zoned.last_zone_capacity = 80;
        // SAFETY: this test owns the zeroed gendisk and its canonical test plug for the complete call.
        unsafe { install_test_wplug(&mut disk, 100); }
        let mut zone = LinuxBlkZone { start: 100, len: 80, wp: 147, zone_type: 0, cond: BLK_ZONE_COND_EXP_OPEN,
            non_seq: 0, reset: 0, resv: [0; 4], capacity: 80, reserved: [0; 24] };
        // SAFETY: disk, its plug hash, and zone remain live for this direct synchronization call.
        unsafe { sync_reported_zone(&mut disk, &mut zone); }
        // SAFETY: the test installed exactly one plug above and has not released it yet.
        assert_eq!(unsafe { test_wplug(&mut disk) }, (47, BLK_ZONE_COND_ACTIVE, 0));
        // SAFETY: the hash allocation was installed by this test and is no longer reachable after this drop.
        unsafe { drop_test_wplug(&mut disk); }
    }
}
