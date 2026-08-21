//! RAII block-holder claims over canonical disks and their partitions.

use alloc::sync::Arc;

use crate::BlockDevice;
use super::{Disk, by_name, snapshot};
use super::root::resolve_root_owner;

/// One admitted block target whose parent disk cannot disappear or rescan.
pub struct DeviceClaim {
    disk: Arc<Disk>,
    dev: Arc<dyn BlockDevice>,
}

impl DeviceClaim {
    /// Canonical target backend retained by this holder. # C: O(1)
    pub fn device(&self) -> Arc<dyn BlockDevice> { self.dev.clone() }

    /// Parent disk identity which owns lifecycle exclusion. # C: O(1)
    pub fn disk(&self) -> &Arc<Disk> { &self.disk }
}

impl Drop for DeviceClaim {
    fn drop(&mut self) {
        // SAFETY: this token incremented the holder count exactly once and the
        // retained disk Arc prevents its lifecycle state from disappearing.
        let mut life = unsafe { self.disk.life.lock() };
        debug_assert!(life.holders != 0);
        life.holders = life.holders.saturating_sub(1);
    }
}

/// Resolve and atomically claim a whole disk or disk-owned partition by name.
/// # C: O(disks + partitions)
pub fn claim_target(name: &str) -> Option<DeviceClaim> {
    let (disk, dev) = match by_name(name) {
        Some(disk) => (disk.clone(), disk.dev.clone()),
        None => snapshot().into_iter().find_map(|disk| {
            disk.partitions().into_iter().find(|part| part.name == name)
                .map(|part| (disk, part.dev.clone()))
        })?,
    };
    // SAFETY: holder admission is process-context lifecycle work. A partition
    // rescan holds the same lifecycle exclusion before replacing child views.
    let mut life = unsafe { disk.life.lock() };
    if life.lifecycle_held || life.detached { return None; }
    life.holders = life.holders.checked_add(1)?;
    drop(life);
    Some(DeviceClaim { disk, dev })
}

/// Resolve and atomically claim any canonical block-device spelling accepted
/// by the boot root-device parser. # C: O(disks + partitions)
pub fn claim_target_spec(value: &[u8]) -> Option<DeviceClaim> {
    let (disk, dev) = resolve_root_owner(value)?;
    // SAFETY: holder admission is process-context lifecycle work and uses the
    // same exclusion as name-based whole-disk and partition claims.
    let mut life = unsafe { disk.life.lock() };
    if life.lifecycle_held || life.detached { return None; }
    life.holders = life.holders.checked_add(1)?;
    drop(life);
    Some(DeviceClaim { disk, dev })
}
