//! Block device registry per `docs/17`. Named lookup table so
//! drivers (virtio-blk, nvme, future loop devices) register their
//! `BlockDevice` impl at boot and ext4 / future filesystems can
//! find them by name (`"rootfs"`, `"sda"`, `"vdb"` etc.).

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Spinlock, Devices as DevicesClass};

use crate::blockdev::BlockDevice;

/// One registered block device. Holds the driver impl + a stable
/// name and a 1-based disk index used by /dev/disk/by-* and the
/// gendisk-equivalent in future PRs.
pub struct Disk {
    pub name: String,
    pub index: u32,
    pub dev: Arc<dyn BlockDevice>,
}

static TABLE: Spinlock<Vec<Arc<Disk>>, DevicesClass> = Spinlock::new(Vec::new());

/// Register a block device. Returns the assigned 1-based index.
/// Idempotent on `name`: returns the existing index if already
/// present (driver hot-replug not supported in v1).
/// # C: O(N_disks)
pub fn register(name: &str, dev: Arc<dyn BlockDevice>) -> u32 {
    let mut t = TABLE.lock();
    if let Some(d) = t.iter().find(|d| d.name == name) {
        return d.index;
    }
    let index = (t.len() as u32) + 1;
    t.push(Arc::new(Disk {
        name: name.to_string(),
        index,
        dev,
    }));
    index
}

/// Look up a registered disk by name.
/// # C: O(N_disks)
pub fn by_name(name: &str) -> Option<Arc<Disk>> {
    TABLE.lock().iter().find(|d| d.name == name).cloned()
}

/// Look up a registered disk by 1-based index.
/// # C: O(1)
pub fn by_index(index: u32) -> Option<Arc<Disk>> {
    let t = TABLE.lock();
    t.iter().find(|d| d.index == index).cloned()
}

/// Snapshot the disk table for /proc/partitions, /sys/block, etc.
/// # C: O(N_disks)
pub fn snapshot() -> Vec<Arc<Disk>> {
    TABLE.lock().clone()
}
