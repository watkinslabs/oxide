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
/// gendisk-equivalent in future PRs. `serial` is the device identity
/// label (`-device …,serial=oxide-root`) read by the driver via
/// GET_ID; used to bind a named volume (root/home) to its mount
/// regardless of probe-order name (vda/vdb/…). `None` for devices
/// with no serial (e.g. the test/loop disks).
pub struct Disk {
    pub name: String,
    pub index: u32,
    pub serial: Option<String>,
    pub dev: Arc<dyn BlockDevice>,
    /// Per-disk I/O counters (Linux `disk_stats`). Shared with the `StatsDev`
    /// wrapper that `dev` points at, so every I/O is counted; `/proc/diskstats`
    /// reads this.
    pub stats: alloc::sync::Arc<crate::stats::DiskStats>,
}

static TABLE: Spinlock<Vec<Arc<Disk>>, DevicesClass> = Spinlock::new(Vec::new());

/// Register a block device. Returns the assigned 1-based index.
/// Idempotent on `name`: returns the existing index if already
/// present (driver hot-replug not supported in v1).
/// # C: O(N_disks)
pub fn register(name: &str, dev: Arc<dyn BlockDevice>) -> u32 {
    register_with_serial(name, None, dev)
}

/// Register a block device with an identity `serial` (`Some("oxide-root")`
/// etc.). Empty/`None` serial = no by-serial binding. Same idempotency
/// on `name` as `register`.
/// # C: O(N_disks)
pub fn register_with_serial(name: &str, serial: Option<&str>, dev: Arc<dyn BlockDevice>) -> u32 {
    let mut t = TABLE.lock();
    if let Some(d) = t.iter().find(|d| d.name == name) {
        return d.index;
    }
    let index = (t.len() as u32) + 1;
    // Wrap the driver device in the stats-counting decorator so every I/O
    // through the registry is accounted at one central point (Linux blk-stat).
    let (dev, stats) = crate::stats::StatsDev::wrap(dev);
    t.push(Arc::new(Disk {
        name: name.to_string(),
        index,
        serial: serial.filter(|s| !s.is_empty()).map(|s| s.to_string()),
        dev,
        stats,
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

/// Find a registered device by its identity `serial` (e.g. `"oxide-root"`).
/// Used by the boot path to bind the named root/home volume to its mount
/// independent of probe-order naming (vda/vdb/…).
/// # C: O(N_disks)
pub fn by_serial(serial: &str) -> Option<Arc<dyn BlockDevice>> {
    TABLE
        .lock()
        .iter()
        .find(|d| d.serial.as_deref() == Some(serial))
        .map(|d| d.dev.clone())
}

/// Return the first registered block device in probe order. Boot uses this
/// only as a fallback when the root disk's virtio serial has not been stamped
/// yet; serial lookup remains the preferred binding.
/// # C: O(1)
pub fn first_device() -> Option<Arc<dyn BlockDevice>> {
    TABLE.lock().first().map(|d| d.dev.clone())
}

/// Snapshot the disk table for /proc/partitions, /sys/block, etc.
/// # C: O(N_disks)
pub fn snapshot() -> Vec<Arc<Disk>> {
    TABLE.lock().clone()
}

/// Capacity in 512-byte sectors — Linux `/sys/block/<dev>/size` units.
/// ALWAYS 512-byte units regardless of the logical block size, so a
/// 4096-byte-sector disk with N blocks reports `N * 8`.
/// # C: O(1)
pub fn size_512_sectors(capacity_blocks: u64, block_size: u32) -> u64 {
    capacity_blocks.saturating_mul((block_size as u64) / 512)
}

/// Synthetic (major, minor) for a disk by registration name + 1-based
/// index. Linux majors where they exist: virtio-blk 254, NVMe 259,
/// SCSI/AHCI disk 8. Minor = `index - 1`. Honest: oxide assigns these
/// statically by name prefix — no dynamic major allocator yet.
/// # C: O(1)
pub fn major_minor(name: &str, index: u32) -> (u32, u32) {
    let major = if name.starts_with("nvme") { 259 }
        else if name.starts_with("vd") { 254 }
        else if name.starts_with("sd") || name.starts_with("sata") { 8 }
        else { 254 };
    (major, index.saturating_sub(1))
}

#[cfg(test)]
mod sysfs_format_tests {
    use super::*;

    #[test]
    fn size_units_512_block() { assert_eq!(size_512_sectors(2048, 512), 2048); }

    #[test]
    fn size_units_4k_block() { assert_eq!(size_512_sectors(1000, 4096), 8000); }

    #[test]
    fn size_units_zero_capacity() { assert_eq!(size_512_sectors(0, 512), 0); }

    #[test]
    fn major_minor_virtio() {
        assert_eq!(major_minor("vda", 1), (254, 0));
        assert_eq!(major_minor("vdb", 2), (254, 1));
    }

    #[test]
    fn major_minor_nvme() { assert_eq!(major_minor("nvme0n1", 1), (259, 0)); }

    #[test]
    fn major_minor_ahci() {
        assert_eq!(major_minor("sata0", 3), (8, 2));
        assert_eq!(major_minor("sda", 1), (8, 0));
    }

    #[test]
    fn uevent_body_format() {
        // The /sys/block/<dev>/uevent body sysfs renders from these.
        let (major, minor) = major_minor("vda", 1);
        let body = alloc::format!(
            "MAJOR={}\nMINOR={}\nDEVNAME={}\nDEVTYPE=disk\n", major, minor, "vda");
        assert_eq!(body, "MAJOR=254\nMINOR=0\nDEVNAME=vda\nDEVTYPE=disk\n");
    }
}
