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

/// Linux block-driver major numbers owned by this registry's synthetic mapping.
pub const BLOCK_MAJOR_SCSI: u32 = 8;
pub const BLOCK_MAJOR_VIRTIO: u32 = 254;
pub const BLOCK_MAJOR_EXT: u32 = 259;

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
type DiskRemoveHook = fn(&str);
static DISK_REMOVE_HOOK: Spinlock<Option<DiskRemoveHook>, DevicesClass> = Spinlock::new(None);

/// Install the disk remove hook used by sysfs to drop stale block dentries. # C: O(1)
pub fn set_remove_hook(f: DiskRemoveHook) { *DISK_REMOVE_HOOK.lock() = Some(f); }

/// Register a block device. Returns the assigned 1-based index.
/// Idempotent on `name`: returns the existing index if already
/// present (driver hot-replug not supported in v1).
/// # C: O(N_disks)
pub fn register(name: &str, dev: Arc<dyn BlockDevice>) -> u32 {
    register_with_serial(name, None, dev)
}

/// Register a block device with an identity `serial` (`Some("oxide-root")`
/// etc.). Empty/`None` serial = no by-serial binding. Same idempotency
/// on `name` as `register`. Returns 0 if the block device cannot be published
/// into the driver model; the disk table is rolled back in that case.
/// # C: O(N_disks)
pub fn register_with_serial(name: &str, serial: Option<&str>, dev: Arc<dyn BlockDevice>) -> u32 {
    let (index, bridge_dev) = {
        let mut t = TABLE.lock();
        if let Some(d) = t.iter().find(|d| d.name == name) {
            return d.index;
        }
        let index = (t.len() as u32) + 1;
        // Wrap the driver device in the stats-counting decorator so every I/O
        // through the registry is accounted at one central point (Linux blk-stat).
        let (dev, stats) = crate::stats::StatsDev::wrap(dev);
        // Keep a handle to the wrapped device so `open("/dev/<name>")` dispatches
        // its I/O (stats-counted) once the /dev node is published below.
        let bridge_dev = dev.clone();
        t.push(Arc::new(Disk {
            name: name.to_string(),
            index,
            serial: serial.filter(|s| !s.is_empty()).map(|s| s.to_string()),
            dev,
            stats,
        }));
        (index, bridge_dev)
    }; // release TABLE before firing the device-model hooks (avoids holding the
       // registry lock across the devtmpfs /dev-node insertion).
    // device-model Stage C (D27): publish the disk as a `drv::try_device_add`
    // block device so ONE registration mints the `/dev/<name>` block node (devtmpfs)
    // alongside the existing `/sys/block/<name>` synthesis (which already reads
    // this registry). bus "block" is ignored by the pci/virtio /sys synthesis,
    // so the disk is NOT double-listed under /sys/bus; the real virtio-blk PCI
    // function is still registered separately under its own bus. No factory: a
    // plain block node synthesised from the real (major,minor) is exactly the
    // devtmpfs node Linux would create (none existed before — the rootfs image
    // ships no /dev/<disk> node).
    let dt = major_minor(name, index);
    match drv::try_device_add(Arc::new(
        drv::Device::new("block", name.to_string(), 0, 0, 0)
            .with_devnode("block", name.to_string(), Some(dt)))) {
        Ok(_) => {
            // Publish into the VFS BLKDEV dispatch table so `open("/dev/<name>")`
            // from userspace (blkid/udev/fsck) resolves to this disk instead of
            // ENXIO (Linux `add_disk`/`blkdev_open`). Node minting above only
            // created the devtmpfs inode; without this the fops had no driver.
            crate::devbridge::publish(name, index, bridge_dev);
            index
        }
        Err(_) => {
            let mut t = TABLE.lock();
            if let Some(pos) = t.iter().position(|d| d.name == name && d.index == index) {
                t.remove(pos);
            }
            0
        }
    }
}

/// Unregister a block device by name. Removes the disk from the registry so
/// `/sys/block`, `/proc/partitions`, `/proc/diskstats`, by-name/by-serial
/// lookup, and future opens stop seeing it; then calls `drv::device_del` for
/// the matching block device so the owned `/dev/<name>` node is removed and a
/// remove uevent is emitted. Existing mounted filesystems may still hold an
/// `Arc<dyn BlockDevice>`; that mirrors gendisk teardown where publication is
/// removed before the final object reference is dropped.
/// # C: O(N_disks + N_devices)
pub fn unregister(name: &str) -> bool {
    let removed = {
        let mut t = TABLE.lock();
        match t.iter().position(|d| d.name == name) {
            Some(i) => {
                // Drop the VFS BLKDEV region so future opens ENXIO again
                // (Linux `del_gendisk`), before the disk leaves the table.
                crate::devbridge::unpublish(name, t[i].index);
                t.remove(i);
                true
            }
            None => false,
        }
    };
    if !removed { return false; }
    if let Some(dev) = drv::devices()
        .into_iter()
        .find(|d| d.bus == "block" && d.addr == name)
    {
        drv::device_del(&dev);
    }
    let hook = *DISK_REMOVE_HOOK.lock();
    if let Some(f) = hook { f(name); }
    true
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

/// `lookup_bdev`-style resolution: find a registered disk by its packed `dev_t`
/// in the glibc/`new_encode_dev` wire form (`st_rdev`/`i_rdev`) — minor[0..8] |
/// major[8..20] | minor[20..32]. The caller resolves a `/dev/<disk>` block node
/// to its inode and passes `i_rdev`; this decodes it to `(major, minor)` and
/// matches against each disk's synthetic [`major_minor`]. Linux's
/// `blkdev_get_by_dev` over the gendisk's `(major, minor)`. `None` ⇒ no disk owns
/// that dev_t (caller falls back to name/serial). # C: O(N_disks)
pub fn by_dev(dev_t: u32) -> Option<Arc<Disk>> {
    // `new_decode_dev` (Linux `include/linux/kdev_t.h`): invert the high-minor
    // split the stat ABI packs into a 32-bit user dev_t.
    let major = (dev_t & 0x000f_ff00) >> 8;
    let minor = (dev_t & 0xff) | ((dev_t >> 12) & 0x000f_ff00);
    TABLE.lock().iter().find(|d| major_minor(&d.name, d.index) == (major, minor)).cloned()
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
    let major = if name.starts_with("nvme") { BLOCK_MAJOR_EXT }
        else if name.starts_with("vd") { BLOCK_MAJOR_VIRTIO }
        else if name.starts_with("sd") || name.starts_with("sata") { BLOCK_MAJOR_SCSI }
        else { BLOCK_MAJOR_VIRTIO };
    (major, index.saturating_sub(1))
}

/// Pack `(major, minor)` into the glibc/`new_encode_dev` wire `dev_t` form
/// (`st_rdev`/`i_rdev`) — the inverse of [`by_dev`]'s decode: minor[0..8] |
/// major[8..20] | minor[20..32]. The canonical 32-bit device id ext4 keys its
/// shared `SuperBlock` (`s_dev`) on. # C: O(1)
pub fn encode_dev(major: u32, minor: u32) -> u32 {
    (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12)
}

/// The packed wire `dev_t` of a registered disk (by name + 1-based index), via
/// its synthetic [`major_minor`]. # C: O(1)
pub fn dev_t_of(name: &str, index: u32) -> u32 {
    let (major, minor) = major_minor(name, index);
    encode_dev(major, minor)
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
        assert_eq!(major_minor("vda", 1), (BLOCK_MAJOR_VIRTIO, 0));
        assert_eq!(major_minor("vdb", 2), (BLOCK_MAJOR_VIRTIO, 1));
    }

    #[test]
    fn major_minor_nvme() { assert_eq!(major_minor("nvme0n1", 1), (BLOCK_MAJOR_EXT, 0)); }

    #[test]
    fn major_minor_ahci() {
        assert_eq!(major_minor("sata0", 3), (BLOCK_MAJOR_SCSI, 2));
        assert_eq!(major_minor("sda", 1), (BLOCK_MAJOR_SCSI, 0));
    }

    #[test]
    fn by_dev_resolves_registered_disk() {
        use crate::blockdev::MemDisk;
        use sync::TaskList;
        let dev: Arc<dyn BlockDevice> = MemDisk::<TaskList>::new(512, 8);
        let idx = register("bydevvd", dev);
        // glibc/new_encode_dev wire form the stat ABI (i_rdev) carries.
        let enc = dev_t_of("bydevvd", idx);
        let found = by_dev(enc).expect("by_dev resolves the registered disk");
        assert_eq!(found.name, "bydevvd");
        assert_eq!(found.index, idx);
        // encode_dev ∘ by_dev round-trips the (major,minor) split.
        let (major, minor) = major_minor("bydevvd", idx);
        assert_eq!(encode_dev(major, minor), enc, "encode_dev is by_dev's inverse");
        // A dev_t no disk owns (impossible major 0xfff) → None.
        assert!(by_dev(0xfff << 8).is_none(), "unowned dev_t → None");
    }

    #[test]
    fn register_fires_device_add_block_node() {
        use crate::blockdev::MemDisk;
        use sync::TaskList;
        // Record what the devtmpfs hook receives (mimics devfs::add_device_node).
        static SEEN: Spinlock<Vec<(String, Option<(u32, u32)>)>, DevicesClass>
            = Spinlock::new(Vec::new());
        fn cb(class: &str, name: &str, dt: Option<(u32, u32)>, _f: Option<drv::NodeFactory>) {
            if class == "block" { SEEN.lock().push((name.to_string(), dt)); }
        }
        drv::set_devtmpfs_hook(cb);
        let dev: Arc<dyn BlockDevice> = MemDisk::<TaskList>::new(512, 8);
        let idx = register("vdadd", dev);
        // device_add minted /dev/vdadd with the disk's real (major,minor).
        let want = (String::from("vdadd"), Some(major_minor("vdadd", idx)));
        assert!(SEEN.lock().iter().any(|e| *e == want),
            "register() device_add's a block /dev node with the disk dev_t");
    }

    #[test]
    fn register_existing_name_is_idempotent_without_republishing() {
        use crate::blockdev::MemDisk;
        use sync::TaskList;
        static SEEN: Spinlock<Vec<String>, DevicesClass> = Spinlock::new(Vec::new());
        fn cb(class: &str, name: &str, _dt: Option<(u32, u32)>, _f: Option<drv::NodeFactory>) {
            if class == "block" {
                SEEN.lock().push(name.to_string());
            }
        }
        drv::set_devtmpfs_hook(cb);
        let first_dev: Arc<dyn BlockDevice> = MemDisk::<TaskList>::new(512, 8);
        let second_dev: Arc<dyn BlockDevice> = MemDisk::<TaskList>::new(512, 8);

        let first = register("vdidem", first_dev);
        let second = register("vdidem", second_dev);

        assert_eq!(second, first);
        assert_eq!(SEEN.lock().iter().filter(|n| n.as_str() == "vdidem").count(), 1);
        assert_eq!(
            drv::devices().iter()
                .filter(|d| d.bus == "block" && d.addr == "vdidem")
                .count(),
            1
        );
        assert!(unregister("vdidem"));
    }

    #[test]
    fn register_rolls_back_disk_table_when_model_publication_conflicts() {
        use crate::blockdev::MemDisk;
        use sync::TaskList;
        let conflict = drv::try_device_add(Arc::new(
            drv::Device::new("block", String::from("vdconflict"), 0, 0, 0)
                .with_devnode("block", String::from("vdconflict"), Some((254, 77)))))
            .expect("conflict device registration");
        let dev: Arc<dyn BlockDevice> = MemDisk::<TaskList>::new(512, 8);

        assert_eq!(register("vdconflict", dev), 0);
        assert!(by_name("vdconflict").is_none());
        assert_eq!(
            drv::devices().iter()
                .filter(|d| d.bus == "block" && d.addr == "vdconflict")
                .count(),
            1
        );

        drv::device_del(&conflict);
    }

    #[test]
    fn unregister_removes_disk_and_device_node() {
        use crate::blockdev::MemDisk;
        use sync::TaskList;
        static REMOVED: Spinlock<Vec<String>, DevicesClass> = Spinlock::new(Vec::new());
        fn del(name: &str) {
            REMOVED.lock().push(name.to_string());
        }
        drv::set_devtmpfs_del_hook(del);
        let dev: Arc<dyn BlockDevice> = MemDisk::<TaskList>::new(512, 8);
        let idx = register("vdremove", dev);
        assert!(idx != 0);
        assert!(by_name("vdremove").is_some());
        assert!(unregister("vdremove"));
        assert!(by_name("vdremove").is_none());
        assert!(REMOVED.lock().iter().any(|n| n == "vdremove"));
        assert!(!unregister("vdremove"));
    }

    #[test]
    fn unregister_then_register_restores_disk_device_node_and_dev_t() {
        use crate::blockdev::MemDisk;
        use sync::TaskList;
        static REMOVED: Spinlock<Vec<String>, DevicesClass> = Spinlock::new(Vec::new());
        fn del(name: &str) {
            REMOVED.lock().push(name.to_string());
        }
        drv::set_devtmpfs_del_hook(del);

        let name = "vdreadd";
        let _ = unregister(name);
        assert!(by_name(name).is_none());
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "block" && d.addr == name)
                .count(),
            0
        );

        let first_dev: Arc<dyn BlockDevice> = MemDisk::<TaskList>::new(512, 8);
        let first = register(name, first_dev);
        assert_ne!(first, 0);
        let first_dev_t = dev_t_of(name, first);
        let first_disk = by_dev(first_dev_t).expect("registered disk owns its dev_t");
        assert_eq!(first_disk.name, name);
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "block" && d.addr == name)
                .count(),
            1
        );

        assert!(unregister(name));
        assert!(by_name(name).is_none());
        assert!(by_dev(first_dev_t).is_none());
        assert!(REMOVED.lock().iter().any(|n| n == name));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "block" && d.addr == name)
                .count(),
            0
        );

        let second_dev: Arc<dyn BlockDevice> = MemDisk::<TaskList>::new(512, 8);
        let second = register(name, second_dev);
        assert_eq!(second, first);
        assert!(by_dev(first_dev_t).is_some());
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "block" && d.addr == name)
                .count(),
            1
        );
        assert!(unregister(name));
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
