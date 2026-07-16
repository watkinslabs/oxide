// `/sys/block` sysfs tree (drivers-plan D7a). Synthesises the
// Linux-visible per-disk attribute tree from the live
// `block::registry`. Everything is dynamic: dir inodes readdir/lookup
// the registry on each access, so a disk registered after boot
// appears automatically (no eager per-disk devfs key writes).
// Mirrors the `/sys/class/net` dynamic-inode pattern.
//
// Tree:
//   /sys/block/                       (dir: one entry per registered disk)
//   /sys/block/<dev>/                 (per-disk dir)
//     size                            capacity in 512-byte sectors
//     ro                              "0\n" (oxide disks are rw)
//     removable                       "0\n"
//     dev                             "<major>:<minor>\n"
//     uevent                          MAJOR=/MINOR=/DEVNAME=/DEVTYPE=disk
//     device/
//       serial                        block registry identity, if present
//     queue/                          (subdir)
//       logical_block_size            block_size (e.g. "512\n")
//       physical_block_size           block_size
//
// Linux gotcha: /sys/block/<dev>/size is ALWAYS reported in 512-byte
// units regardless of the device's logical block size:
//   size_512 = capacity_blocks * block_size / 512.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{mk_mode, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use crate::kobject::{make_attr_inode, Attribute, AttrGroup, SysfsOps};
use crate::{DIR_PERM, RO_PERM, RW_PERM};

const INO_BLOCK_ROOT: Ino = crate::ids::BLOCK_ROOT;
const INO_DISK_DIR: Ino = crate::ids::BLOCK_DISK_DIR;
const INO_QUEUE_DIR: Ino = crate::ids::BLOCK_QUEUE_DIR;
const INO_DEVICE_DIR: Ino = crate::ids::BLOCK_DEVICE_DIR;
const INO_ATTR: Ino = crate::ids::BLOCK_ATTR;

use block::registry::{major_minor, size_512_sectors};

/// `uevent` body for a disk. Linux block uevent env (one var/line).
/// # C: O(1)
fn uevent_body(name: &str, major: u32, minor: u32) -> Vec<u8> {
    alloc::format!("MAJOR={}\nMINOR={}\nDEVNAME={}\nDEVTYPE=disk\n",
        major, minor, name).into_bytes()
}

fn disk_attr(disk: &block::registry::Disk, leaf: &str) -> Option<Vec<u8>> {
    let bs = disk.dev.block_size();
    let (major, minor) = major_minor(&disk.name, disk.index);
    match leaf {
        "size" => {
            let s = size_512_sectors(disk.dev.capacity_blocks(), bs);
            Some(alloc::format!("{}\n", s).into_bytes())
        }
        "ro"        => Some(b"0\n".to_vec()),
        "removable" => Some(b"0\n".to_vec()),
        "dev"       => Some(alloc::format!("{}:{}\n", major, minor).into_bytes()),
        "uevent"    => Some(uevent_body(&disk.name, major, minor)),
        _ => None,
    }
}

/// `/sys/block/<dev>` default attribute group (Linux `disk_attrs`). # C: n/a
const DISK_ATTR_LIST: &[Attribute] = &[
    Attribute { name: "size",      mode: RO_PERM },
    Attribute { name: "ro",        mode: RO_PERM },
    Attribute { name: "removable", mode: RO_PERM },
    Attribute { name: "dev",       mode: RO_PERM },
    // uevent is WRITABLE (Linux disk_uevent): `udevadm trigger` / coldplug
    // writes "add" to it to re-emit the device's uevent after udevd is up. A
    // read-only uevent made coldplug fail EROFS on the first disk, so udevd
    // never received ANY device uevent (no master-of-seat tag → no greeter).
    Attribute { name: "uevent",    mode: RW_PERM },
];
static DISK_GROUP: AttrGroup = AttrGroup { attrs: DISK_ATTR_LIST };

/// `/sys/block/<dev>/queue` attribute group (Linux `queue_attrs`). # C: n/a
const QUEUE_ATTR_LIST: &[Attribute] = &[
    Attribute { name: "logical_block_size",  mode: RO_PERM },
    Attribute { name: "physical_block_size", mode: RO_PERM },
];
static QUEUE_GROUP: AttrGroup = AttrGroup { attrs: QUEUE_ATTR_LIST };

/// `/sys/block/<dev>/device` identity leaves for block devices with a registry
/// serial. # C: n/a
const DEVICE_ATTR_LIST: &[Attribute] = &[
    Attribute { name: "serial", mode: RO_PERM },
];
static DEVICE_GROUP: AttrGroup = AttrGroup { attrs: DEVICE_ATTR_LIST };

/// `sysfs_ops` for a `/sys/block/<dev>` kobject — `show` renders each disk
/// attribute fresh from the live `block::registry`. # C: O(1)
struct DiskKobj { name: String }
impl SysfsOps for DiskKobj {
    fn show(&self, attr: &str) -> KResult<Vec<u8>> {
        let disk = block::registry::by_name(&self.name).ok_or(VfsError::Enodev)?;
        disk_attr(&disk, attr).ok_or(VfsError::Enoent)
    }

    /// Writing "add"/"change"/"remove" to `uevent` re-emits the disk's uevent
    /// (Linux `uevent_store` → `kobject_synth_uevent`). This is what `udevadm
    /// trigger` (coldplug) does to replay device events after udevd starts.
    /// # C: O(1)
    fn store(&self, attr: &str, buf: &[u8]) -> KResult<usize> {
        if attr != "uevent" {
            return Err(VfsError::Erofs);
        }
        let disk = block::registry::by_name(&self.name).ok_or(VfsError::Enoent)?;
        let (major, minor) = major_minor(&disk.name, disk.index);
        let devpath = alloc::format!("/devices/virtual/block/{}", disk.name);
        let devname = alloc::format!("DEVNAME={}", disk.name);
        let maj = alloc::format!("MAJOR={}", major);
        let min = alloc::format!("MINOR={}", minor);
        ::netlink::emit_uevent_with_env(
            crate::uevent_action(buf),
            &devpath,
            "block",
            &[&devname, &maj, &min, "DEVTYPE=disk"],
        );
        Ok(buf.len())
    }
}

/// `sysfs_ops` for a `/sys/block/<dev>/queue` kobject — both leaves report the
/// disk's block size. # C: O(1)
struct QueueKobj { name: String }
impl SysfsOps for QueueKobj {
    fn show(&self, attr: &str) -> KResult<Vec<u8>> {
        QUEUE_GROUP.find(attr).ok_or(VfsError::Enoent)?;
        let disk = block::registry::by_name(&self.name).ok_or(VfsError::Enodev)?;
        Ok(alloc::format!("{}\n", disk.dev.block_size()).into_bytes())
    }
}

/// `sysfs_ops` for `/sys/block/<dev>/device`. # C: O(1)
struct DeviceKobj { name: String }
impl SysfsOps for DeviceKobj {
    fn show(&self, attr: &str) -> KResult<Vec<u8>> {
        DEVICE_GROUP.find(attr).ok_or(VfsError::Enoent)?;
        let disk = block::registry::by_name(&self.name).ok_or(VfsError::Enodev)?;
        let serial = disk.serial.as_ref().ok_or(VfsError::Enoent)?;
        Ok(alloc::format!("{}\n", serial).into_bytes())
    }
}

/// `/sys/block` directory — readdir/lookup enumerates the live
/// `block::registry`. One entry per registered disk.
struct SysBlockOps;
impl InodeOps for SysBlockOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        if block::registry::by_name(name).is_some() {
            return Ok(make_disk_dir_inode(String::from(name)));
        }
        Err(VfsError::Enoent)
    }
}
impl FileOps for SysBlockOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let disks = block::registry::snapshot();
        let mut idx = ctx.pos as usize;
        while idx < disks.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(&disks[idx].name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(&disks[idx].name, ino, FileType::Directory, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_sys_block_inode() -> InodeRef {
    InodeBuilder::new(INO_BLOCK_ROOT, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysBlockOps), Arc::new(SysBlockOps)).build()
}

/// `/sys/block/<dev>` directory — per-disk attribute set + `queue/`.
struct DiskDirData { name: String }

struct DiskDirOps;
impl InodeOps for DiskDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<DiskDirData>().ok_or(VfsError::Einval)?;
        if name == "queue" {
            return Ok(make_queue_dir_inode(d.name.clone()));
        }
        if name == "device" {
            let disk = block::registry::by_name(&d.name).ok_or(VfsError::Enoent)?;
            if disk.serial.is_none() { return Err(VfsError::Enoent); }
            return Ok(make_device_dir_inode(d.name.clone()));
        }
        // `subsystem` symlink → /sys/class/block: sd-device reads it (basename)
        // for SUBSYSTEM (60§6.2). Correct depth for /sys/devices/virtual/block/
        // <name>/subsystem (the DEVPATH udev processes).
        if name == "subsystem" {
            return Ok(crate::make_symlink_inode(b"../../../../class/block".to_vec()));
        }
        let attr = DISK_GROUP.find(name).ok_or(VfsError::Enoent)?;
        let ops: Arc<dyn SysfsOps> = Arc::new(DiskKobj { name: d.name.clone() });
        Ok(make_attr_inode(attr, ops, INO_ATTR))
    }
}
impl FileOps for DiskDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = inode.private::<DiskDirData>().ok_or(VfsError::Einval)?;
        let mut idx = ctx.pos as usize;
        while idx < DISK_GROUP.attrs.len() {
            let next = idx as u64 + 1;
            let name = DISK_GROUP.attrs[idx].name;
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Regular, next) { return Ok(()); }
            idx += 1;
        }
        if idx == DISK_GROUP.attrs.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup("queue").map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit("queue", ino, FileType::Directory, next) { return Ok(()); }
            idx += 1;
        }
        if idx == DISK_GROUP.attrs.len() + 1 {
            let has_serial = block::registry::by_name(&d.name)
                .map(|disk| disk.serial.is_some())
                .unwrap_or(false);
            if has_serial {
                let next = idx as u64 + 1;
                let ino = inode.lookup("device").map(|i| i.ino()).unwrap_or(0);
                if !ctx.emit("device", ino, FileType::Directory, next) { return Ok(()); }
                idx += 1;
            }
        }
        let subsystem_pos = DISK_GROUP.attrs.len() + 1
            + block::registry::by_name(&d.name)
                .map(|disk| disk.serial.is_some() as usize)
                .unwrap_or(0);
        if idx == subsystem_pos {
            let next = idx as u64 + 1;
            let ino = inode.lookup("subsystem").map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit("subsystem", ino, FileType::Symlink, next) { return Ok(()); }
        }
        Ok(())
    }
}
fn make_disk_dir_inode(name: String) -> InodeRef {
    InodeBuilder::new(INO_DISK_DIR, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(DiskDirOps), Arc::new(DiskDirOps))
        .private(Arc::new(DiskDirData { name }))
        .build()
}

/// `/sys/block/<dev>/device` directory — identity attrs from registry serial.
struct DeviceDirData { name: String }

struct DeviceDirOps;
impl InodeOps for DeviceDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<DeviceDirData>().ok_or(VfsError::Einval)?;
        let attr = DEVICE_GROUP.find(name).ok_or(VfsError::Enoent)?;
        let ops: Arc<dyn SysfsOps> = Arc::new(DeviceKobj { name: d.name.clone() });
        Ok(make_attr_inode(attr, ops, INO_ATTR))
    }
}
impl FileOps for DeviceDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let mut idx = ctx.pos as usize;
        while idx < DEVICE_GROUP.attrs.len() {
            let next = idx as u64 + 1;
            let name = DEVICE_GROUP.attrs[idx].name;
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Regular, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_device_dir_inode(name: String) -> InodeRef {
    InodeBuilder::new(INO_DEVICE_DIR, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(DeviceDirOps), Arc::new(DeviceDirOps))
        .private(Arc::new(DeviceDirData { name }))
        .build()
}

/// `/sys/block/<dev>/queue` directory — block-queue limits.
struct QueueDirData { name: String }

struct QueueDirOps;
impl InodeOps for QueueDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<QueueDirData>().ok_or(VfsError::Einval)?;
        let attr = QUEUE_GROUP.find(name).ok_or(VfsError::Enoent)?;
        let ops: Arc<dyn SysfsOps> = Arc::new(QueueKobj { name: d.name.clone() });
        Ok(make_attr_inode(attr, ops, INO_ATTR))
    }
}
impl FileOps for QueueDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let mut idx = ctx.pos as usize;
        while idx < QUEUE_GROUP.attrs.len() {
            let next = idx as u64 + 1;
            let name = QUEUE_GROUP.attrs[idx].name;
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Regular, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_queue_dir_inode(name: String) -> InodeRef {
    InodeBuilder::new(INO_QUEUE_DIR, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(QueueDirOps), Arc::new(QueueDirOps))
        .private(Arc::new(QueueDirData { name }))
        .build()
}

/// Register the dynamic `/sys/block` directory in sysfs's own tree.
/// Called from `sysfs::init`. The per-disk + queue dirs are
/// synthesised on demand, so disks registered after boot appear with
/// no further work.
const INO_VIRT_BLOCK: Ino = crate::ids::BLOCK_VIRT;
const INO_CLASS_BLOCK: Ino = crate::ids::BLOCK_CLASS;
const INO_CLASS_LINK: Ino = crate::ids::BLOCK_CLASS_LINK;

/// `/sys/devices/virtual/block` — the canonical location of the per-disk dirs
/// that block uevent DEVPATHs resolve to (60§6.3a). Reuses `SysBlockOps` so
/// each `<name>` resolves to the same disk dir as `/sys/block/<name>`.
fn make_sys_devices_virtual_block_inode() -> InodeRef {
    InodeBuilder::new(INO_VIRT_BLOCK, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysBlockOps), Arc::new(SysBlockOps)).build()
}

/// `/sys/class/block` — directory of symlinks to each disk's canonical dir
/// (Linux `block_class`). sd-device enumerates the block class through here.
struct SysClassBlockOps;
impl InodeOps for SysClassBlockOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        if block::registry::by_name(name).is_none() { return Err(VfsError::Enoent); }
        let mut target = String::from("../../devices/virtual/block/");
        target.push_str(name);
        Ok(crate::make_symlink_inode_ino(target.into_bytes(), INO_CLASS_LINK))
    }
}
impl FileOps for SysClassBlockOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let disks = block::registry::snapshot();
        let mut idx = ctx.pos as usize;
        while idx < disks.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(&disks[idx].name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(&disks[idx].name, ino, FileType::Symlink, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_sys_class_block_inode() -> InodeRef {
    InodeBuilder::new(INO_CLASS_BLOCK, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysClassBlockOps), Arc::new(SysClassBlockOps)).build()
}

#[cfg(target_os = "oxide-kernel")]
fn invalidate_block_paths(name: &str) {
    for path in ["/sys/block/", "/sys/devices/virtual/block/", "/sys/class/block/"] {
        let full = alloc::format!("{}{}", path, name);
        crate::drop_cached(&full);
    }
}

/// # C: O(1)
pub fn init() {
    crate::register("/sys/block", make_sys_block_inode());
    // 60§6.3a: the real per-disk dirs udev's DEVPATH resolves to + the class
    // index sd-device enumerates. Without these, block-device uevents named a
    // /sys path that did not exist and udevd processed no disk.
    crate::register("/sys/devices/virtual/block", make_sys_devices_virtual_block_inode());
    crate::register("/sys/class/block", make_sys_class_block_inode());
    #[cfg(target_os = "oxide-kernel")]
    block::registry::set_remove_hook(invalidate_block_paths);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use netlink::{proto, NetlinkSocket};
    use sync::TaskList;

    #[test]
    fn block_uevent_write_reemits_model_event() {
        let dev: Arc<dyn block::BlockDevice> = block::MemDisk::<TaskList>::new(512, 8);
        let index = block::registry::register("sysfsblk0", dev);
        assert_ne!(index, 0);
        let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &network_namespace::initial()));
        listener.set_group_mask(1);
        netlink::register_uevent_listener(&listener);

        let root = make_sys_block_inode();
        let dir = root.lookup("sysfsblk0").expect("disk dir");
        let uevent = dir.lookup("uevent").expect("uevent attr");
        assert_eq!(uevent.write(0, b"change\n"), Ok("change\n".len()));
        let (msg, _src) = listener.dequeue().expect("uevent message");
        assert!(msg.windows(b"ACTION=change".len()).any(|w| w == b"ACTION=change"));
        assert!(msg.windows(b"DEVPATH=/devices/virtual/block/sysfsblk0".len()).any(|w| w == b"DEVPATH=/devices/virtual/block/sysfsblk0"));
        assert!(msg.windows(b"SUBSYSTEM=block".len()).any(|w| w == b"SUBSYSTEM=block"));
        assert!(msg.windows(b"DEVNAME=sysfsblk0".len()).any(|w| w == b"DEVNAME=sysfsblk0"));
        assert!(msg.windows(b"DEVTYPE=disk".len()).any(|w| w == b"DEVTYPE=disk"));

        assert!(block::registry::unregister("sysfsblk0"));
    }

    #[test]
    fn block_device_serial_reads_registry_identity() {
        let dev: Arc<dyn block::BlockDevice> = block::MemDisk::<TaskList>::new(512, 8);
        let index = block::registry::register_with_serial("sysfsblkserial", Some("oxahci-test"), dev);
        assert_ne!(index, 0);

        let root = make_sys_block_inode();
        let dir = root.lookup("sysfsblkserial").expect("disk dir");
        let device = dir.lookup("device").expect("device dir");
        let serial = device.lookup("serial").expect("serial attr");
        let mut buf = [0u8; 32];
        let n = serial.read(0, &mut buf).expect("read serial");
        assert_eq!(&buf[..n], b"oxahci-test\n");

        assert!(block::registry::unregister("sysfsblkserial"));
    }
}
