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
use crate::{DIR_PERM, RO_PERM};

const INO_BLOCK_ROOT: Ino = 0x5103_0001;
const INO_DISK_DIR:   Ino = 0x5103_1000;
const INO_QUEUE_DIR:  Ino = 0x5103_1100;
const INO_ATTR:       Ino = 0x5103_2000;

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
    Attribute { name: "uevent",    mode: RO_PERM },
];
static DISK_GROUP: AttrGroup = AttrGroup { attrs: DISK_ATTR_LIST };

/// `/sys/block/<dev>/queue` attribute group (Linux `queue_attrs`). # C: n/a
const QUEUE_ATTR_LIST: &[Attribute] = &[
    Attribute { name: "logical_block_size",  mode: RO_PERM },
    Attribute { name: "physical_block_size", mode: RO_PERM },
];
static QUEUE_GROUP: AttrGroup = AttrGroup { attrs: QUEUE_ATTR_LIST };

/// `sysfs_ops` for a `/sys/block/<dev>` kobject — `show` renders each disk
/// attribute fresh from the live `block::registry`. # C: O(1)
struct DiskKobj { name: String }
impl SysfsOps for DiskKobj {
    fn show(&self, attr: &str) -> Option<Vec<u8>> {
        let disk = block::registry::by_name(&self.name)?;
        disk_attr(&disk, attr)
    }
}

/// `sysfs_ops` for a `/sys/block/<dev>/queue` kobject — both leaves report the
/// disk's block size. # C: O(1)
struct QueueKobj { name: String }
impl SysfsOps for QueueKobj {
    fn show(&self, attr: &str) -> Option<Vec<u8>> {
        QUEUE_GROUP.find(attr)?;
        let disk = block::registry::by_name(&self.name)?;
        Some(alloc::format!("{}\n", disk.dev.block_size()).into_bytes())
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
        let attr = DISK_GROUP.find(name).ok_or(VfsError::Enoent)?;
        let ops: Arc<dyn SysfsOps> = Arc::new(DiskKobj { name: d.name.clone() });
        Ok(make_attr_inode(attr, ops, INO_ATTR))
    }
}
impl FileOps for DiskDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
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
        Ok(())
    }
}
fn make_disk_dir_inode(name: String) -> InodeRef {
    InodeBuilder::new(INO_DISK_DIR, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(DiskDirOps), Arc::new(DiskDirOps))
        .private(Arc::new(DiskDirData { name }))
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
/// # C: O(1)
pub fn init() {
    crate::register("/sys/block", make_sys_block_inode());
}
