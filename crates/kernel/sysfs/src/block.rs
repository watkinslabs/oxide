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

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

use crate::BodyInode;

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

const DISK_ATTRS: &[&str] = &["size", "ro", "removable", "dev", "uevent"];
const QUEUE_ATTRS: &[&str] = &["logical_block_size", "physical_block_size"];

/// `/sys/block` directory — readdir/lookup enumerates the live
/// `block::registry`. One entry per registered disk.
pub struct SysBlockInode;
impl Inode for SysBlockInode {
    fn ino(&self) -> Ino { INO_BLOCK_ROOT }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        if block::registry::by_name(name).is_some() {
            return Ok(Arc::new(DiskDirInode { name: String::from(name) }) as InodeRef);
        }
        Err(VfsError::Enoent)
    }
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        let disks = block::registry::snapshot();
        let mut idx = off as usize;
        while idx < disks.len() {
            let next = idx as u64 + 1;
            let ino = self.lookup(&disks[idx].name).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, &disks[idx].name, FileType::Directory) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// `/sys/block/<dev>` directory — per-disk attribute set + `queue/`.
struct DiskDirInode { name: String }
impl Inode for DiskDirInode {
    fn ino(&self) -> Ino { INO_DISK_DIR }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        if name == "queue" {
            return Ok(Arc::new(QueueDirInode { name: self.name.clone() }) as InodeRef);
        }
        let disk = block::registry::by_name(&self.name).ok_or(VfsError::Enoent)?;
        let body = disk_attr(&disk, name).ok_or(VfsError::Enoent)?;
        Ok(Arc::new(BodyInode::new(body, INO_ATTR)) as InodeRef)
    }
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        let mut idx = off as usize;
        while idx < DISK_ATTRS.len() {
            let next = idx as u64 + 1;
            let ino = self.lookup(DISK_ATTRS[idx]).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, DISK_ATTRS[idx], FileType::Regular) { return Ok(next); }
            idx += 1;
        }
        if idx == DISK_ATTRS.len() {
            let next = idx as u64 + 1;
            let ino = self.lookup("queue").map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, "queue", FileType::Directory) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// `/sys/block/<dev>/queue` directory — block-queue limits.
struct QueueDirInode { name: String }
impl Inode for QueueDirInode {
    fn ino(&self) -> Ino { INO_QUEUE_DIR }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        if !QUEUE_ATTRS.contains(&name) { return Err(VfsError::Enoent); }
        let disk = block::registry::by_name(&self.name).ok_or(VfsError::Enoent)?;
        let body = alloc::format!("{}\n", disk.dev.block_size()).into_bytes();
        Ok(Arc::new(BodyInode::new(body, INO_ATTR)) as InodeRef)
    }
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        let mut idx = off as usize;
        while idx < QUEUE_ATTRS.len() {
            let next = idx as u64 + 1;
            let ino = self.lookup(QUEUE_ATTRS[idx]).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, QUEUE_ATTRS[idx], FileType::Regular) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// Register the dynamic `/sys/block` directory in the devfs key
/// registry. Called from `sysfs::init`. The per-disk + queue dirs are
/// synthesised on demand, so disks registered after boot appear with
/// no further work.
/// # C: O(1)
pub fn init() {
    crate::register("/sys/block", Arc::new(SysBlockInode) as InodeRef);
}
