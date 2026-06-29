// `/sys/dev/char/<maj>:<min>` + `/sys/dev/block/<maj>:<min>` (DVR-0014).
// Linux's device-number index: a symlink per registered char/block device
// pointing at the device's canonical sysfs directory, so
// `udevadm info --query=path --name=/dev/<x>` resolves `/dev/<x>` → sysfs.
//
// Block entries derive live from `block::registry` (every disk has a
// `/sys/block/<name>` home → target `../../block/<name>`). Char entries come
// from a small registry that subsystems with a sysfs class home register into
// (`register_char_dev`); the tty class registers its nodes here at init. The
// dirs are dynamic, so a device registered after boot appears automatically.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, TaskList as LockClass};
use vfs::{mk_mode, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use crate::{make_symlink_inode_ino, DIR_PERM};

const INO_DEV_CHAR: Ino = 0x5104_0001;
const INO_DEV_BLOCK: Ino = 0x5104_0002;
const INO_LINK: Ino = 0x5104_0080;

/// One registered char device: `(major, minor, sysfs-target relative to /sys)`.
/// e.g. `(4, 0, "class/tty/tty0")`. # C: n/a
static CHAR_DEVS: Spinlock<Vec<(u32, u32, String)>, LockClass> = Spinlock::new(Vec::new());

/// Register a char device's `/sys/dev/char/<maj>:<min>` index entry. `target`
/// is the device's sysfs path RELATIVE to `/sys` (no leading slash), e.g.
/// `"class/tty/tty0"` or `"devices/pci0000:00/.../drm/card0"`. Idempotent on
/// `(major, minor)`. # C: O(N_char)
pub fn register_char_dev(major: u32, minor: u32, target: &str) {
    let mut t = CHAR_DEVS.lock();
    if t.iter().any(|(a, b, _)| *a == major && *b == minor) { return; }
    t.push((major, minor, String::from(target)));
}

/// Snapshot of registered char devices as `("maj:min", target_rel)`. # C: O(N)
fn char_list() -> Vec<(String, String)> {
    CHAR_DEVS.lock().iter().map(|(maj, min, t)| (alloc::format!("{}:{}", maj, min), t.clone())).collect()
}

/// Live block-device index as `("maj:min", "<name>")` from `block::registry`.
/// # C: O(N_disks)
fn block_list() -> Vec<(String, String)> {
    block::registry::snapshot().iter().map(|d| {
        let (maj, min) = block::registry::major_minor(&d.name, d.index);
        (alloc::format!("{}:{}", maj, min), d.name.clone())
    }).collect()
}

fn make_link_inode(target: String) -> InodeRef {
    make_symlink_inode_ino(target.into_bytes(), INO_LINK)
}

/// `/sys/dev/char` — symlink per char device → `../../<target_rel>`.
struct DevCharOps;
impl InodeOps for DevCharOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        for (k, target) in char_list() {
            if k == name { return Ok(make_link_inode(alloc::format!("../../{}", target))); }
        }
        Err(VfsError::Enoent)
    }
}
impl FileOps for DevCharOps {
    fn iterate(&self, inode: &Inode, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        let list = char_list();
        let mut idx = off as usize;
        while idx < list.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(&list[idx].0).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, &list[idx].0, FileType::Symlink) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// `/sys/dev/block` — symlink per disk → `../../block/<name>`.
struct DevBlockOps;
impl InodeOps for DevBlockOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        for (k, disk) in block_list() {
            if k == name { return Ok(make_link_inode(alloc::format!("../../block/{}", disk))); }
        }
        Err(VfsError::Enoent)
    }
}
impl FileOps for DevBlockOps {
    fn iterate(&self, inode: &Inode, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        let list = block_list();
        let mut idx = off as usize;
        while idx < list.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(&list[idx].0).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, &list[idx].0, FileType::Symlink) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// Register the `/sys/dev/{char,block}` index dirs + the tty char entries
/// (the char devices that have a sysfs class home today). # C: O(1)
pub fn init() {
    crate::register("/sys/dev/char",
        InodeBuilder::new(INO_DEV_CHAR, mk_mode(FileType::Directory, DIR_PERM),
            Arc::new(DevCharOps), Arc::new(DevCharOps)).build());
    crate::register("/sys/dev/block",
        InodeBuilder::new(INO_DEV_BLOCK, mk_mode(FileType::Directory, DIR_PERM),
            Arc::new(DevBlockOps), Arc::new(DevBlockOps)).build());
    // tty class nodes (major/minor per `sysfs::TTY_DEVICES`).
    register_char_dev(5, 1, "class/tty/console");
    register_char_dev(5, 0, "class/tty/tty");
    register_char_dev(4, 0, "class/tty/tty0");
    register_char_dev(crate::SERIAL_TTY_MAJOR, 64, "class/tty/ttyS0");
}
