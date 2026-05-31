//! K2V verify-left harness: drive the dentry path-walk
//! (`vfs::path_lookup`) over the REAL ext4 Inode impls
//! (`Ext4StatInode::lookup` / `readlink` / `wrap_any_ino`) against a
//! fixture image — no QEMU boot. This is the fast dev loop for the
//! VFS dentry/mount rebuild (TASKS.md Track K2V): symlink-follow,
//! intermediate symlinks (merged-usr), ELOOP, and descent are all
//! testable in milliseconds.
//!
//! Image `tests/walk.img` (2 MiB, 1 KiB blocks, no has_journal). Built:
//!   dd if=/dev/zero of=walk.img bs=1M count=2
//!   mkfs.ext4 -F -O ^has_journal -b 1024 walk.img
//!   debugfs -w -f cmds walk.img   # where cmds =
//!     mkdir /usr ; mkdir /usr/bin ; write <REALTOOL> /usr/bin/realtool
//!     symlink /bin /usr/bin                 # merged-usr (intermediate)
//!     write <SLOK> /target.txt
//!     symlink /link /target.txt             # absolute symlink
//!     symlink /rellink target.txt           # relative symlink
//!     symlink /loopa loopb ; symlink /loopb loopa   # loop
//!     mkdir /etc ; mkdir /etc/sub ; write <DEEP> /etc/sub/deep.txt

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::{Dentry, FileType, InodeRef, LookupFlags, VfsError};

const IMAGE: &[u8] = include_bytes!("walk.img");
const BLOCK_SIZE: u32 = 512;

fn build_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (BLOCK_SIZE as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(BLOCK_SIZE, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write,
        start_block: 0,
        len_blocks: cap as u32,
        buffer: IMAGE.to_vec(),
    };
    disk.submit_sync(&mut req).expect("memdisk write");
    disk
}

/// Publish walk.img as the global ext4 rootfs (idempotent) and return a
/// fresh root dentry. Tests run in parallel sharing the global mount;
/// the first publish wins, all see the same image.
fn root() -> Arc<Dentry> {
    let mount = ext4::Mount::open(build_disk()).expect("mount walk.img");
    ext4::rootfs::set_test_mount(mount);
    let root_inode = ext4::rootfs::lookup_inode_any(b"/").expect("root inode");
    Dentry::new_root(root_inode)
}

fn look(path: &str, f: LookupFlags) -> vfs::KResult<(InodeRef, Arc<Dentry>)> {
    let r = root();
    vfs::path_lookup(r.clone(), r, path, f)
}

/// ext4 ino of `path` via the independent whole-path lookup — the oracle
/// the per-component walk must agree with.
fn whole_path_ino(path: &str) -> u64 {
    root(); // ensure mount published
    ext4::rootfs::lookup_inode_any(path.as_bytes()).expect("whole-path").ino()
}

#[test]
fn descends_nested_dirs() {
    let (i, _) = look("/etc/sub/deep.txt", LookupFlags::default()).expect("descend");
    assert_eq!(i.ino(), whole_path_ino("/etc/sub/deep.txt"));
    assert_eq!(i.file_type(), FileType::Regular);
}

// merged-usr: /bin is a symlink → /usr/bin. Resolving /bin/realtool must
// follow the INTERMEDIATE symlink (R6) and land on /usr/bin/realtool.
#[test]
fn follows_intermediate_symlink_merged_usr() {
    let (i, _) = look("/bin/realtool", LookupFlags::default()).expect("merged-usr");
    assert_eq!(i.ino(), whole_path_ino("/usr/bin/realtool"));
    assert_eq!(i.file_type(), FileType::Regular);
}

#[test]
fn follows_absolute_symlink() {
    let (i, _) = look("/link", LookupFlags::default()).expect("abs symlink");
    assert_eq!(i.ino(), whole_path_ino("/target.txt"));
}

#[test]
fn follows_relative_symlink() {
    let (i, _) = look("/rellink", LookupFlags::default()).expect("rel symlink");
    assert_eq!(i.ino(), whole_path_ino("/target.txt"));
}

#[test]
fn o_nofollow_returns_symlink() {
    let f = LookupFlags { no_follow_final: true, ..Default::default() };
    let (i, _) = look("/link", f).expect("nofollow");
    assert_eq!(i.file_type(), FileType::Symlink, "final symlink not followed");
}

#[test]
fn symlink_loop_is_eloop() {
    assert_eq!(look("/loopa", LookupFlags::default()).err(), Some(VfsError::Eloop));
}

#[test]
fn missing_is_enoent() {
    assert_eq!(look("/etc/sub/nope", LookupFlags::default()).err(), Some(VfsError::Enoent));
}

// docs/16§2 Superblock::root — the inode a path-walk switches to when it
// crosses into this mount (the V4 piece V5's mount-crossing uses).
#[test]
fn fs_root_is_root_dir() {
    use vfs::fs::FileSystem;
    root(); // ensure the mount is published
    let r = ext4::rootfs::Ext4RootfsFs.root().expect("fs.root()");
    assert_eq!(r.file_type(), FileType::Directory);
    assert_eq!(r.ino(), whole_path_ino("/"), "fs.root() is the ino-2 root dir");
}
