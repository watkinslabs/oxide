//! The VFS-facing filesystem, driven through a real block device.
//!
//! Everything below `mount` is tested against an image in memory. This is the
//! layer that turns that into a filesystem the rest of the kernel can use, and
//! until now nothing exercised it — a rename in a signature or a missing
//! override here would have shown up only once a real program ran.
//!
//! Durability is checked the only way it can be: write, take the bytes off the
//! device, and mount them again.

use super::*;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use block::{BlockDevice, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::{CreateCtx, DirEmit, File, FileOps, FileType, OpenFlags, VfsError};

const BS: u32 = BLKSIZE as u32;

/// A device holding `bytes`.
fn disk(bytes: &[u8]) -> Arc<MemDisk<TaskList>> {
    let blocks = bytes.len() as u64 / u64::from(BS);
    let dev: Arc<MemDisk<TaskList>> = MemDisk::new(BS, blocks);
    let mut req = BlockRequest::new_write(0, blocks as u32, bytes.to_vec());
    dev.submit_sync(&mut req).expect("device write");
    dev
}

/// Everything currently on the device.
fn drain(dev: &Arc<MemDisk<TaskList>>) -> Vec<u8> {
    let blocks = dev.capacity_blocks();
    let mut req = BlockRequest::new_read(0, blocks as u32, BS);
    dev.submit_sync(&mut req).expect("device read");
    req.buffer
}

/// A writable filesystem over a fresh fixture image, and its device.
fn mounted() -> (Arc<F2fs>, Arc<MemDisk<TaskList>>) {
    let dev = disk(&test_image::with_root().finish());
    let fs = F2fs::open_with(dev.clone(), "/dev/fake", true, Options::defaults()).expect("mount");
    (fs, dev)
}

/// Mount whatever is on `dev` now.
fn remount(dev: &Arc<MemDisk<TaskList>>) -> Arc<F2fs> {
    let fresh = disk(&drain(dev));
    F2fs::open_with(fresh, "/dev/fake", true, Options::defaults()).expect("remount")
}

#[test]
fn a_fixture_image_mounts_through_the_interface() {
    let (fs, _dev) = mounted();
    assert!(fs.is_writable());
    assert_eq!(fs.source(), "/dev/fake");
    assert_eq!(vfs::fs::FileSystem::name(&*fs), F2FS_NAME);
    assert_eq!(vfs::fs::FileSystem::magic(&*fs), crate::uapi::F2FS_SUPER_MAGIC);
    assert_eq!(vfs::fs::FileSystem::block_size(&*fs), BS);
}

#[test]
fn a_mount_that_did_not_ask_to_write_is_not_writable() {
    let dev = disk(&test_image::with_root().finish());
    let fs = F2fs::open_with(dev, "/dev/fake", false, Options::defaults()).unwrap();
    assert!(!fs.is_writable());
}

#[test]
fn the_root_inode_is_a_directory() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    assert_eq!(root.file_type(), FileType::Directory);
    assert_eq!(root.ino(), u64::from(ROOT_INO));
}

#[test]
fn a_file_created_through_the_interface_is_found_again() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    let ctx = CreateCtx::root();
    let made = root.create_child("hello", 0o644, &ctx).unwrap();
    assert_eq!(made.file_type(), FileType::Regular);
    let found = root.lookup("hello").unwrap();
    assert_eq!(found.ino(), made.ino());
}

#[test]
fn a_missing_name_reports_no_entry() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    assert_eq!(root.lookup("absent").err(), Some(VfsError::Enoent));
}

#[test]
fn bytes_written_through_the_interface_read_back() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    let file = root.create_child("f", 0o644, &CreateCtx::root()).unwrap();
    assert_eq!(file.write(0, b"payload").unwrap(), 7);
    let mut buf = [0u8; 7];
    assert_eq!(file.read(0, &mut buf).unwrap(), 7);
    assert_eq!(&buf, b"payload");
    assert_eq!(file.size(), 7);
}

#[test]
fn a_write_survives_an_unmount_and_a_fresh_mount() {
    // The whole point of the adapter: state has to reach the DEVICE.
    let (fs, dev) = mounted();
    let root = fs.root_inode().unwrap();
    let file = root.create_child("f", 0o644, &CreateCtx::root()).unwrap();
    file.write(0, b"durable").unwrap();
    fs.super_ops().unwrap().put_super();
    let fs = remount(&dev);
    let root = fs.root_inode().unwrap();
    let found = root.lookup("f").unwrap();
    let mut buf = [0u8; 7];
    found.read(0, &mut buf).unwrap();
    assert_eq!(&buf, b"durable");
}

#[test]
fn an_unmount_without_a_sync_still_writes_a_checkpoint() {
    // Skipping this loses everything the mount did; the medium would still
    // describe the state it was mounted in.
    let (fs, dev) = mounted();
    let root = fs.root_inode().unwrap();
    root.create_child("kept", 0o644, &CreateCtx::root()).unwrap();
    fs.super_ops().unwrap().put_super();
    let fs = remount(&dev);
    let root = fs.root_inode().unwrap();
    assert!(root.lookup("kept").is_ok());
}

#[test]
fn a_sync_makes_a_change_durable_without_an_unmount() {
    let (fs, dev) = mounted();
    let root = fs.root_inode().unwrap();
    root.create_child("synced", 0o644, &CreateCtx::root()).unwrap();
    fs.super_ops().unwrap().sync_fs(true).unwrap();
    let fs = remount(&dev);
    let root = fs.root_inode().unwrap();
    assert!(root.lookup("synced").is_ok());
}

#[test]
fn fsync_makes_a_files_bytes_durable() {
    // Reporting success here while the data is only in memory is the one
    // failure a database cannot defend against.
    let (fs, dev) = mounted();
    let root = fs.root_inode().unwrap();
    let file = root.create_child("j", 0o644, &CreateCtx::root()).unwrap();
    file.write(0, b"committed").unwrap();
    let dentry = vfs::Dentry::new_root(file.clone());
    let f = File::new(file.clone(), dentry, OpenFlags::empty());
    crate::mount::ops::F2fsOps.fsync(&f, false).unwrap();
    let fs = remount(&dev);
    let root = fs.root_inode().unwrap();
    let found = root.lookup("j").unwrap();
    let mut buf = [0u8; 9];
    found.read(0, &mut buf).unwrap();
    assert_eq!(&buf, b"committed");
}

#[test]
fn a_directory_lists_its_own_stored_dots_exactly_once() {
    // The interface synthesises `.` and `..` for backends that lack them, so a
    // backend that stores them must say so or every listing shows them twice.
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    assert!(root.dir_emits_dots());
    let names = list(&root);
    assert_eq!(names.iter().filter(|n| *n == ".").count(), 1);
    assert_eq!(names.iter().filter(|n| *n == "..").count(), 1);
}

#[test]
fn a_listing_reports_what_was_created() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    let ctx = CreateCtx::root();
    root.create_child("one", 0o644, &ctx).unwrap();
    root.mkdir("two", 0o755, &ctx).unwrap();
    let names = list(&root);
    assert!(names.iter().any(|n| n == "one"));
    assert!(names.iter().any(|n| n == "two"));
    assert_eq!(names.len(), 4);
}

/// Every name a directory reports.
fn list(dir: &vfs::InodeRef) -> Vec<alloc::string::String> {
    struct Sink(Vec<alloc::string::String>);
    impl DirEmit for Sink {
        fn emit(&mut self, name: &str, _ino: u64, _t: FileType, _next: u64) -> bool {
            self.0.push(name.into());
            true
        }
    }
    let mut sink = Sink(Vec::new());
    let mut ctx = vfs::DirContext::new(0, &mut sink);
    dir.readdir(&mut ctx).unwrap();
    sink.0
}

#[test]
fn a_directory_removed_through_the_interface_is_gone() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    let ctx = CreateCtx::root();
    root.mkdir("d", 0o755, &ctx).unwrap();
    root.rmdir("d").unwrap();
    assert_eq!(root.lookup("d").err(), Some(VfsError::Enoent));
}

#[test]
fn removing_a_directory_that_holds_a_name_is_refused() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    let ctx = CreateCtx::root();
    let d = root.mkdir("d", 0o755, &ctx).unwrap();
    d.create_child("inside", 0o644, &ctx).unwrap();
    assert_eq!(root.rmdir("d").err(), Some(VfsError::Enotempty));
}

#[test]
fn a_symbolic_link_reads_its_target_back() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    let ctx = CreateCtx::root();
    root.symlink_child("l", b"/somewhere/else", &ctx).unwrap();
    let link = root.lookup("l").unwrap();
    assert_eq!(link.file_type(), FileType::Symlink);
    assert_eq!(link.readlink().unwrap(), b"/somewhere/else".to_vec());
}

#[test]
fn an_empty_link_target_is_refused() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    assert!(root.symlink_child("l", b"", &CreateCtx::root()).is_err());
}

#[test]
fn an_attribute_set_through_the_interface_reads_back() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    let file = root.create_child("f", 0o644, &CreateCtx::root()).unwrap();
    file.setxattr("user.k", b"v".to_vec(), false, false).unwrap();
    assert_eq!(file.getxattr("user.k").unwrap(), b"v".to_vec());
    assert_eq!(file.listxattr().unwrap(), ["user.k"]);
}

#[test]
fn statfs_reports_this_filesystem() {
    let (fs, _dev) = mounted();
    let st = fs.super_ops().unwrap().statfs().unwrap();
    assert_eq!(st.f_type, crate::uapi::F2FS_SUPER_MAGIC);
    assert_eq!(st.f_bsize, BS);
    assert_eq!(st.f_namelen, crate::limits::NAME_MAX);
    assert!(st.f_blocks > 0);
    assert!(st.f_bfree <= st.f_blocks);
    assert!(st.f_bavail <= st.f_bfree);
}

#[test]
fn statfs_free_space_falls_as_the_volume_fills() {
    let (fs, _dev) = mounted();
    let ops = fs.super_ops().unwrap();
    let root = fs.root_inode().unwrap();
    let file = root.create_child("big", 0o644, &CreateCtx::root()).unwrap();
    ops.sync_fs(true).unwrap();
    let before = ops.statfs().unwrap().f_bfree;
    file.write(0, &vec![1u8; 8 * BLKSIZE]).unwrap();
    ops.sync_fs(true).unwrap();
    assert!(ops.statfs().unwrap().f_bfree < before);
}

#[test]
fn the_option_tail_round_trips_and_names_this_filesystem() {
    let dev = disk(&test_image::with_root().finish());
    let opts = crate::opts::parse(Options::defaults(), "noacl,mode=lfs").unwrap();
    let fs = F2fs::open_with(dev, "/dev/fake", true, opts).unwrap();
    let shown = vfs::fs::FileSystem::show_options(&*fs);
    assert!(shown.contains(",noacl"));
    assert!(shown.contains(",mode=lfs"));
    assert_eq!(fs.super_ops().unwrap().show_options(), shown);
    assert!(crate::opts::parse(Options::defaults(), &shown).is_ok());
}

#[test]
fn a_read_only_mount_refuses_every_mutation() {
    let dev = disk(&test_image::with_root().finish());
    let fs = F2fs::open_with(dev, "/dev/fake", false, Options::defaults()).unwrap();
    let root = fs.root_inode().unwrap();
    let ctx = CreateCtx::root();
    assert_eq!(root.create_child("x", 0o644, &ctx).err(), Some(VfsError::Erofs));
    assert_eq!(root.mkdir("d", 0o755, &ctx).err(), Some(VfsError::Erofs));
    assert_eq!(root.unlink_child("x").err(), Some(VfsError::Erofs));
    assert_eq!(root.rmdir("x").err(), Some(VfsError::Erofs));
    assert!(root.symlink_child("l", b"t", &ctx).is_err());
}

#[test]
fn a_read_only_mount_still_reads_and_reports() {
    let dev = disk(&test_image::with_root().finish());
    let fs = F2fs::open_with(dev, "/dev/fake", false, Options::defaults()).unwrap();
    let root = fs.root_inode().unwrap();
    assert_eq!(list(&root).len(), 2);
    assert!(fs.super_ops().unwrap().statfs().is_ok());
    // Nothing is dirty, so an unmount has nothing to write and must not fail.
    fs.super_ops().unwrap().put_super();
}

#[test]
fn errno_translation_keeps_each_meaning() {
    use syscall::errno::Errno;
    assert_eq!(errno_to_vfs(Errno::Enoent), VfsError::Enoent);
    assert_eq!(errno_to_vfs(Errno::Erofs), VfsError::Erofs);
    assert_eq!(errno_to_vfs(Errno::Enotempty), VfsError::Enotempty);
    assert_eq!(errno_to_vfs(Errno::Eexist), VfsError::Eexist);
    assert_eq!(errno_to_vfs(Errno::Eopnotsupp), VfsError::Eopnotsupp);
    assert_eq!(errno_to_vfs(Errno::Enodata), VfsError::Enodata);
    assert_eq!(errno_to_vfs(Errno::Enospc), VfsError::Enospc);
    // Anything without a closer meaning is an I/O error, not a silent success.
    assert_eq!(errno_to_vfs(Errno::Eio), VfsError::Eio);
    assert_eq!(errno_to_vfs(Errno::Eagain), VfsError::Eio);
}
