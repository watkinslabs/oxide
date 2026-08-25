use super::*;

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
    // Refusals a caller acts on. Each of these used to arrive as EIO, which
    // tells a program the disk failed: it retries, or reports a broken volume,
    // when what happened was a quota limit or a permission.
    assert_eq!(errno_to_vfs(Errno::Eperm), VfsError::Eperm);
    assert_eq!(errno_to_vfs(Errno::Eacces), VfsError::Eacces);
    assert_eq!(errno_to_vfs(Errno::Edquot), VfsError::Edquot);
    assert_eq!(errno_to_vfs(Errno::Emlink), VfsError::Emlink);
    assert_eq!(errno_to_vfs(Errno::Exdev), VfsError::Exdev);
    assert_eq!(errno_to_vfs(Errno::Ebusy), VfsError::Ebusy);
    assert_eq!(errno_to_vfs(Errno::Etxtbsy), VfsError::Etxtbsy);
    assert_eq!(errno_to_vfs(Errno::Eagain), VfsError::Eagain);
    assert_eq!(errno_to_vfs(Errno::Erange), VfsError::Erange);
    assert_eq!(errno_to_vfs(Errno::Eoverflow), VfsError::Eoverflow);
    assert_eq!(errno_to_vfs(Errno::Euclean), VfsError::Euclean);
    assert_eq!(errno_to_vfs(Errno::Enotty), VfsError::Enotty);
    assert_eq!(errno_to_vfs(Errno::Emsgsize), VfsError::Emsgsize);
    assert_eq!(errno_to_vfs(Errno::Eloop), VfsError::Eloop);
    // Anything without a closer meaning is an I/O error, not a silent success.
    assert_eq!(errno_to_vfs(Errno::Eio), VfsError::Eio);
    assert_eq!(errno_to_vfs(Errno::Enokey), VfsError::Enokey);
    assert_eq!(errno_to_vfs(Errno::Ekeyrejected), VfsError::Ekeyrejected);
    assert_eq!(errno_to_vfs(Errno::Ebadmsg), VfsError::Ebadmsg);
    assert_eq!(errno_to_vfs(Errno::Enopkg), VfsError::Enopkg);
}

// --------------------------------------------------------- freeze and thaw

/// The condition word's freezing bit, read through the volume the way every
/// reporting surface reads it. # C: O(1)
#[test]
fn freezing_a_clean_writable_mount_raises_the_mark_and_thawing_lowers_it() {
    let (fs, _dev) = mounted();
    assert!(!freezing(&fs), "a mount that was never frozen must not claim to be");
    vfs::superblock::SuperOps::freeze_fs(&crate::mount::sb::F2fsSuperOps { fs: fs.clone() }).expect("freeze");
    assert!(freezing(&fs), "a frozen volume has to say so, or nothing can tell");
    vfs::superblock::SuperOps::thaw_fs(&crate::mount::sb::F2fsSuperOps { fs: fs.clone() }).expect("thaw");
    assert!(!freezing(&fs));
}

#[test]
fn freezing_a_volume_still_dirty_is_refused_and_raises_nothing() {
    // The freeze syncs before it asks, so work left over means the sync did
    // not do what it promised — and sealing over it would name a state the
    // medium never held.
    let (fs, _dev) = mounted();
    let root = fs.root_inode().expect("root");
    root.create_child("pending", 0o644, &CreateCtx::root()).expect("create");
    assert!(fs.volume.lock().is_dirty(), "the fixture must leave work pending");
    assert_eq!(vfs::superblock::SuperOps::freeze_fs(&crate::mount::sb::F2fsSuperOps { fs: fs.clone() }).err(),
               Some(VfsError::Einval));
    assert!(!freezing(&fs), "a refused freeze leaves no mark behind");
}

#[test]
fn freezing_a_read_only_mount_does_nothing_and_says_so() {
    // It has no writes to stop and no mark to raise; refusing would make a
    // snapshot of a read-only mount impossible.
    let dev = disk(&test_image::with_root().finish());
    let fs = F2fs::open_with(dev, "/dev/fake", false, Options::defaults()).expect("mount");
    vfs::superblock::SuperOps::freeze_fs(&crate::mount::sb::F2fsSuperOps { fs: fs.clone() }).expect("freeze");
    assert!(!freezing(&fs));
}

// ---------------------------------------------- buffered writes, as the VFS
// sees them. The mount is what gives the mapping a way back to itself, and
// nothing below this file can prove that was done: a `Volume` on its own has
// no host, so its pages are placed only by its own flush points. These drive
// the real filesystem.

