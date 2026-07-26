//! SCM_RIGHTS receive publication: reserve one fd under RLIMIT_NOFILE,
//! copy its number to userspace, then install the file. A copy fault rolls
//! back only that reservation; descriptors published by earlier calls stay live.

use std::sync::Arc;

use vfs::{Dentry, FdTable, File, FileType, InodeBuilder, InodeRef, OpenFlags, VfsError};
use vfs::{default_file_ops, default_inode_ops, mk_mode};

fn mk_file(ino: u64) -> Arc<File> {
    let inode: InodeRef = InodeBuilder::new(
        ino,
        mk_mode(FileType::Regular, 0o644),
        default_inode_ops(),
        default_file_ops(),
    ).build();
    let dentry = Dentry::new(None, "scm-rights".into(), Arc::clone(&inode));
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

#[test]
fn scm_install_copies_number_before_cloexec_install() {
    let t = FdTable::new();
    let file = mk_file(0x5343_4d01);
    let mut copied = None;

    let fd = t.scm_install_fd(file, OpenFlags::O_CLOEXEC, 1, |reserved| {
        copied = Some(reserved);
        assert_eq!(t.get(reserved).err(), Some(VfsError::Ebadf));
        // `cloexec()` gates on `!is_reserved` — a reserved-but-uninstalled fd
        // reports Ebadf, same as `get()`, not the flag it was reserved with.
        assert_eq!(t.cloexec(reserved), Err(VfsError::Ebadf));
        Ok(())
    }).unwrap();

    assert_eq!(fd, 0);
    assert_eq!(copied, Some(fd));
    assert!(t.get(fd).is_ok());
    assert_eq!(t.cloexec(fd), Ok(true));
    assert_eq!(t.scm_install_fd(mk_file(0x5343_4d02), OpenFlags::empty(), 1, |_| Ok(())), Err(VfsError::Emfile));
}

#[test]
fn scm_copy_fault_rolls_back_only_current_reservation() {
    let t = FdTable::new();
    let first = t.scm_install_fd(mk_file(0x5343_4d03), OpenFlags::empty(), 2, |_| Ok(())).unwrap();
    let faulted = t.scm_install_fd(mk_file(0x5343_4d04), OpenFlags::O_CLOEXEC, 2, |fd| {
        assert_eq!(fd, 1);
        assert_eq!(t.get(fd).err(), Some(VfsError::Ebadf));
        Err(VfsError::Efault)
    });

    assert_eq!(faulted, Err(VfsError::Efault));
    assert!(t.get(first).is_ok(), "an earlier published fd survives a later copy fault");
    let reused = t.scm_install_fd(mk_file(0x5343_4d05), OpenFlags::empty(), 2, |_| Ok(())).unwrap();
    assert_eq!(reused, 1, "the faulted call releases its own reservation");
    assert_eq!(t.cloexec(reused), Ok(false), "rollback clears reserve-time CLOEXEC");
}

#[test]
fn put_unused_fd_does_not_remove_published_descriptor() {
    let t = FdTable::new();
    let fd = t.scm_install_fd(mk_file(0x5343_4d06), OpenFlags::empty(), 1, |_| Ok(())).unwrap();

    t.put_unused_fd(fd);

    assert!(t.get(fd).is_ok());
    assert_eq!(t.count(), 1);
}
