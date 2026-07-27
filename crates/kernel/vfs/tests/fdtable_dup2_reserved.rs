use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use vfs::{Dentry, FdTable, File, FileType, InodeBuilder, InodeRef, OpenFlags, VfsError, default_file_ops, default_inode_ops, mk_mode};

static CLONE_CALLS: AtomicUsize = AtomicUsize::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn record_clone(_ino: &InodeRef, _writable: bool) {
    CLONE_CALLS.fetch_add(1, Ordering::AcqRel);
}

fn reset_clone_hook() {
    CLONE_CALLS.store(0, Ordering::Release);
    vfs::set_clone_hook(record_clone);
}

fn mk_inode(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

fn mk_file(ino: u64) -> Arc<File> {
    let inode = mk_inode(ino);
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&inode));
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

#[test]
fn dup2_reserved_target_returns_ebusy_without_installing() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_clone_hook();
    let t = FdTable::new();
    let old = t.alloc(mk_file(0x3320)).unwrap();
    let reserved = t.get_unused_fd_flags(OpenFlags::O_CLOEXEC, vfs::FD_TABLE_MAX).unwrap();

    assert_eq!(t.dup2(old, reserved), Err(VfsError::Ebusy));
    assert_eq!(t.get(reserved).unwrap_err(), VfsError::Ebadf);
    // `cloexec()` gates on `!is_reserved` (`c1582ede2` "retain canonical pid
    // identities" hardened this alongside `close_on_exec`'s reserved-skip): a
    // reserved-but-unpublished fd isn't a valid open descriptor yet, so it
    // reports Ebadf like every other query, not the flag it was reserved with.
    assert_eq!(t.cloexec(reserved), Err(VfsError::Ebadf));
    assert_eq!(CLONE_CALLS.load(Ordering::Acquire), 0);
    t.fd_install(reserved, mk_file(0x3321));
    assert!(t.get(reserved).is_ok());
}

#[test]
fn dup3_reserved_target_returns_ebusy_without_installing() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_clone_hook();
    let t = FdTable::new();
    let old = t.alloc(mk_file(0x3322)).unwrap();
    let reserved = t.get_unused_fd_flags(OpenFlags::empty(), vfs::FD_TABLE_MAX).unwrap();

    assert_eq!(t.dup3(old, reserved, OpenFlags::O_CLOEXEC), Err(VfsError::Ebusy));
    assert_eq!(t.get(reserved).unwrap_err(), VfsError::Ebadf);
    // Same reserved-fd gate as above — not yet a valid open descriptor.
    assert_eq!(t.cloexec(reserved), Err(VfsError::Ebadf));
    assert_eq!(CLONE_CALLS.load(Ordering::Acquire), 0);
    t.fd_install(reserved, mk_file(0x3323));
    assert!(t.get(reserved).is_ok());
}
