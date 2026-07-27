//! `install_open_at` owns the single Linux `do_dentry_open` / `vfs_open`
//! `f_op->open` call. Syscall layers must not pre-call `inode->i_fop->open`.

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};

use vfs::{Dentry, FdTable, File, FileOps, FileType, InodeBuilder, KResult, OpenFlags, VfsError, default_inode_ops, mk_mode};

static OPEN_CALLS: AtomicUsize = AtomicUsize::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());

struct CountOpenOps;

impl FileOps for CountOpenOps {
    fn on_open_file(&self, file: &File) -> KResult<()> {
        assert!(!file.f_mode().contains(vfs::Fmode::PATH));
        OPEN_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn install_open_at_runs_file_open_hook_once() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    OPEN_CALLS.store(0, Ordering::SeqCst);
    let fdt = FdTable::new();
    let inode = InodeBuilder::new(0x7210, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(CountOpenOps)).build();
    let dentry = Dentry::new_root(Arc::clone(&inode));

    let fd = vfs::file::install_open_at(&fdt, inode, dentry, OpenFlags::O_RDONLY,
        0, vfs::FileCred::root(), usize::MAX, None).unwrap();

    assert_eq!(fd, 0);
    assert_eq!(OPEN_CALLS.load(Ordering::SeqCst), 1);
    assert!(fdt.get(fd).is_ok());
}

#[test]
fn install_open_at_skips_open_hook_for_opath() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    OPEN_CALLS.store(0, Ordering::SeqCst);
    let fdt = FdTable::new();
    let inode = InodeBuilder::new(0x7211, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(CountOpenOps)).build();
    let dentry = Dentry::new_root(Arc::clone(&inode));

    let fd = vfs::file::install_open_at(&fdt, inode, dentry, OpenFlags::O_PATH,
        0, vfs::FileCred::root(), usize::MAX, None).unwrap();

    assert_eq!(fd, 0);
    assert_eq!(OPEN_CALLS.load(Ordering::SeqCst), 0);
    assert!(fdt.get(fd).unwrap().f_mode().contains(vfs::Fmode::PATH));
}

#[test]
fn install_open_at_returns_truncate_error_before_fd_install() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    OPEN_CALLS.store(0, Ordering::SeqCst);
    let fdt = FdTable::new();
    let inode = InodeBuilder::new(0x7212, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(CountOpenOps)).build();
    let dentry = Dentry::new_root(Arc::clone(&inode));

    let err = vfs::file::install_open_at(&fdt, inode, dentry,
        OpenFlags::O_WRONLY | OpenFlags::O_TRUNC, 0, vfs::FileCred::root(), usize::MAX, None);

    assert_eq!(err, Err(VfsError::Erofs));
    assert_eq!(OPEN_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(fdt.count(), 0);
}

#[test]
fn install_open_at_ignores_truncate_for_char_device() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    OPEN_CALLS.store(0, Ordering::SeqCst);
    let fdt = FdTable::new();
    let inode = InodeBuilder::new(0x7214, mk_mode(FileType::CharDev, 0o666),
        default_inode_ops(), Arc::new(CountOpenOps)).build();
    let dentry = Dentry::new_root(Arc::clone(&inode));

    let fd = vfs::file::install_open_at(&fdt, inode, dentry,
        OpenFlags::O_WRONLY | OpenFlags::O_TRUNC, 0, vfs::FileCred::root(), usize::MAX, None)
        .expect("O_TRUNC must not truncate a character device");

    assert_eq!(fd, 0);
    assert_eq!(OPEN_CALLS.load(Ordering::SeqCst), 1);
    assert!(fdt.get(fd).is_ok());
}

#[test]
fn install_open_at_emfile_precedes_open_and_truncate_side_effects() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    OPEN_CALLS.store(0, Ordering::SeqCst);
    let fdt = FdTable::new();
    let inode = InodeBuilder::new(0x7213, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(CountOpenOps)).build();
    let dentry = Dentry::new_root(Arc::clone(&inode));

    let err = vfs::file::install_open_at(&fdt, inode, dentry,
        OpenFlags::O_WRONLY | OpenFlags::O_TRUNC, 0, vfs::FileCred::root(), 0, None);

    assert_eq!(err, Err(VfsError::Emfile));
    assert_eq!(OPEN_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(fdt.count(), 0);
}
