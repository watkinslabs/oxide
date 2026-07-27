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

fn mk_inode() -> InodeRef {
    InodeBuilder::new(0x1, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

fn mk_file() -> Arc<File> {
    let ino: InodeRef = mk_inode();
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::O_RDWR)
}

/// Failed dup/F_DUPFD allocations must not announce a new fd-table
/// reference. Linux drops the temporary fget/get_file reference on failure;
/// clone-hook accounting is for successful descriptor installs only.
#[test]
fn failed_dup_allocation_does_not_fire_clone_hook() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_clone_hook();
    let t = FdTable::new();
    let fd = t.alloc(mk_file()).unwrap();
    assert_eq!(t.dup_limit(fd, 1), Err(VfsError::Emfile));
    assert_eq!(t.dup_min_limit(fd, 1, 1), Err(VfsError::Einval));
    assert_eq!(CLONE_CALLS.load(Ordering::Acquire), 0);
    assert_eq!(t.dup_limit(fd, 2), Ok(1));
    assert_eq!(CLONE_CALLS.load(Ordering::Acquire), 1);
}

#[test]
fn dup2_and_dup3_fire_clone_hook_once_per_successful_install() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_clone_hook();
    let t = FdTable::new();
    let old = t.alloc(mk_file()).unwrap();
    let victim = t.alloc(mk_file()).unwrap();

    assert_eq!(t.dup2(old, victim), Ok(victim));
    assert_eq!(CLONE_CALLS.load(Ordering::Acquire), 1);
    assert_eq!(t.dup3(old, victim + 1, OpenFlags::O_CLOEXEC), Ok(victim + 1));
    assert_eq!(CLONE_CALLS.load(Ordering::Acquire), 2);
    assert_eq!(t.dup3(old, old, OpenFlags::empty()), Err(VfsError::Einval));
    assert_eq!(CLONE_CALLS.load(Ordering::Acquire), 2);
}
