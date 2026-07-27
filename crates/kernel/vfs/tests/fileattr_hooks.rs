use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use vfs::inode::{FileAttr, Inode, FS_APPEND_FL};
use vfs::inode_ops::InodeOps;
use vfs::{
    Cred, FileAttrSource, FileType, InodeBuilder, InodeRef, KResult, VfsError,
    clear_fileattr_hooks, default_file_ops, fileattr_get, fileattr_set, mk_mode,
    set_fileattr_hooks,
};

static TEST_LOCK: Mutex<()> = Mutex::new(());
static GETS: AtomicUsize = AtomicUsize::new(0);
static SETS: AtomicUsize = AtomicUsize::new(0);
static NOTIFIES: AtomicUsize = AtomicUsize::new(0);

struct AttrOps;
impl InodeOps for AttrOps {
    fn fileattr_get(&self, _inode: &Inode) -> KResult<FileAttr> {
        GETS.fetch_add(1, Ordering::SeqCst);
        Ok(FileAttr::default())
    }

    fn fileattr_set(&self, _inode: &Inode, _fa: &FileAttr) -> KResult<()> {
        SETS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn inode() -> InodeRef {
    InodeBuilder::new(0xFA41, mk_mode(FileType::Regular, 0o644), Arc::new(AttrOps), default_file_ops())
        .owner(0, 0).build()
}

fn reset() {
    GETS.store(0, Ordering::SeqCst);
    SETS.store(0, Ordering::SeqCst);
    NOTIFIES.store(0, Ordering::SeqCst);
    clear_fileattr_hooks();
}

fn deny_get(_inode: &InodeRef) -> KResult<()> { Err(VfsError::Eperm) }
fn deny_set(_inode: &InodeRef, _fa: &FileAttr) -> KResult<()> { Err(VfsError::Eperm) }
fn notify(_inode: &InodeRef) { NOTIFIES.fetch_add(1, Ordering::SeqCst); }

#[test]
fn security_getattr_runs_before_backend_get() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    set_fileattr_hooks(Some(deny_get), None, None);
    let node = inode();
    assert_eq!(fileattr_get(&node), Err(VfsError::Eperm));
    assert_eq!(GETS.load(Ordering::SeqCst), 0, "security denial blocks backend get");
    reset();
}

#[test]
fn security_setattr_runs_before_backend_set_and_notify() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    set_fileattr_hooks(None, Some(deny_set), Some(notify));
    let node = inode();
    let want = FileAttr { flags: FS_APPEND_FL, ..Default::default() };
    assert_eq!(
        fileattr_set(&vfs::idmap::Idmap::identity(), &node, want, FileAttrSource::Flags,
            &Cred::root(), true, true),
        Err(VfsError::Eperm));
    assert_eq!(SETS.load(Ordering::SeqCst), 0, "security denial blocks backend set");
    assert_eq!(NOTIFIES.load(Ordering::SeqCst), 0, "failed set does not notify");
    reset();
}

#[test]
fn successful_set_notifies_after_backend_set() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    set_fileattr_hooks(None, None, Some(notify));
    let node = inode();
    let want = FileAttr::default();
    assert_eq!(
        fileattr_set(&vfs::idmap::Idmap::identity(), &node, want, FileAttrSource::Flags,
            &Cred::root(), false, true),
        Ok(()));
    assert_eq!(SETS.load(Ordering::SeqCst), 1, "backend set ran once");
    assert_eq!(NOTIFIES.load(Ordering::SeqCst), 1, "successful set fires fsnotify_xattr hook");
    reset();
}
