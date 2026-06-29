//! mount/D25 (two-sources-of-root-truth), consistency validation.
//!
//! Linux defines a namespace root mount solely by `mnt_parent == self`. This
//! engine encodes root-ness THREE ways — (a) `root_mount_id(ns) == mnt_id`
//! (`MntNamespace.root`), (b) `mountpoint() == None`, (c) self-parent
//! `parent_id == mnt_id`. The ledger flags that these "can disagree". They
//! cannot, in practice: `attach` (the only root-mount constructor) sets all
//! three atomically, and `copy_mnt_ns` reproduces the same triple per cloned
//! root. This test pins that the three encodings stay MUTUALLY CONSISTENT for a
//! freshly attached root mount and for a non-root mount (where all three say
//! "not root"), so a future change cannot let them drift apart silently.
//! Process-global table → SERIAL-guarded; each test uses its own ns id.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());
static CUR_NS: AtomicU64 = AtomicU64::new(0);
fn ns_provider() -> u64 { CUR_NS.load(Ordering::Relaxed) }
fn guard(ns: u64) -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    CUR_NS.store(ns, Ordering::Relaxed);
    vfs::mount::set_current_ns_provider(ns_provider);
    common::install();
    g
}

struct TDir { ino: u64 }
impl Inode for TDir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
struct RFs { ino: u64 }
impl FileSystem for RFs {
    fn name(&self) -> &str { "rfs" }
    fn root(&self) -> Option<InodeRef> { Some(Arc::new(TDir { ino: self.ino })) }
}

/// All three root-truth encodings agree for a freshly attached root mount.
#[test]
fn root_mount_three_encodings_agree() {
    let _g = guard(0x2501);
    // Attach the ns root mount (mp == "/" => None inside attach).
    common::register("/", Arc::new(RFs { ino: 0xA0 })).expect("attach root");

    let rid = vfs::mount::root_mount_id(0x2501).expect("ns has a root mount");
    let m = vfs::mount::mount_by_id(rid).expect("root mount object");

    // (a) MntNamespace.root == this mount's id (tautology of how we fetched it).
    assert_eq!(m.mnt_id, rid, "(a) root_mount_id names this mount");
    // (b) mountpoint() is None for a root mount.
    assert!(m.mountpoint().is_none(), "(b) a root mount has no mountpoint dentry");
    // (c) self-parent: parent_id == mnt_id.
    assert_eq!(vfs::mount::parent_mnt_id(&m), m.mnt_id, "(c) root is its own parent");
    // The convenience predicate agrees with all three.
    assert!(m.is_root(), "Mount::is_root agrees with the root-id encoding");
}

/// A non-root mount fails ALL three root predicates — they agree negatively too.
#[test]
fn non_root_mount_is_not_root_by_any_encoding() {
    let _g = guard(0x2502);
    common::register("/", Arc::new(RFs { ino: 0x90 })).expect("attach root");
    common::register("/sub", Arc::new(RFs { ino: 0x91 })).expect("attach sub");

    let rid = vfs::mount::root_mount_id(0x2502).expect("root");
    let sub = common::mount_at_path_exact("/sub").expect("sub mount");

    assert_ne!(sub.mnt_id, rid, "(a) sub is not the ns root id");
    assert!(sub.mountpoint().is_some(), "(b) a non-root mount HAS a mountpoint dentry");
    assert_ne!(vfs::mount::parent_mnt_id(&sub), sub.mnt_id, "(c) sub is not self-parented");
    assert!(!sub.is_root(), "Mount::is_root is false for a non-root mount");
}
