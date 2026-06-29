//! file-D10: `open_dentry` (the `f->f_path.dentry` builder used by
//! `install_open`) must hand the fd the CANONICAL, HASHED dcache node for the
//! opened path — the exact `(parent,name)` object already in the global
//! `dentry_hashtable` — NOT a fresh, unhashed `Dentry::new_child` Arc fabricated
//! per open. Two opens of the same path therefore share ONE dentry object, and
//! `d_lookup(parent, name)` returns that same object, so a wired
//! `d_move`/`d_drop`/rename reaches the open fd's dentry (Linux: the open holds
//! a `dget`'d hashed dentry). Before 6326681e/099d16ca `open_dentry` returned a
//! detached per-open Arc, so the two opens diverged and `d_lookup` could not
//! find the leaf — this test fails on that shape.
//!
//! Touches the GLOBAL dentry hashtable (and the fixture root-dentry provider),
//! so it is SERIAL-guarded and installs the fixture on entry.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::file::open_dentry;
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

mod common;

/// Serializes against the shared dentry hashtable / LRU touched by every
/// `open_dentry` (d_lookup/d_add) and `Dentry` drop (dput).
static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0);
    common::install();
    g
}

/// Minimal regular-file inode for the opened leaf. `open_dentry` only needs a
/// type + ino to instantiate the positive dentry.
struct RegFile(u64);
impl Inode for RegFile {
    fn ino(&self) -> vfs::Ino { self.0 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _off: u64, _buf: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn write(&self, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
}

/// Two opens of the same path resolve to ONE canonical dentry Arc, and that
/// object is the one cached in the global hash (`d_lookup` finds it from the
/// resolved parent). The leaf is positive (carries the opened inode).
#[test]
fn two_opens_share_canonical_hashed_leaf() {
    let _g = guard();
    let ino_a: InodeRef = Arc::new(RegFile(0xA10));
    let ino_b: InodeRef = Arc::new(RegFile(0xB20));

    let d1 = open_dentry("/a/b/c", &ino_a);
    let d2 = open_dentry("/a/b/c", &ino_b);
    assert!(Arc::ptr_eq(&d1, &d2),
        "two opens of the same path must share ONE canonical dentry, not two detached Arcs");

    // The leaf is the object hashed under (parent, name): d_lookup from the
    // resolved parent returns the SAME Arc the open handed out.
    let parent = vfs::resolve_path_dentry("/a/b").expect("parent /a/b resolves via dcache walk");
    let looked = vfs::d_lookup(&parent, "c").expect("opened leaf is hashed → findable by d_lookup");
    assert!(Arc::ptr_eq(&looked, &d1),
        "d_lookup(parent,name) must return the very dentry the open interned");
    assert!(!looked.is_negative(), "opened leaf is a POSITIVE dentry (carries the inode)");
    assert!(looked.inode().is_some(), "positive leaf exposes its inode");
}

/// The interned leaf is parented (its name is the basename), so the cached node
/// is a real child of its directory — not a whole-path-in-one-name blob.
#[test]
fn opened_leaf_is_parented_basename() {
    let _g = guard();
    let ino: InodeRef = Arc::new(RegFile(0xC30));
    let d = open_dentry("/x/y/leaf", &ino);
    assert_eq!(d.name(), "leaf", "leaf dentry name is the basename, not the whole path");
    let parent = vfs::resolve_path_dentry("/x/y").expect("parent resolves");
    assert!(vfs::d_lookup(&parent, "leaf").is_some(), "leaf is hashed under its real parent");
}

/// Opening the root path reuses the one canonical root dentry rather than
/// fabricating a fresh empty-name node each time.
#[test]
fn root_open_reuses_canonical_root() {
    let _g = guard();
    let ino: InodeRef = Arc::new(RegFile(0xD40));
    let root = vfs::resolve_path_dentry("/").expect("root dentry exists");
    let d = open_dentry("/", &ino);
    assert!(Arc::ptr_eq(&d, &root), "open of \"/\" reuses the canonical root dentry");
}
