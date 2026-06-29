//! ATTR_SIZE truncate apply path (Linux `fs/attr.c` notify_change +
//! `fs/open.c` vfs_truncate / do_truncate): a size change requires MAY_WRITE,
//! is rejected on an immutable (EPERM, via `inode_permission`) or append-only
//! (EPERM, via the `vfs_truncate` IS_APPEND gate) inode, and otherwise drives
//! `i_op->truncate` so the backend updates `i_size` and drops backing storage
//! past the new length. Synthetic `Inode` with real Vec backing — no FS.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use vfs::inode::{Inode, S_APPEND, S_IMMUTABLE};
use vfs::setattr::{notify_change, setattr_prepare, Iattr, ATTR_SIZE};
use vfs::{Cred, FileType, Idmap, InodeRef, KResult, VfsError};

/// Regular-file inode whose `truncate` hook resizes a real backing buffer:
/// grow zero-fills the tail, shrink drops the bytes past the new length —
/// exactly the page-drop a truncate must perform. `flags` carries the
/// `S_*` `i_flags` (immutable / append-only) under test.
struct TruncNode {
    data: Mutex<Vec<u8>>,
    flags: AtomicU32,
    perm: AtomicU32,
    truncs: AtomicU64,
}

impl TruncNode {
    fn new(initial: &[u8], flags: u32) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            data: Mutex::new(initial.to_vec()),
            flags: AtomicU32::new(flags),
            perm: AtomicU32::new(0o644),
            truncs: AtomicU64::new(0),
        })
    }
    fn data_len(&self) -> usize { self.data.lock().unwrap().len() }
    fn truncs(&self) -> u64 { self.truncs.load(Ordering::Acquire) }
}

impl Inode for TruncNode {
    fn ino(&self) -> vfs::Ino { 1 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { self.data.lock().unwrap().len() as u64 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn perm(&self) -> Option<u16> { Some(self.perm.load(Ordering::Acquire) as u16) }
    fn uid(&self) -> Option<u32> { Some(0) }
    fn gid(&self) -> Option<u32> { Some(0) }
    fn i_flags(&self) -> u32 { self.flags.load(Ordering::Acquire) }
    fn set_perm(&self, p: u16) -> KResult<()> { self.perm.store(p as u32, Ordering::Release); Ok(()) }
    fn truncate(&self, len: u64) -> KResult<()> {
        // Drop / extend the backing buffer to the new i_size (page drop).
        self.data.lock().unwrap().resize(len as usize, 0u8);
        self.truncs.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

fn size_change(n: u64) -> Iattr { Iattr { valid: ATTR_SIZE, size: n, ..Default::default() } }

/// Grow: new i_size > old, tail zero-filled, truncate hook fired once.
#[test]
fn truncate_grow_extends_and_zero_fills() {
    let raw = TruncNode::new(b"hello", 0);
    let inode: InodeRef = raw.clone();
    let mut ia = size_change(100);
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(inode.size(), 100);
    assert_eq!(raw.data.lock().unwrap()[..5], b"hello"[..]); // head preserved
    assert!(raw.data.lock().unwrap()[5..].iter().all(|&b| b == 0)); // tail zeroed
    assert_eq!(raw.truncs(), 1);
}

/// Shrink: new i_size < old, bytes past the new length dropped.
#[test]
fn truncate_shrink_drops_pages() {
    let inode: InodeRef = TruncNode::new(b"abcdefghij", 0);
    let mut ia = size_change(4);
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(inode.size(), 4);
}

/// Immutable inode: a size change is EPERM even for root (Linux
/// `inode_permission` rejects MAY_WRITE on S_IMMUTABLE before the DAC class
/// check) — and the truncate hook never fires.
#[test]
fn truncate_immutable_eperm() {
    let raw = TruncNode::new(b"locked", S_IMMUTABLE);
    let inode: InodeRef = raw.clone();
    let mut ia = size_change(0);
    assert_eq!(setattr_prepare(&Idmap::identity(), &inode, &mut ia, &Cred::root()), Err(VfsError::Eperm));
    assert_eq!(notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()), Err(VfsError::Eperm));
    assert_eq!(raw.data_len(), 6); // unchanged
    assert_eq!(raw.truncs(), 0);   // hook never ran
}

/// Append-only inode: a size change is EPERM even for root (Linux
/// `vfs_truncate` IS_APPEND gate) — MAY_WRITE alone passes, so this is the
/// dedicated S_APPEND reject. The hook never fires.
#[test]
fn truncate_append_only_eperm() {
    let raw = TruncNode::new(b"appendlog", S_APPEND);
    let inode: InodeRef = raw.clone();
    let mut ia = size_change(0);
    assert_eq!(setattr_prepare(&Idmap::identity(), &inode, &mut ia, &Cred::root()), Err(VfsError::Eperm));
    assert_eq!(notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()), Err(VfsError::Eperm));
    assert_eq!(raw.data_len(), 9); // unchanged
    assert_eq!(raw.truncs(), 0);   // hook never ran
}
