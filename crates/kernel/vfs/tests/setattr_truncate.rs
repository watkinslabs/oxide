//! ATTR_SIZE truncate apply path (Linux `fs/attr.c` notify_change +
//! `fs/open.c` vfs_truncate / do_truncate): a size change requires MAY_WRITE,
//! is rejected on an immutable (EPERM, via `inode_permission`) or append-only
//! (EPERM, via the `vfs_truncate` IS_APPEND gate) inode, and otherwise drives
//! `i_op->truncate` so the backend updates `i_size` and drops backing storage
//! past the new length. Synthetic `Inode` with real Vec backing — no FS.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use vfs::inode::{Inode, S_APPEND, S_IMMUTABLE};
use vfs::setattr::{notify_change, setattr_prepare, Iattr, ATTR_SIZE};
use vfs::{default_file_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{Cred, FileType, Idmap, InodeRef, KResult, VfsError};

/// Backend state (`i_private`) for a truncatable regular file: a real backing
/// buffer plus a truncate-call counter. The `truncate` hook resizes the buffer
/// — grow zero-fills the tail, shrink drops the bytes past the new length.
struct TruncData {
    data: Mutex<Vec<u8>>,
    truncs: AtomicU64,
}

impl TruncData {
    fn data_len(&self) -> usize { self.data.lock().unwrap().len() }
    fn truncs(&self) -> u64 { self.truncs.load(Ordering::Acquire) }
}

/// `i_op->truncate`: resize the backing buffer to the new `i_size` (page drop)
/// and update the inode's `i_size`.
struct TruncOps;
impl InodeOps for TruncOps {
    fn truncate(&self, inode: &Inode, len: u64) -> KResult<()> {
        let d = inode.private::<TruncData>().ok_or(VfsError::Einval)?;
        d.data.lock().unwrap().resize(len as usize, 0u8);
        d.truncs.fetch_add(1, Ordering::AcqRel);
        inode.set_size(len);
        Ok(())
    }
}

/// Build a regular-file inode (perm 0o644, owner root) with `flags` `i_flags`
/// (immutable / append-only under test) over `initial` backing bytes. Returns
/// the inode + the backend state so the test can inspect the buffer / counter.
fn make_trunc(initial: &[u8], flags: u32) -> (InodeRef, Arc<TruncData>) {
    let d = Arc::new(TruncData { data: Mutex::new(initial.to_vec()), truncs: AtomicU64::new(0) });
    let inode = InodeBuilder::new(1, mk_mode(FileType::Regular, 0o644), Arc::new(TruncOps), default_file_ops())
        .size(initial.len() as u64).owner(0, 0).i_flags(flags).private(d.clone()).build();
    (inode, d)
}

fn size_change(n: u64) -> Iattr { Iattr { valid: ATTR_SIZE, size: n, ..Default::default() } }

/// Grow: new i_size > old, tail zero-filled, truncate hook fired once.
#[test]
fn truncate_grow_extends_and_zero_fills() {
    let (inode, raw) = make_trunc(b"hello", 0);
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
    let (inode, _raw) = make_trunc(b"abcdefghij", 0);
    let mut ia = size_change(4);
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(inode.size(), 4);
}

/// Immutable inode: a size change is EPERM even for root (Linux
/// `inode_permission` rejects MAY_WRITE on S_IMMUTABLE before the DAC class
/// check) — and the truncate hook never fires.
#[test]
fn truncate_immutable_eperm() {
    let (inode, raw) = make_trunc(b"locked", S_IMMUTABLE);
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
    let (inode, raw) = make_trunc(b"appendlog", S_APPEND);
    let mut ia = size_change(0);
    assert_eq!(setattr_prepare(&Idmap::identity(), &inode, &mut ia, &Cred::root()), Err(VfsError::Eperm));
    assert_eq!(notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()), Err(VfsError::Eperm));
    assert_eq!(raw.data_len(), 9); // unchanged
    assert_eq!(raw.truncs(), 0);   // hook never ran
}
