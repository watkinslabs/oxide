//! dcache-D20: per-dentry `d_seq` seqcount (Linux `dentry->d_seq`) guards the
//! `d_parent`/`d_name` binding against a concurrent `d_move` (rename) during a
//! lock-free walk. A reader snapshots `read_seqbegin`, reads name/parent, then
//! `read_seqretry`; a `d_move` brackets its rehome in `seq_write_begin/end`, so
//! the reader observes the change and retries instead of trusting a stale name.

use std::sync::Arc;

use vfs::dcache::{d_add, d_move};
use vfs::dentry::Dentry;
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

struct Dir { ino: u64 }
impl Inode for Dir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn dir(ino: u64) -> InodeRef { Arc::new(Dir { ino }) }
fn root() -> Arc<Dentry> { Dentry::new_root(dir(1)) }

#[test]
fn d_seq_starts_even_and_stable() {
    let d = root();
    let s = d.read_seqbegin();
    assert_eq!(s & 1, 0, "fresh dentry seqcount is even (quiescent)");
    assert!(!d.read_seqretry(s), "no writer raced — read is valid");
}

#[test]
fn write_window_is_odd_then_even_new_generation() {
    let d = root();
    let before = d.d_seq();
    d.seq_write_begin();
    assert_eq!(d.d_seq() & 1, 1, "inside the write window d_seq is odd");
    d.seq_write_end();
    assert_eq!(d.d_seq() & 1, 0, "after the write window d_seq is even");
    assert_ne!(d.d_seq(), before, "a new generation — readers must retry");
}

#[test]
fn d_move_makes_reader_retry() {
    let r = root();
    let p2 = d_add(&r, "dst", dir(20));
    let child = d_add(&r, "old", dir(21));
    // A walker snapshots `child`'s seqcount before the rename.
    let snap = child.read_seqbegin();
    assert!(!child.read_seqretry(snap), "stable before the move");
    // Rename it elsewhere.
    let _moved = d_move(&child, &p2, "new");
    // The pre-move reader now detects the rename and must re-walk.
    assert!(child.read_seqretry(snap), "d_move advanced d_seq — reader retries");
    // The dentry settles back to an even quiescent state.
    let snap2 = child.read_seqbegin();
    assert!(!child.read_seqretry(snap2), "stable after the move completes");
}
