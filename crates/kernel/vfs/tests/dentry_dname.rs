//! dcache-D22: pseudo dentries (`d_alloc_pseudo`) carry a `d_op->d_dname` hook
//! (Linux `dentry_operations::d_dname`) that renders their displayed path
//! dynamically — `pipe:[ino]` / `[eventfd]` — so `d_path`/`dentry_path` return
//! that verbatim instead of parent-walking a parentless pseudo dentry into a
//! bogus `/eventfd`. Also asserts the `D_OP_DNAME` presence bit is stamped and
//! that ordinary dentries (no `d_dname`) still reconstruct by the parent walk.

use std::sync::Arc;

use vfs::dcache::d_alloc_pseudo;
use vfs::dentry::{Dentry, DentryOps, D_OP_DNAME};
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

struct PInode { ino: u64, ft: FileType }
impl Inode for PInode {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { self.ft }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}
fn fifo(ino: u64) -> InodeRef { Arc::new(PInode { ino, ft: FileType::Fifo }) }
fn reg(ino: u64) -> InodeRef { Arc::new(PInode { ino, ft: FileType::Regular }) }

// pipefs `pipe:[%lu]` — renders the whole path from the inode number.
fn pipe_dname(d: &Dentry) -> String {
    let ino = d.inode().map(|i| i.ino()).unwrap_or(0);
    format!("pipe:[{ino}]")
}
static PIPE_OPS: DentryOps = DentryOps {
    d_dname: Some(pipe_dname),
    d_hash: None, d_compare: None, d_revalidate: None, d_delete: None, d_release: None, d_iput: None,
};

#[test]
fn pseudo_dentry_stamps_op_dname_presence_bit() {
    let d = d_alloc_pseudo("pipe", fifo(1234), &PIPE_OPS);
    assert_ne!(d.flags() & D_OP_DNAME, 0, "D_OP_DNAME stamped from d_set_d_op");
    assert!(d.d_has_op_dname(), "presence helper agrees");
    // Pseudo dentries are parentless and unhashed (no (parent,name) key).
    assert!(d.parent().is_none(), "pseudo dentry is parentless");
    assert!(d.is_unhashed(), "pseudo dentry not in the global hash table");
}

#[test]
fn d_dname_drives_absolute_and_dentry_path() {
    let d = d_alloc_pseudo("pipe", fifo(1234), &PIPE_OPS);
    assert_eq!(d.d_dname().as_deref(), Some("pipe:[1234]"));
    // d_path / __dentry_path consult d_dname instead of walking to "/pipe".
    assert_eq!(d.absolute_path(), b"pipe:[1234]".to_vec());
    assert_eq!(d.dentry_path(None), "pipe:[1234]");
}

#[test]
fn ordinary_dentry_has_no_d_dname_and_parent_walks() {
    // No d_op → no d_dname → ordinary reconstruction (and no presence bit).
    let root = Dentry::new(None, String::from(""), reg(1));
    let child = Dentry::new(Some(root), String::from("file"), reg(2));
    assert_eq!(child.flags() & D_OP_DNAME, 0);
    assert!(!child.d_has_op_dname());
    assert!(child.d_dname().is_none(), "ordinary dentry renders no dynamic name");
    assert_eq!(child.absolute_path(), b"/file".to_vec());
}
