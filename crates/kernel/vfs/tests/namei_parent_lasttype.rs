//! LOOKUP_PARENT leaf classification (Linux `nd->last_type` as a string).
//! `path_parentat` stops before the final component and reports it in
//! `VfsPath.last_component`. The final segment must be reported VERBATIM —
//! including a trailing `.` (Linux `LAST_DOT`) and `..` (`LAST_DOTDOT`) — so a
//! caller can reject `rmdir("..")` / `unlink(".")` without re-parsing the path.
//!
//! Fails-before: a trailing `..` walked up and reported `last_component == None`;
//! a trailing `.` (dropped by the component splitter) reported the WRONG leaf
//! (the dir before it) with the wrong parent. Drives the real `vfs::path_lookup`
//! walker over a synthetic inode tree (no real filesystem).

use std::collections::BTreeMap;
use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{Dentry, FileType, InodeRef, LookupFlags, VfsError};

struct DirData { kids: BTreeMap<String, InodeRef> }
struct DirOps;
impl vfs::InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> vfs::KResult<InodeRef> {
        inode.private::<DirData>().unwrap().kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}


fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755),
        Arc::new(DirOps), vfs::default_file_ops())
        .private(Arc::new(DirData { kids: m })).build()
}
fn file(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Regular, 0o644),
        vfs::default_inode_ops(), vfs::default_file_ops()).build()
}

// Synthetic tree:
//   /            (ino 2)  → a, f(file 3)
//   /a           (ino 10) → b
//   /a/b         (ino 20) → leaf(file 21)
fn build_root() -> Arc<Dentry> {
    let b = dir(20, &[("leaf", file(21))]);
    let a = dir(10, &[("b", b)]);
    let root = dir(2, &[("a", a), ("f", file(3))]);
    Dentry::new_root(root)
}

fn parent_flags() -> LookupFlags { let mut f = LookupFlags::default(); f.parent = true; f }

// A normal leaf: parent is the dir containing it, leaf is the name (LAST_NORM).
#[test]
fn normal_leaf() {
    let root = build_root();
    let p = vfs::path_lookup_path(root.clone(), root, "/a/b/leaf", parent_flags()).expect("parent walk");
    assert_eq!(p.inode.ino(), 20, "parent is /a/b");
    assert_eq!(p.last_component.as_deref(), Some("leaf"), "leaf reported verbatim");
}

// Trailing `..`: parent is the dir the `..` resolves WITHIN (here /a/b), and the
// leaf is reported as `..` (Linux LAST_DOTDOT) instead of silently walking up.
#[test]
fn trailing_dotdot_reported_as_leaf() {
    let root = build_root();
    let p = vfs::path_lookup_path(root.clone(), root, "/a/b/..", parent_flags()).expect("parent walk ..");
    assert_eq!(p.last_component.as_deref(), Some(".."),
        "LOOKUP_PARENT reports a trailing `..` as the leaf (LAST_DOTDOT), not None");
    assert_eq!(p.inode.ino(), 20, "parent stays /a/b — the `..` is NOT applied in parent mode");
}

// Trailing `.`: the splitter drops `.`, so the parent is the fully-resolved dir
// (/a/b) and the leaf is restored to `.` (Linux LAST_DOT).
#[test]
fn trailing_dot_reported_as_leaf() {
    let root = build_root();
    let p = vfs::path_lookup_path(root.clone(), root, "/a/b/.", parent_flags()).expect("parent walk .");
    assert_eq!(p.last_component.as_deref(), Some("."),
        "LOOKUP_PARENT reports a trailing `.` as the leaf (LAST_DOT)");
    assert_eq!(p.inode.ino(), 20, "parent is the fully-resolved /a/b, not /a");
}

// `.` / `..` directly under the resolution root.
#[test]
fn dot_dotdot_at_root() {
    let root = build_root();
    let pd = vfs::path_lookup_path(root.clone(), root.clone(), "/.", parent_flags()).expect("/. parent");
    assert_eq!(pd.last_component.as_deref(), Some("."), "/. → leaf `.`");
    assert_eq!(pd.inode.ino(), 2, "/. parent is the root");

    let pdd = vfs::path_lookup_path(root.clone(), root, "/..", parent_flags()).expect("/.. parent");
    assert_eq!(pdd.last_component.as_deref(), Some(".."), "/.. → leaf `..`");
    assert_eq!(pdd.inode.ino(), 2, "/.. parent clamps at the root");
}

// Non-parent (full) resolution is UNCHANGED: `..` still walks up normally.
#[test]
fn non_parent_dotdot_unchanged() {
    let root = build_root();
    let (i, _) = vfs::path_lookup(root.clone(), root, "/a/b/..", LookupFlags::default())
        .expect("full walk ..");
    assert_eq!(i.ino(), 10, "full (non-parent) walk applies `..`: /a/b/.. → /a");
}
