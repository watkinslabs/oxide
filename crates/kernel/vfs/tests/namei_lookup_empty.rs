//! LOOKUP_EMPTY (Linux `AT_EMPTY_PATH`, fix-ledger namei D18): an empty
//! pathname is `ENOENT` unless LOOKUP_EMPTY is set, in which case the walk
//! operates on the dirfd/cwd base itself. First-class engine flag replacing the
//! per-`*at`-handler AT_EMPTY_PATH gate. Drives the real `vfs::path_lookup`
//! walker over a synthetic inode tree (`docs/16§3`).

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

// /            (ino 2) → a
// /a           (ino 10) → leaf(file 21)
fn build_root() -> Arc<Dentry> {
    let a = dir(10, &[("leaf", file(21))]);
    Dentry::new_root(dir(2, &[("a", a)]))
}
fn empty() -> LookupFlags { let mut f = LookupFlags::default(); f.empty = true; f }

// Without LOOKUP_EMPTY an empty pathname is ENOENT (Linux default).
#[test]
fn empty_path_without_flag_is_enoent() {
    let root = build_root();
    assert_eq!(vfs::path_lookup(root.clone(), root.clone(), "", LookupFlags::default()).err(),
        Some(VfsError::Enoent), "empty path without LOOKUP_EMPTY → ENOENT");
}

// WITH LOOKUP_EMPTY an empty pathname resolves to the START (dirfd) itself.
#[test]
fn empty_path_with_flag_resolves_dirfd() {
    let root = build_root();
    // Use a non-root dirfd to prove the empty walk returns the START base,
    // not the resolution root: start = /a, empty path → /a (ino 10).
    let (_, a_dentry) = vfs::path_lookup(root.clone(), root.clone(), "/a", LookupFlags::default())
        .expect("/a resolves");
    let (i, d) = vfs::path_lookup(a_dentry.clone(), root.clone(), "", empty())
        .expect("empty path with LOOKUP_EMPTY operates on the dirfd");
    assert_eq!(i.ino(), 10, "empty path with LOOKUP_EMPTY resolves to the dirfd inode");
    assert!(Arc::ptr_eq(&d, &a_dentry), "returns the dirfd dentry itself");
}

// LOOKUP_EMPTY is empty-only: a non-empty path is unaffected by the flag.
#[test]
fn nonempty_path_unaffected_by_flag() {
    let root = build_root();
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/a/leaf", empty())
        .expect("non-empty path still resolves normally with LOOKUP_EMPTY set");
    assert_eq!(i.ino(), 21);
}
