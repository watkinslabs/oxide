//! Linux `nd->last_type` classification of a LOOKUP_PARENT leaf
//! (`VfsPath::last_type`, fix-ledger namei D16/D1). The walker reports the leaf
//! VERBATIM in `last_component`; `last_type()` maps it to the Linux enum so a
//! caller can reject the dot-forms (`rmdir(".")`→EINVAL, `rmdir("..")`→ENOTEMPTY,
//! root→EBUSY) without re-parsing. Drives the real `vfs::path_lookup_path`
//! parent walk over a synthetic inode tree.

use std::collections::BTreeMap;
use std::sync::Arc;

use vfs::inode::Inode;
use vfs::namei::LastType;
use vfs::{Dentry, FileType, InodeRef, LookupFlags, VfsError};

struct Dir { ino: u64, kids: BTreeMap<String, InodeRef> }
impl Inode for Dir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> vfs::KResult<InodeRef> {
        self.kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}
struct F { ino: u64 }
impl Inode for F {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> vfs::KResult<InodeRef> { Err(VfsError::Enotdir) }
}
fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    Arc::new(Dir { ino, kids: m })
}
fn file(ino: u64) -> InodeRef { Arc::new(F { ino }) }

// /            (ino 2) → a
// /a           (ino 10) → b
// /a/b         (ino 20) → leaf(file 21)
fn build_root() -> Arc<Dentry> {
    let b = dir(20, &[("leaf", file(21))]);
    let a = dir(10, &[("b", b)]);
    Dentry::new_root(dir(2, &[("a", a)]))
}
fn parent() -> LookupFlags { let mut f = LookupFlags::default(); f.parent = true; f }
fn lt(root: &Arc<Dentry>, path: &str) -> LastType {
    vfs::path_lookup_path(root.clone(), root.clone(), path, parent()).expect("parent walk").last_type()
}

#[test]
fn normal_name_is_norm() {
    let root = build_root();
    assert_eq!(lt(&root, "/a/b/leaf"), LastType::Norm);
}

#[test]
fn trailing_dot_is_dot() {
    let root = build_root();
    assert_eq!(lt(&root, "/a/b/."), LastType::Dot, "`rmdir(\".\")` shape → LAST_DOT (EINVAL)");
    assert_eq!(lt(&root, "/."), LastType::Dot);
}

#[test]
fn trailing_dotdot_is_dotdot() {
    let root = build_root();
    assert_eq!(lt(&root, "/a/b/.."), LastType::Dotdot, "`rmdir(\"..\")` shape → LAST_DOTDOT (ENOTEMPTY)");
    assert_eq!(lt(&root, "/.."), LastType::Dotdot);
}

#[test]
fn bare_root_is_root() {
    let root = build_root();
    assert_eq!(lt(&root, "/"), LastType::Root, "a PARENT walk of `/` has no leaf → LAST_ROOT (EBUSY)");
}

// A full (non-PARENT) walk carries no leaf → Root (last_component is None).
#[test]
fn full_walk_has_no_leaf() {
    let root = build_root();
    let p = vfs::path_lookup_path(root.clone(), root.clone(), "/a/b/leaf", LookupFlags::default())
        .expect("full walk");
    assert_eq!(p.last_component, None);
    assert_eq!(p.last_type(), LastType::Root);
}
