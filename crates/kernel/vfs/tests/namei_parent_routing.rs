//! PARENT-walk ROUTING contract (namei D16 / ext4 D9): the namespace mutations
//! (mkdir/unlink/rename/create-open) now resolve their target via the engine
//! LOOKUP_PARENT walk — returning the resolved PARENT dir inode + the leaf name
//! — instead of an ad-hoc `rfind('/')` string split + a separate full walk of
//! the parent string. This drives the real `vfs::path_lookup_path` parent walk
//! over a synthetic inode tree and asserts the `(parent_inode, last_component)`
//! tuple a create/unlink/rename consumes, including the cases the old string
//! split handled specially: trailing slash, top-level leaf, and a not-yet-
//! existing leaf (the parent walk must NOT try to resolve the leaf).

use std::collections::BTreeMap;
use std::sync::Arc;

use vfs::inode::Inode;
use vfs::namei::LastType;
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

// /            (ino 2) → a, f(file 3)
// /a           (ino 10) → b, doc(file 11)
// /a/b         (ino 20) → leaf(file 21)
fn build_root() -> Arc<Dentry> {
    let b = dir(20, &[("leaf", file(21))]);
    let a = dir(10, &[("b", b), ("doc", file(11))]);
    Dentry::new_root(dir(2, &[("a", a), ("f", file(3))]))
}
fn parent() -> LookupFlags { let mut f = LookupFlags::default(); f.parent = true; f }

/// The (parent_ino, leaf) tuple a create/unlink/rename would act on.
fn parent_of(root: &Arc<Dentry>, path: &str) -> (u64, String) {
    let p = vfs::path_lookup_path(root.clone(), root.clone(), path, parent()).expect("parent walk");
    (p.inode.ino(), p.last_component.expect("leaf present"))
}

// mkdir/create("/a/new"): parent is /a, leaf is the (not-yet-existing) name.
#[test]
fn create_leaf_resolves_parent_and_name() {
    let root = build_root();
    let (pino, name) = parent_of(&root, "/a/new");
    assert_eq!(pino, 10, "parent is /a");
    assert_eq!(name, "new", "leaf reported verbatim — parent walk does NOT resolve it");
}

// unlink("/a/b/leaf"): the parent walk stops at /a/b, leaf "leaf".
#[test]
fn unlink_leaf_resolves_parent_and_name() {
    let root = build_root();
    let (pino, name) = parent_of(&root, "/a/b/leaf");
    assert_eq!(pino, 20, "parent is /a/b");
    assert_eq!(name, "leaf");
}

// Top-level leaf "/f": parent is the root, leaf "f" (old split's `idx == 0`).
#[test]
fn top_level_leaf_parent_is_root() {
    let root = build_root();
    let (pino, name) = parent_of(&root, "/f");
    assert_eq!(pino, 2, "parent of a top-level name is the root");
    assert_eq!(name, "f");
}

// Trailing slash (`mkdir /a/b/`): equivalent to `/a/b` — parent /a, leaf "b"
// (the old helper stripped one trailing slash before the rfind split).
#[test]
fn trailing_slash_equivalent_to_unslashed() {
    let root = build_root();
    assert_eq!(parent_of(&root, "/a/b/"), parent_of(&root, "/a/b"));
    let (pino, name) = parent_of(&root, "/a/b/");
    assert_eq!((pino, name.as_str()), (10, "b"));
}

// A missing INTERMEDIATE component still errors (parent itself unresolvable),
// but a missing LEAF does not (create/unlink act on it). Mirrors the old
// `resolve(parent)`-fails → error vs. leaf-absent → ok split.
#[test]
fn missing_intermediate_errors_missing_leaf_ok() {
    let root = build_root();
    // Missing leaf under an existing parent: OK (returns parent + leaf).
    assert!(vfs::path_lookup_path(root.clone(), root.clone(), "/a/nope", parent()).is_ok());
    // Missing intermediate: the parent dir itself can't be resolved → error.
    assert_eq!(
        vfs::path_lookup_path(root.clone(), root.clone(), "/a/ghost/leaf", parent()).err(),
        Some(VfsError::Enoent),
    );
    // A non-directory used as a parent prefix → ENOTDIR (Linux `link_path_walk`).
    assert_eq!(
        vfs::path_lookup_path(root.clone(), root.clone(), "/f/leaf", parent()).err(),
        Some(VfsError::Enotdir),
    );
}

// rename's two-sided parent resolution: each path independently yields its
// (parent, leaf) for `lock_rename` + the backend op.
#[test]
fn rename_two_sided_parents() {
    let root = build_root();
    let (fp, fname) = parent_of(&root, "/a/doc");
    let (tp, tname) = parent_of(&root, "/a/b/doc2");
    assert_eq!((fp, fname.as_str()), (10, "doc"), "from-side parent /a");
    assert_eq!((tp, tname.as_str()), (20, "doc2"), "to-side parent /a/b");
}

// The dot-forms surface as their LastType so the caller can reject them
// (`rmdir(".")`→EINVAL, `rmdir("..")`→ENOTEMPTY, root→EBUSY) without re-parsing.
#[test]
fn dot_forms_classify_for_rejection() {
    let root = build_root();
    let lt = |p: &str| vfs::path_lookup_path(root.clone(), root.clone(), p, parent())
        .expect("parent walk").last_type();
    assert_eq!(lt("/a/."), LastType::Dot);
    assert_eq!(lt("/a/.."), LastType::Dotdot);
    assert_eq!(lt("/"), LastType::Root);
    assert_eq!(lt("/a/b/leaf"), LastType::Norm);
}
