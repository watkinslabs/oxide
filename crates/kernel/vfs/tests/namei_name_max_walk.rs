//! Per-component NAME_MAX enforced DURING the walk (Linux `link_path_walk`):
//! `vfs::path_lookup` rejects any single component longer than 255 bytes with
//! `ENAMETOOLONG`, even when the whole pathname is under PATH_MAX. The lexical
//! `path::check_component` primitive already existed; this pins that the WALK
//! actually invokes it (it formerly fell through to `i_op->lookup` → ENOENT).
//!
//! Fails-before: a 256-byte component resolved to ENOENT (no match), or to the
//! fs lookup's errno — never ENAMETOOLONG — because the walk used the unchecked
//! `components()` splitter.

use std::collections::BTreeMap;
use std::sync::Arc;

use vfs::inode::Inode;
use vfs::path::NAME_MAX;
use vfs::{Dentry, FileType, InodeRef, LookupFlags, VfsError};

struct DirData { kids: BTreeMap<String, InodeRef> }
struct DirOps;
impl vfs::InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> vfs::KResult<InodeRef> {
        inode.private::<DirData>().unwrap().kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}
fn mk_dir(ino: u64, kids: BTreeMap<String, InodeRef>) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755),
        Arc::new(DirOps), vfs::default_file_ops())
        .private(Arc::new(DirData { kids })).build()
}
fn file(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Regular, 0o644),
        vfs::default_inode_ops(), vfs::default_file_ops()).build()
}

// Root holds a child named exactly NAME_MAX 'a's (file ino 50) and a `dir`.
fn build() -> Arc<Dentry> {
    let at_limit = "a".repeat(NAME_MAX);
    let mut kids = BTreeMap::new();
    kids.insert(at_limit, file(50));
    kids.insert("dir".to_string(), mk_dir(10, BTreeMap::new()));
    Dentry::new_root(mk_dir(2, kids))
}

// A component of NAME_MAX bytes resolves; NAME_MAX+1 bytes is ENAMETOOLONG.
#[test]
fn boundary_at_and_over_name_max() {
    let root = build();
    let at = format!("/{}", "a".repeat(NAME_MAX));
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), &at, LookupFlags::default())
        .expect("255-byte component resolves");
    assert_eq!(i.ino(), 50);

    let over = format!("/{}", "a".repeat(NAME_MAX + 1));
    assert_eq!(
        vfs::path_lookup(root.clone(), root.clone(), &over, LookupFlags::default()).err(),
        Some(VfsError::Enametoolong),
        "256-byte component is ENAMETOOLONG during the walk, not ENOENT",
    );
}

// An over-length INTERMEDIATE component fails before the rest is consumed.
#[test]
fn over_length_intermediate() {
    let root = build();
    let p = format!("/{}/leaf", "b".repeat(NAME_MAX + 1));
    assert_eq!(
        vfs::path_lookup(root.clone(), root.clone(), &p, LookupFlags::default()).err(),
        Some(VfsError::Enametoolong),
        "over-length intermediate component short-circuits to ENAMETOOLONG",
    );
}

// An over-length LOOKUP_PARENT leaf is rejected before the parent-stop returns.
#[test]
fn over_length_parent_leaf() {
    let root = build();
    let p = format!("/dir/{}", "c".repeat(NAME_MAX + 1));
    let mut f = LookupFlags::default();
    f.parent = true;
    assert_eq!(
        vfs::path_lookup(root.clone(), root.clone(), &p, f).err(),
        Some(VfsError::Enametoolong),
        "over-length parent leaf is ENAMETOOLONG, not a successful parent-stop",
    );
}
