//! LOOKUP_FOLLOW (Linux `fs/namei.c`, fix-ledger namei D30): an explicit
//! `follow` flag for the trailing-symlink decision, a first-class counterpart to
//! `no_follow_final`. When set it OVERRIDES no_follow_final so the final symlink
//! is resolved (Linux's flag set never holds both; FOLLOW wins). Default-off:
//! with neither bit set the trailing symlink is followed as before. Drives the
//! real `vfs::path_lookup` walker over a synthetic inode tree (`docs/16§3`).

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
struct SymData { target: Vec<u8> }
struct SymOps;
impl vfs::InodeOps for SymOps {
    fn readlink(&self, inode: &Inode) -> vfs::KResult<Vec<u8>> {
        Ok(inode.private::<SymData>().unwrap().target.clone())
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
fn sym(ino: u64, t: &str) -> InodeRef {
    let body = t.as_bytes().to_vec();
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Symlink, 0o777),
        Arc::new(SymOps), vfs::default_file_ops())
        .size(body.len() as u64).private(Arc::new(SymData { target: body })).build()
}

// /somefile          (regular file, ino 11)
// /link_to_file -> somefile   (rel symlink → a regular file, ino 30)
fn build_root() -> Arc<Dentry> {
    let root_inode = dir(2, &[
        ("somefile", file(11)),
        ("link_to_file", sym(30, "somefile")),
    ]);
    Dentry::new_root(root_inode)
}
fn look(root: &Arc<Dentry>, path: &str, f: LookupFlags) -> vfs::KResult<InodeRef> {
    vfs::path_lookup(root.clone(), root.clone(), path, f).map(|(i, _)| i)
}

// Default (no follow, no no_follow): the trailing symlink IS followed — the
// historical default the new flag must not regress.
#[test]
fn default_follows_trailing_symlink() {
    let root = build_root();
    let i = look(&root, "/link_to_file", LookupFlags::default()).expect("resolves");
    assert_eq!(i.ino(), 11, "default trailing-symlink follow unchanged");
}

// no_follow_final alone: the trailing symlink is returned as-is.
#[test]
fn no_follow_returns_symlink() {
    let root = build_root();
    let mut f = LookupFlags::default();
    f.no_follow_final = true;
    let i = look(&root, "/link_to_file", f).expect("resolves the link itself");
    assert_eq!(i.file_type(), FileType::Symlink);
    assert_eq!(i.ino(), 30);
}

// LOOKUP_FOLLOW OVERRIDES no_follow_final: the trailing symlink is followed
// even with no_follow_final also set (FOLLOW wins).
#[test]
fn follow_overrides_no_follow_final() {
    let root = build_root();
    let mut f = LookupFlags::default();
    f.no_follow_final = true;
    f.follow = true;
    let i = look(&root, "/link_to_file", f).expect("follow overrides no_follow_final");
    assert_eq!(i.ino(), 11, "LOOKUP_FOLLOW follows the trailing symlink to its target");
}

// LOOKUP_FOLLOW alone (no no_follow_final) follows the trailing symlink.
#[test]
fn follow_alone_follows() {
    let root = build_root();
    let mut f = LookupFlags::default();
    f.follow = true;
    let i = look(&root, "/link_to_file", f).expect("resolves");
    assert_eq!(i.ino(), 11);
    // sanity: the non-symlink target is unaffected by the flag.
    assert_eq!(look(&root, "/somefile", f).map(|i| i.ino()), Ok(11));
}

// A dangling symlink target still ENOENT when followed under LOOKUP_FOLLOW.
#[test]
fn follow_dangling_target_enoent() {
    let root = Dentry::new_root(dir(2, &[("dangling", sym(40, "nope"))]));
    let mut f = LookupFlags::default();
    f.follow = true;
    assert_eq!(look(&root, "/dangling", f).err(), Some(VfsError::Enoent));
}
