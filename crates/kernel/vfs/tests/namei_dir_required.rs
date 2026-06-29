//! D14/D15 — directory-required enforcement (Linux `link_path_walk`
//! `LOOKUP_DIRECTORY` derived from pathname syntax). Three trailing forms force
//! the leaf to be a directory: a trailing `/` (covered by
//! `namei_trailing_slash`), a trailing `.` (`foo/.`), and a trailing `..`
//! (`foo/..`). On a non-directory leaf each is ENOTDIR; on a directory each
//! resolves. Drives the real `vfs::path_lookup` over a synthetic inode tree.

use std::collections::BTreeMap;
use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{Dentry, FileType, InodeRef, KResult, LookupFlags, VfsError};

struct DirData { kids: BTreeMap<String, InodeRef> }
struct DirOps;
impl InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<DirData>().ok_or(VfsError::Enotdir)?;
        d.kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}
fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(DirOps), default_file_ops())
        .private(Arc::new(DirData { kids: m })).build()
}
fn file(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}
fn build_root() -> Arc<Dentry> {
    // /afile (regular, 11); /adir (dir, 20) with a child file /adir/inner (21).
    Dentry::new_root(dir(2, &[
        ("afile", file(11)),
        ("adir", dir(20, &[("inner", file(21))])),
    ]))
}
fn look(root: &Arc<Dentry>, path: &str) -> KResult<(InodeRef, Arc<Dentry>)> {
    vfs::path_lookup(root.clone(), root.clone(), path, LookupFlags::default())
}

// `foo/.` on a FILE → ENOTDIR (the `.` form requires a directory leaf). The
// `.` is dropped by the splitter, so the requirement comes from `requires_dir`
// setting LOOKUP_DIRECTORY in the engine.
#[test]
fn trailing_dot_on_file_is_enotdir() {
    let root = build_root();
    assert_eq!(look(&root, "/afile/.").err(), Some(VfsError::Enotdir),
        "`/afile/.` (trailing dot on a file) must be ENOTDIR");
}

// `foo/.` on a DIRECTORY resolves to the directory itself.
#[test]
fn trailing_dot_on_dir_is_ok() {
    let root = build_root();
    let (i, _) = look(&root, "/adir/.").expect("`/adir/.` resolves the directory");
    assert_eq!(i.ino(), 20);
}

// `foo/..` on a FILE → ENOTDIR: `..` is resolved only from a directory, so the
// non-dir prefix is rejected before any walk-up (Linux resolves `..` only from
// `d_can_lookup`).
#[test]
fn trailing_dotdot_on_file_is_enotdir() {
    let root = build_root();
    assert_eq!(look(&root, "/afile/..").err(), Some(VfsError::Enotdir),
        "`/afile/..` (trailing dotdot on a file) must be ENOTDIR");
}

// `foo/..` on a DIRECTORY walks back to the parent (here the root).
#[test]
fn trailing_dotdot_on_dir_walks_up() {
    let root = build_root();
    let (i, _) = look(&root, "/adir/..").expect("`/adir/..` walks up to the root");
    assert_eq!(i.ino(), 2, "`/adir/..` resolves to the root directory");
}
