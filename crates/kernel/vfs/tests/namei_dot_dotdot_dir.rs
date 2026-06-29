//! path/namei: a pathname whose final element is a trailing `/`, a `.`, or a
//! `..` syntactically requires its resolved target to be a directory (Linux
//! `LOOKUP_DIRECTORY` + `..`/`.` only resolve against a directory). So
//! `/file/`, `/file/.` and `/file/..` are all ENOTDIR when `file` is a regular
//! file — even though the lexical splitter drops the trailing `.` and walks the
//! `..` up. Pins `path::requires_dir` and the walker's enforcement
//! (`docs/16§3`). The bare splitter previously dropped `/.` (Ok, wrong) and the
//! walker applied `..` from a non-dir without an ENOTDIR check (Ok, wrong).

use std::collections::BTreeMap;
use std::sync::Arc;

use vfs::inode::Inode;
use vfs::path::requires_dir;
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

// /somefile (regular, ino 11); /somedir (dir, ino 20).
fn build_root() -> Arc<Dentry> {
    let root_inode = dir(2, &[("somefile", file(11)), ("somedir", dir(20, &[]))]);
    Dentry::new_root(root_inode)
}
fn look(root: &Arc<Dentry>, p: &str) -> vfs::KResult<InodeRef> {
    vfs::path_lookup(root.clone(), root.clone(), p, LookupFlags::default()).map(|(i, _)| i)
}

// --- path::requires_dir (lexical layer) --------------------------------------

#[test]
fn requires_dir_lexical_contract() {
    // Trailing slash on a non-root path.
    assert!(requires_dir("/a/"));
    assert!(requires_dir("a/"));
    assert!(requires_dir("/a//"));   // collapsed trailing slashes still count
    // Final `.` / `..` component.
    assert!(requires_dir("/a/."));
    assert!(requires_dir("/a/.."));
    assert!(requires_dir("."));
    assert!(requires_dir(".."));
    assert!(requires_dir("a/.."));
    // No directory requirement.
    assert!(!requires_dir("/a"));
    assert!(!requires_dir("a"));
    assert!(!requires_dir("/a/b.txt"));
    assert!(!requires_dir("..foo"));   // `..foo` is a normal name, not `..`
    assert!(!requires_dir("...."));    // not `.` or `..`
    assert!(!requires_dir(""));
    // The bare root is itself a directory and imposes nothing extra.
    assert!(!requires_dir("/"));
}

// --- walker enforcement ------------------------------------------------------

// Trailing `.` on a regular file is ENOTDIR. Pre-fix: `components` dropped the
// `.`, so `/somefile/.` resolved identically to `/somefile` and returned Ok.
#[test]
fn trailing_dot_on_file_is_enotdir() {
    let root = build_root();
    assert_eq!(look(&root, "/somefile/.").err(), Some(VfsError::Enotdir));
    // Sanity: the file alone resolves, and `.` on the directory is fine.
    assert_eq!(look(&root, "/somefile").map(|i| i.ino()), Ok(11));
    assert_eq!(look(&root, "/somedir/.").map(|i| i.ino()), Ok(20));
}

// Trailing `..` on a regular file is ENOTDIR. Pre-fix: the walker applied
// `handle_dotdot` from the file's dentry (walking up to the root dir) WITHOUT a
// directory check, so `/somefile/..` wrongly resolved to `/`.
#[test]
fn trailing_dotdot_on_file_is_enotdir() {
    let root = build_root();
    assert_eq!(look(&root, "/somefile/..").err(), Some(VfsError::Enotdir));
    // `..` from a real directory still walks up correctly.
    assert_eq!(look(&root, "/somedir/..").map(|i| i.ino()), Ok(2));
}

// An interior non-directory prefix is ENOTDIR regardless of the final element.
#[test]
fn interior_file_prefix_is_enotdir() {
    let root = build_root();
    assert_eq!(look(&root, "/somefile/../somedir").err(), Some(VfsError::Enotdir));
    assert_eq!(look(&root, "/somefile/./x").err(), Some(VfsError::Enotdir));
}
