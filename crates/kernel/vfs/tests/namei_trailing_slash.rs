//! Trailing-slash semantics (Linux `link_path_walk`): a pathname ending in
//! `/` means LOOKUP_DIRECTORY — the final component must resolve to a
//! directory (else ENOTDIR) AND a final symlink is followed even under
//! `no_follow_final`. Drives the real `vfs::path_lookup` walker over a
//! synthetic inode tree (no real fs), the authoritative layer (`docs/16§3`).

use std::collections::BTreeMap;
use std::sync::Arc;

use vfs::inode::Inode;
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

struct Sym { ino: u64, target: String }
impl Inode for Sym {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { self.target.len() as u64 }
    fn lookup(&self, _n: &str) -> vfs::KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn readlink(&self) -> vfs::KResult<Vec<u8>> { Ok(self.target.clone().into_bytes()) }
}

fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    Arc::new(Dir { ino, kids: m })
}
fn file(ino: u64) -> InodeRef { Arc::new(F { ino }) }
fn sym(ino: u64, t: &str) -> InodeRef { Arc::new(Sym { ino, target: t.to_string() }) }

// Synthetic tree:
//   /somefile          (regular file, ino 11)
//   /somedir           (directory, ino 20)
//   /link_to_file -> somefile   (rel symlink → a regular file)
//   /link_to_dir  -> somedir    (rel symlink → a directory)
fn build_root() -> Arc<Dentry> {
    let root_inode = dir(2, &[
        ("somefile", file(11)),
        ("somedir", dir(20, &[("inner", file(21))])),
        ("link_to_file", sym(30, "somefile")),
        ("link_to_dir", sym(31, "somedir")),
    ]);
    Dentry::new_root(root_inode)
}

fn look(root: &Arc<Dentry>, path: &str) -> vfs::KResult<(InodeRef, Arc<Dentry>)> {
    vfs::path_lookup(root.clone(), root.clone(), path, LookupFlags::default())
}

// A trailing `/` on a regular FILE is ENOTDIR (the leaf must be a directory).
// Pre-fix this FAILED: the trailing `/` was filtered out by `components()`, so
// `/somefile/` resolved identically to `/somefile` and returned Ok.
#[test]
fn trailing_slash_on_file_is_enotdir() {
    let root = build_root();
    assert_eq!(look(&root, "/somefile/").err(), Some(VfsError::Enotdir),
        "`/somefile/` (trailing slash on a file) must be ENOTDIR");
    // Sanity: WITHOUT the trailing slash the same file resolves fine.
    assert_eq!(look(&root, "/somefile").map(|(i, _)| i.ino()), Ok(11));
}

// A trailing `/` on a DIRECTORY resolves to the directory.
#[test]
fn trailing_slash_on_dir_is_ok() {
    let root = build_root();
    let (i, _) = look(&root, "/somedir/").expect("`/somedir/` resolves the directory");
    assert_eq!(i.ino(), 20);
}

// Root "/" is itself a directory and must still resolve fine (the len==1 edge
// the trailing-slash detection must NOT mistake for `foo/`).
#[test]
fn root_slash_is_ok() {
    let root = build_root();
    let (i, _) = look(&root, "/").expect("root resolves");
    assert_eq!(i.ino(), 2);
}

// A trailing `/` FORCES the final symlink to be followed even under
// `no_follow_final`; `/link_to_file/` follows the link to a regular file, then
// the trailing-slash directory requirement yields ENOTDIR.
#[test]
fn trailing_slash_follows_final_symlink_then_enotdir() {
    let root = build_root();
    let mut f = LookupFlags::default();
    f.no_follow_final = true;
    // Without the trailing slash + no_follow_final, the symlink is returned.
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/link_to_file", f)
        .expect("nofollow returns the symlink itself");
    assert_eq!(i.file_type(), FileType::Symlink);
    // WITH the trailing slash the final symlink is followed despite
    // no_follow_final, and its (regular-file) target is ENOTDIR.
    assert_eq!(vfs::path_lookup(root.clone(), root.clone(), "/link_to_file/", f).err(),
        Some(VfsError::Enotdir),
        "`/link_to_file/` follows the symlink then ENOTDIR (target not a dir)");
    // A trailing slash on a symlink → directory resolves the directory.
    let (j, _) = vfs::path_lookup(root.clone(), root, "/link_to_dir/", f)
        .expect("`/link_to_dir/` follows the symlink to a directory");
    assert_eq!(j.ino(), 20);
}
