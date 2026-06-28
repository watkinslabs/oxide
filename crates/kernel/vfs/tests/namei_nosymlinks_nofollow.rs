//! RESOLVE_NO_SYMLINKS vs O_NOFOLLOW ordering on the FINAL component
//! (Linux `fs/namei.c`: `pick_link`'s `LOOKUP_NO_SYMLINKS` ELOOP gate fires only
//! when a link is actually FOLLOWED). A trailing symlink left unfollowed by
//! O_NOFOLLOW (`no_follow_final`) is NOT resolved, so RESOLVE_NO_SYMLINKS does
//! not turn it into ELOOP — the walk returns the symlink itself (the shape
//! `open(symlink, O_PATH|O_NOFOLLOW)` under RESOLVE_NO_SYMLINKS needs).
//!
//! Fails-before: the walker checked `no_symlinks` BEFORE the `no_follow_final`
//! final-return, so a final symlink with BOTH flags wrongly returned ELOOP.
//! Drives the real `vfs::path_lookup` walker over a synthetic inode tree.

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
//   /            (ino 2)  → realdir, link_to_file, link_to_dir, via_link
//   /realdir     (ino 10) → leaf(file 11)
//   /link_to_file -> realdir/leaf   (sym → a regular file)
//   /link_to_dir  -> realdir        (sym → a directory)
//   /via_link     -> link_to_dir    (an INTERMEDIATE symlink prefix below)
fn build_root() -> Arc<Dentry> {
    let realdir = dir(10, &[("leaf", file(11))]);
    let root = dir(2, &[
        ("realdir", realdir),
        ("link_to_file", sym(20, "realdir/leaf")),
        ("link_to_dir", sym(21, "realdir")),
        ("via_link", sym(22, "link_to_dir")),
    ]);
    Dentry::new_root(root)
}

fn flags(no_symlinks: bool, no_follow_final: bool) -> LookupFlags {
    let mut f = LookupFlags::default();
    f.no_symlinks = no_symlinks;
    f.no_follow_final = no_follow_final;
    f
}

// THE FIX: a FINAL symlink with BOTH RESOLVE_NO_SYMLINKS and O_NOFOLLOW is
// returned UNFOLLOWED (not ELOOP) — the link is never resolved, so the
// NO_SYMLINKS gate does not apply. Fails-before (ELOOP), passes-after.
#[test]
fn final_nofollow_under_no_symlinks_returns_link() {
    let root = build_root();
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/link_to_file", flags(true, true))
        .expect("O_NOFOLLOW final symlink is returned even under RESOLVE_NO_SYMLINKS");
    assert_eq!(i.file_type(), FileType::Symlink, "the symlink itself is returned, not its target");
    assert_eq!(i.ino(), 20);
}

// A FINAL symlink that IS followed (no O_NOFOLLOW) under RESOLVE_NO_SYMLINKS is
// ELOOP — the gate fires because the link is actually resolved.
#[test]
fn final_followed_under_no_symlinks_is_eloop() {
    let root = build_root();
    assert_eq!(
        vfs::path_lookup(root.clone(), root.clone(), "/link_to_file", flags(true, false)).err(),
        Some(VfsError::Eloop),
        "following a final symlink under RESOLVE_NO_SYMLINKS is ELOOP",
    );
}

// A trailing slash FORCES the final symlink to be followed, so O_NOFOLLOW does
// NOT short-circuit and RESOLVE_NO_SYMLINKS fires ELOOP.
#[test]
fn final_nofollow_trailing_slash_under_no_symlinks_is_eloop() {
    let root = build_root();
    assert_eq!(
        vfs::path_lookup(root.clone(), root.clone(), "/link_to_dir/", flags(true, true)).err(),
        Some(VfsError::Eloop),
        "a trailing slash forces the final symlink to be followed → ELOOP under NO_SYMLINKS",
    );
}

// An INTERMEDIATE symlink (a non-final path component) is always followed, so
// O_NOFOLLOW on the FINAL does not exempt it: RESOLVE_NO_SYMLINKS is ELOOP.
#[test]
fn intermediate_symlink_under_no_symlinks_is_eloop() {
    let root = build_root();
    // `via_link` → `link_to_dir` → `realdir`; resolving `via_link/leaf` follows
    // the intermediate `via_link` (and `link_to_dir`) → ELOOP under NO_SYMLINKS
    // even with no_follow_final (which only governs the FINAL `leaf`).
    assert_eq!(
        vfs::path_lookup(root.clone(), root.clone(), "/via_link/leaf", flags(true, true)).err(),
        Some(VfsError::Eloop),
        "an intermediate symlink is followed → ELOOP under RESOLVE_NO_SYMLINKS",
    );
}

// Sanity: WITHOUT RESOLVE_NO_SYMLINKS, O_NOFOLLOW on the final still returns the
// link, and a normal follow resolves to the target (unchanged behaviour).
#[test]
fn no_symlinks_clear_unchanged() {
    let root = build_root();
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/link_to_file", flags(false, true))
        .expect("nofollow returns the link");
    assert_eq!(i.file_type(), FileType::Symlink);
    let (t, _) = vfs::path_lookup(root.clone(), root.clone(), "/link_to_file", flags(false, false))
        .expect("followed to target");
    assert_eq!(t.ino(), 11, "followed link resolves to realdir/leaf");
}
