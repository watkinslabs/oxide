//! RESOLVE_BENEATH (`openat2(2)`, Linux `LOOKUP_BENEATH`): the START dirfd is
//! the scoped resolution root; escaping ABOVE it ERRORS `EXDEV` rather than
//! clamping. Three escapes are rejected: an absolute pathname, a `..` at the
//! scoped root, and an absolute symlink target. Movement that stays at or below
//! the dirfd is allowed. Drives the real `vfs::path_lookup` walker over a
//! synthetic inode tree (fix-ledger namei D20).
//!
//! Fails-before: pre-fix `beneath_exdev` did not exist; the only `beneath` flag
//! CLAMPED escapes (restart-at-root / `/.. == /`) and absolute symlinks
//! surfaced as ELOOP — never EXDEV.

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
//   /            (ino 2)  → etc, secret (ino 99, only at the global root)
//   /etc         (ino 10) → hostname (11), sub (15), up (sym → /secret)
fn build() -> (Arc<Dentry>, Arc<Dentry>) {
    let etc = dir(10, &[
        ("hostname", file(11)),
        ("sub", dir(15, &[])),
        ("up", sym(12, "/secret")),
    ]);
    let root = Dentry::new_root(dir(2, &[("etc", etc), ("secret", file(99))]));
    let (_, etc_d) = vfs::path_lookup(root.clone(), root.clone(), "/etc", LookupFlags::default())
        .expect("resolve /etc");
    (root, etc_d)
}

fn beneath_exdev() -> LookupFlags { let mut f = LookupFlags::default(); f.beneath_exdev = true; f }

// Escape 1: an absolute pathname from the dirfd → EXDEV (Linux would resolve it
// against the real root, above the dirfd).
#[test]
fn beneath_exdev_absolute_path() {
    let (root, etc_d) = build();
    assert_eq!(
        vfs::path_lookup(etc_d.clone(), root.clone(), "/hostname", beneath_exdev()).err(),
        Some(VfsError::Exdev),
        "RESOLVE_BENEATH rejects an absolute pathname with EXDEV",
    );
}

// Escape 2: `..` at the scoped root → EXDEV (not a silent clamp).
#[test]
fn beneath_exdev_dotdot_at_root() {
    let (root, etc_d) = build();
    assert_eq!(
        vfs::path_lookup(etc_d.clone(), root.clone(), "..", beneath_exdev()).err(),
        Some(VfsError::Exdev),
        "RESOLVE_BENEATH rejects `..` escaping the dirfd with EXDEV",
    );
}

// Escape 3: an absolute symlink target → EXDEV (the D20 errno fix: previously
// ELOOP / clamp).
#[test]
fn beneath_exdev_absolute_symlink() {
    let (root, etc_d) = build();
    assert_eq!(
        vfs::path_lookup(etc_d.clone(), root.clone(), "up", beneath_exdev()).err(),
        Some(VfsError::Exdev),
        "RESOLVE_BENEATH rejects an absolute symlink target with EXDEV",
    );
}

// Allowed: a relative name AT the dirfd resolves normally.
#[test]
fn beneath_exdev_relative_ok() {
    let (root, etc_d) = build();
    let (i, _) = vfs::path_lookup(etc_d.clone(), root.clone(), "hostname", beneath_exdev())
        .expect("a name at the dirfd is allowed");
    assert_eq!(i.ino(), 11);
}

// Allowed: `sub/..` descends then returns to the dirfd — never ABOVE it — so it
// is NOT an escape and resolves back to /etc (ino 10).
#[test]
fn beneath_exdev_interior_dotdot_ok() {
    let (root, etc_d) = build();
    let (i, _) = vfs::path_lookup(etc_d.clone(), root.clone(), "sub/..", beneath_exdev())
        .expect("interior `..` back to the dirfd is allowed");
    assert_eq!(i.ino(), 10, "sub/.. returns to /etc, not above it");
}

// Distinction from the chroot `beneath` CLAMP: with `root == dirfd` and the
// clamp flag, an absolute path restarts at the root (no error) — proving
// EXDEV is exclusive to `beneath_exdev`.
#[test]
fn chroot_beneath_still_clamps() {
    let (_, etc_d) = build();
    let mut f = LookupFlags::default();
    f.beneath = true;
    let (i, _) = vfs::path_lookup(etc_d.clone(), etc_d.clone(), "/hostname", f)
        .expect("chroot beneath clamps absolute path to the jail root");
    assert_eq!(i.ino(), 11, "absolute path restarts at the jail root, not EXDEV");
}
