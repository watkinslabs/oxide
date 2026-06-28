//! Confined-root (chroot) absolute-SYMLINK resolution. Under a confined
//! resolution root — the mechanism `pathresolve::resolution_root` uses for
//! chroot, threading `beneath = true` with `root` = the jail dentry — an
//! absolute symlink target must restart AT the jail root (Linux `nd_jump_root`),
//! exactly as an absolute PATHNAME already does. A chroot'd `/hostname` symlink
//! resolves to `<jail>/hostname`, NOT the global tree.
//!
//! Fails-before: the walk returned `ELOOP` for an absolute symlink whenever
//! `beneath` was set (a chroot bug — chroot does not forbid absolute symlinks,
//! it confines them). Drives the real `vfs::path_lookup` walker.

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
//   /          (ino 2)  → jail, secret(file 99)   [global-only]
//   /jail      (ino 10) → abs(symlink → /hostname), hostname(file 11), to_secret(symlink → /secret)
fn build_root() -> Arc<Dentry> {
    let jail = dir(10, &[
        ("abs", sym(12, "/hostname")),       // absolute target present inside the jail
        ("hostname", file(11)),
        ("to_secret", sym(13, "/secret")),   // absolute target present ONLY at the global root
    ]);
    let root = dir(2, &[("jail", jail), ("secret", file(99))]);
    Dentry::new_root(root)
}

fn chroot() -> LookupFlags { let mut f = LookupFlags::default(); f.beneath = true; f }

// An absolute symlink under a chroot restarts at the jail root: /jail is "/",
// so `abs` → `/hostname` → /jail/hostname (ino 11). Before the fix this was
// ELOOP. The START and ROOT are both the jail dentry (as pathresolve sets up).
#[test]
fn chroot_absolute_symlink_confined_to_jail() {
    let root = build_root();
    let (_, jail) = vfs::path_lookup(root.clone(), root.clone(), "/jail", LookupFlags::default())
        .expect("resolve /jail");

    let i = vfs::path_lookup(jail.clone(), jail.clone(), "abs", chroot())
        .map(|(i, _)| i)
        .expect("chroot absolute symlink resolves (was ELOOP before the fix)");
    assert_eq!(i.ino(), 11, "abs → /hostname restarts at the jail → /jail/hostname");
}

// The absolute symlink target cannot escape the jail: `to_secret` → `/secret`,
// but the jail has no `secret` child, so it is ENOENT (confined), NOT the
// global-root /secret (ino 99).
#[test]
fn chroot_absolute_symlink_cannot_escape() {
    let root = build_root();
    let (_, jail) = vfs::path_lookup(root.clone(), root.clone(), "/jail", LookupFlags::default())
        .expect("resolve /jail");

    // Baseline: from the GLOBAL root, /jail/to_secret → /secret → ino 99.
    let g = vfs::path_lookup(root.clone(), root.clone(), "/jail/to_secret", LookupFlags::default())
        .map(|(i, _)| i).expect("global to_secret");
    assert_eq!(g.ino(), 99, "without chroot, the absolute target reaches the global /secret");

    // Under chroot the target restarts at the jail, which has no `secret`.
    let e = vfs::path_lookup(jail.clone(), jail.clone(), "to_secret", chroot()).err();
    assert_eq!(e, Some(VfsError::Enoent),
        "chroot confines the absolute symlink target to the jail (no escape to /secret)");
}
