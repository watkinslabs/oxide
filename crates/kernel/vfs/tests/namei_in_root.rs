//! RESOLVE_IN_ROOT (`openat2(2)`) confinement: the dirfd (START) is treated as
//! "/", so absolute paths, `..`, and absolute symlink targets are all confined
//! to it, overriding the passed resolution `root` (Linux `nd->root = nd->path`).
//! Drives the real `vfs::path_lookup` walker over a synthetic inode tree (no
//! real filesystem), proving the formerly-dormant `in_root` flag is now wired.

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

// Synthetic tree:
//   /          (ino 2)  → etc, usr, secret
//   /etc       (ino 10) → hostname (ino 11), up (symlink → /secret)
//   /secret    (ino 99) file ONLY reachable from the GLOBAL root
//   /usr/lib   (ino 24/25)
fn build_root() -> Arc<Dentry> {
    let etc = dir(10, &[
        ("hostname", file(11)),
        // Absolute symlink whose target only exists at the global root.
        ("up", sym(12, "/secret")),
    ]);
    let usr = dir(24, &[("lib", dir(25, &[]))]);
    let root_inode = dir(2, &[
        ("etc", etc),
        ("usr", usr),
        ("secret", file(99)),
    ]);
    Dentry::new_root(root_inode)
}

// Helper: resolve `path` with START=`start`, ROOT=global, and the given flags.
fn at(start: &Arc<Dentry>, root: &Arc<Dentry>, path: &str, f: LookupFlags)
    -> vfs::KResult<InodeRef>
{
    vfs::path_lookup(start.clone(), root.clone(), path, f).map(|(i, _)| i)
}

// Baseline (no in_root): with START=/etc but ROOT=global, an absolute path
// restarts at the GLOBAL root — `/secret` resolves, `/hostname` does not (the
// global root has no `hostname` child). This is the fail-before behaviour the
// in_root wiring must change.
#[test]
fn baseline_absolute_uses_passed_root() {
    let root = build_root();
    let (_, etc_d) = vfs::path_lookup(root.clone(), root.clone(), "/etc", LookupFlags::default())
        .expect("resolve /etc dentry");

    let f = LookupFlags::default();
    // Absolute path restarts at the passed (global) root.
    assert_eq!(at(&etc_d, &root, "/secret", f).expect("global secret").ino(), 99,
        "without in_root, /secret resolves at the global root");
    // Global root has no `hostname` child → ENOENT.
    assert_eq!(at(&etc_d, &root, "/hostname", f).err(), Some(VfsError::Enoent),
        "without in_root, /hostname is not visible from the global root");
}

// RESOLVE_IN_ROOT: START (/etc) becomes "/". Absolute paths confine to it, so
// `/hostname` → /etc/hostname (ino 11) and `/secret` (only at the global root)
// is invisible (ENOENT).
#[test]
fn in_root_absolute_confined_to_dirfd() {
    let root = build_root();
    let (_, etc_d) = vfs::path_lookup(root.clone(), root.clone(), "/etc", LookupFlags::default())
        .expect("resolve /etc dentry");

    let mut f = LookupFlags::default();
    f.in_root = true;
    assert_eq!(at(&etc_d, &root, "/hostname", f).expect("confined hostname").ino(), 11,
        "in_root: /hostname resolves relative to dirfd /etc");
    assert_eq!(at(&etc_d, &root, "/secret", f).err(), Some(VfsError::Enoent),
        "in_root: the global-root-only /secret is invisible inside the dirfd root");
}

// RESOLVE_IN_ROOT: `..` cannot ascend above the dirfd root (Linux clamps `..`
// at nd->root). `/../secret` stays inside /etc, so /secret is still invisible.
#[test]
fn in_root_dotdot_clamped_to_dirfd() {
    let root = build_root();
    let (_, etc_d) = vfs::path_lookup(root.clone(), root.clone(), "/etc", LookupFlags::default())
        .expect("resolve /etc dentry");

    let mut f = LookupFlags::default();
    f.in_root = true;
    // `..` clamps at the dirfd root → still inside /etc → hostname visible.
    assert_eq!(at(&etc_d, &root, "/../hostname", f).expect("clamped dotdot").ino(), 11,
        "in_root: .. clamps at the dirfd root, /hostname still resolves");
    // ...and the global-only /secret remains unreachable via `..`.
    assert_eq!(at(&etc_d, &root, "/../secret", f).err(), Some(VfsError::Enoent),
        "in_root: .. cannot escape the dirfd root to reach /secret");
}

// RESOLVE_IN_ROOT: an absolute SYMLINK target restarts at the dirfd root, not
// the global root (Linux confines absolute symlinks under IN_ROOT). `/etc/up`
// points to `/secret`; under in_root that resolves to /etc/secret (absent),
// whereas without in_root it would reach the global /secret.
#[test]
fn in_root_absolute_symlink_confined() {
    let root = build_root();
    let (_, etc_d) = vfs::path_lookup(root.clone(), root.clone(), "/etc", LookupFlags::default())
        .expect("resolve /etc dentry");

    // Baseline: from the GLOBAL root, /etc/up → /secret → ino 99.
    assert_eq!(at(&root, &root, "/etc/up", LookupFlags::default()).expect("global up").ino(), 99,
        "without in_root, /etc/up follows its absolute target to the global /secret");

    // in_root: dirfd = /etc is "/"; up's `/secret` target restarts at /etc and
    // /etc has no `secret` child → ENOENT (confined, not escaped).
    let mut f = LookupFlags::default();
    f.in_root = true;
    assert_eq!(at(&etc_d, &root, "up", f).err(), Some(VfsError::Enoent),
        "in_root: absolute symlink target is confined to the dirfd root");
}
