//! path_lookup walker tests on a synthetic inode tree (docs/16§9:
//! ".."/symlinks/depth-limit/mount-transitions/NO_SYMLINKS). No real
//! filesystem — just `Inode` impls — so this exercises the walker in
//! isolation.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

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
//   /etc/hostname            (file, ino 11)
//   /etc/localtime -> /usr/share/zoneinfo/UTC   (abs symlink)
//   /usr/share/zoneinfo/UTC  (file, ino 21)
//   /link_rel -> etc/hostname   (rel symlink at root)
//   /loopa -> loopb, /loopb -> loopa  (mutual loop)
fn build_root() -> (Arc<Dentry>, u64, u64) {
    let hostname = file(11);
    let utc = file(21);
    let etc = dir(10, &[
        ("hostname", hostname),
        ("localtime", sym(12, "/usr/share/zoneinfo/UTC")),
    ]);
    let zoneinfo = dir(22, &[("UTC", utc)]);
    let share = dir(23, &[("zoneinfo", zoneinfo)]);
    let usr = dir(24, &[("share", share)]);
    let root_inode = dir(2, &[
        ("etc", etc),
        ("usr", usr),
        ("link_rel", sym(30, "etc/hostname")),
        ("loopa", sym(31, "loopb")),
        ("loopb", sym(32, "loopa")),
    ]);
    let root = Dentry::new_root(root_inode);
    (root, 11, 21)
}

fn look(root: &Arc<Dentry>, path: &str, f: LookupFlags) -> vfs::KResult<(InodeRef, Arc<Dentry>)> {
    vfs::path_lookup(root.clone(), root.clone(), path, f)
}

#[test]
fn descends_to_file() {
    let (root, host_ino, _) = build_root();
    let (i, _) = look(&root, "/etc/hostname", LookupFlags::default()).expect("resolve");
    assert_eq!(i.ino(), host_ino);
}

#[test]
fn dot_and_dotdot() {
    let (root, host_ino, _) = build_root();
    let (i, _) = look(&root, "/etc/./hostname", LookupFlags::default()).expect("dot");
    assert_eq!(i.ino(), host_ino);
    let (j, _) = look(&root, "/etc/../etc/hostname", LookupFlags::default()).expect("dotdot");
    assert_eq!(j.ino(), host_ino);
    // `..` at root stays at root.
    let (k, _) = look(&root, "/../etc/hostname", LookupFlags::default()).expect("dotdot-root");
    assert_eq!(k.ino(), host_ino);
}

#[test]
fn follows_relative_symlink() {
    let (root, host_ino, _) = build_root();
    let (i, _) = look(&root, "/link_rel", LookupFlags::default()).expect("rel symlink");
    assert_eq!(i.ino(), host_ino, "link_rel → etc/hostname");
}

#[test]
fn follows_absolute_symlink() {
    let (root, _, utc_ino) = build_root();
    let (i, _) = look(&root, "/etc/localtime", LookupFlags::default()).expect("abs symlink");
    assert_eq!(i.ino(), utc_ino, "localtime → /usr/share/zoneinfo/UTC");
}

#[test]
fn o_nofollow_returns_symlink() {
    let (root, _, _) = build_root();
    let mut f = LookupFlags::default();
    f.no_follow_final = true;
    let (i, _) = look(&root, "/link_rel", f).expect("nofollow");
    assert_eq!(i.file_type(), FileType::Symlink, "final symlink returned, not followed");
}

#[test]
fn resolve_no_symlinks_errors() {
    let (root, _, _) = build_root();
    let mut f = LookupFlags::default();
    f.no_symlinks = true;
    assert_eq!(look(&root, "/link_rel", f).err(), Some(VfsError::Eloop));
}

#[test]
fn symlink_loop_is_eloop() {
    let (root, _, _) = build_root();
    assert_eq!(look(&root, "/loopa", LookupFlags::default()).err(), Some(VfsError::Eloop));
}

#[test]
fn missing_component_enoent() {
    let (root, _, _) = build_root();
    assert_eq!(look(&root, "/etc/nope", LookupFlags::default()).err(), Some(VfsError::Enoent));
}

// Mount crossing: /mnt whose root holds `file`; /proc is a whole-path
// filesystem (its root rejects per-component lookup) reached via the
// whole-path delegate. One combined resolver so the global hooks don't
// race between parallel tests (unique paths, idempotent installs).
static MOUNT_ROOT: OnceLock<InodeRef> = OnceLock::new();
static PROC_ROOT: OnceLock<InodeRef> = OnceLock::new();
static PROC_TARGET: OnceLock<InodeRef> = OnceLock::new();
fn test_resolver(abs: &str) -> Option<InodeRef> {
    match abs {
        "/mnt"  => MOUNT_ROOT.get().cloned(),
        "/proc" => PROC_ROOT.get().cloned(),
        _ => None,
    }
}
fn test_whole_path(abs: &str) -> Option<InodeRef> {
    if abs == "/proc/123/stat" { PROC_TARGET.get().cloned() } else { None }
}

// A whole-path-only directory inode: per-component lookup is unsupported
// (Enotdir), like procfs's synthesised dirs.
struct WholePathDir { ino: u64 }
impl Inode for WholePathDir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> vfs::KResult<InodeRef> { Err(VfsError::Enotdir) }
}

#[test]
fn crosses_mount_point() {
    let mnt_file = file(99);
    let mnt_root = dir(98, &[("file", mnt_file)]);
    MOUNT_ROOT.set(mnt_root).ok();
    vfs::set_mount_resolver(test_resolver);

    // Root tree gains an empty `/mnt` directory the fs is mounted over.
    let empty_mnt = dir(50, &[]);
    let root_inode = dir(2, &[("mnt", empty_mnt)]);
    let root = Dentry::new_root(root_inode);

    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/mnt/file", LookupFlags::default())
        .expect("cross into mount");
    assert_eq!(i.ino(), 99, "resolved file inside the mounted fs, not the underlay");
}

// Crossing into a whole-path filesystem (procfs): per-component lookup
// of `/proc/123` fails (Enotdir), so the walker delegates the remaining
// absolute path to the owning mount's whole-path lookup.
#[test]
fn delegates_whole_path_for_procfs_style_fs() {
    PROC_ROOT.set(Arc::new(WholePathDir { ino: 300 })).ok();
    PROC_TARGET.set(file(301)).ok();
    vfs::set_mount_resolver(test_resolver);
    vfs::set_mount_whole_path(test_whole_path);

    let empty_proc = dir(60, &[]);
    let root_inode = dir(2, &[("proc", empty_proc)]);
    let root = Dentry::new_root(root_inode);

    let (i, _) = vfs::path_lookup(root.clone(), root, "/proc/123/stat", LookupFlags::default())
        .expect("delegate whole-path into procfs");
    assert_eq!(i.ino(), 301, "whole-path delegate resolved /proc/123/stat");
}
