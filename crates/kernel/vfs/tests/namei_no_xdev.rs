//! RESOLVE_NO_XDEV (`openat2(2)`): mount-point traversal is forbidden during
//! resolution. Descending INTO a mount, or `..` ascending OUT of one, is
//! `EXDEV` (Linux `LOOKUP_NO_XDEV`). The START position's own over-mount is
//! exempt. Drives the real `vfs::path_lookup` walker over a synthetic tree with
//! a registered test mount.
//!
//! Fails-before: pre-fix the `no_xdev` flag did not exist, so `/mnt/file`
//! crossed the mount and SUCCEEDED instead of `EXDEV`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{Dentry, FileType, InodeRef, LookupFlags, VfsError};

// Mount registration is process-global; serialise this binary's tests.
static SERIAL: Mutex<()> = Mutex::new(());

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

struct TestMountFs;
impl FileSystem for TestMountFs {
    fn name(&self) -> &str { "testfs" }
}

// `register_bind` resolves its filesystem type by NAME through the real
// global `get_fs_type` registry — it never accepts an explicit type, so
// "testfs" must be registered once before the first bind. Idempotent: later
// calls in the same test binary see it already present and no-op.
fn ensure_testfs_type() {
    if vfs::fs::get_fs_type("testfs").is_some() { return; }
    let ty = vfs::fs::FsType::new("testfs", 0, vfs::fs::FsFlags::empty(),
        Box::new(|_, _, _, _| unreachable!("testfs is mounted explicitly via register_bind")));
    let _ = vfs::fs::register_fs(ty);
}

fn mount_id_for(mp: &Arc<Dentry>, root: InodeRef) -> u64 {
    ensure_testfs_type();
    vfs::mount::register_bind(Some(mp.clone()), Arc::new(TestMountFs), root).expect("register test mount");
    vfs::mount::snapshot_all()
        .into_iter()
        .filter(|m| m.mountpoint().map(|d| Arc::ptr_eq(&d, mp)).unwrap_or(false))
        .last()
        .expect("registered mount visible")
        .mnt_id
}

fn no_xdev() -> LookupFlags { let mut f = LookupFlags::default(); f.no_xdev = true; f }

// Build a root with an empty `/mnt` covered by a test mount whose root holds
// `file` (ino 99) and a `sub` dir (ino 97). Returns (root, mnt_dentry).
fn build_mounted() -> (Arc<Dentry>, Arc<Dentry>) {
    let mnt_root = dir(98, &[("file", file(99)), ("sub", dir(97, &[]))]);
    let root = Dentry::new_root(dir(2, &[("mnt", dir(50, &[]))]));
    let (_, mnt_d) = vfs::path_lookup(root.clone(), root.clone(), "/mnt", LookupFlags::default())
        .expect("resolve /mnt");
    let _mnt_id = mount_id_for(&mnt_d, mnt_root);
    (root, mnt_d)
}

// Baseline: WITHOUT no_xdev, descending into the mount resolves the mounted
// `file` (ino 99) — proves the mount is live and crossed.
#[test]
fn baseline_crosses_mount() {
    let _g = SERIAL.lock().unwrap();
    let (root, _) = build_mounted();
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/mnt/file", LookupFlags::default())
        .expect("baseline crosses into the mount");
    assert_eq!(i.ino(), 99);
}

// NO_XDEV: descending INTO the mount at `/mnt` is EXDEV.
#[test]
fn no_xdev_blocks_descent() {
    let _g = SERIAL.lock().unwrap();
    let (root, _) = build_mounted();
    assert_eq!(
        vfs::path_lookup(root.clone(), root.clone(), "/mnt/file", no_xdev()).err(),
        Some(VfsError::Exdev),
        "NO_XDEV forbids descending into the mounted fs",
    );
}

// NO_XDEV: resolving exactly the mountpoint `/mnt` ALSO crosses to the mounted
// `s_root` (Linux `__follow_mount`), so it too is EXDEV under NO_XDEV.
#[test]
fn no_xdev_blocks_mountpoint_itself() {
    let _g = SERIAL.lock().unwrap();
    let (root, _) = build_mounted();
    assert_eq!(
        vfs::path_lookup(root.clone(), root.clone(), "/mnt", no_xdev()).err(),
        Some(VfsError::Exdev),
        "NO_XDEV forbids crossing onto the mount root",
    );
}

// NO_XDEV: a `..` that ascends OUT of the mount (from the mounted root back to
// the mountpoint in the parent mount) is EXDEV. START is INSIDE the mount
// (`/mnt`, already crossed by Nameidata::new — exempt), then `../` escapes.
#[test]
fn no_xdev_blocks_dotdot_escape() {
    let _g = SERIAL.lock().unwrap();
    let (root, mnt_d) = build_mounted();
    // START = /mnt (its over-mount is normalised to the mounted s_root by
    // Nameidata::new and is exempt). `..` then tries to leave the mount.
    assert_eq!(
        vfs::path_lookup(mnt_d.clone(), root.clone(), "..", no_xdev()).err(),
        Some(VfsError::Exdev),
        "NO_XDEV forbids `..` ascending out of the mount",
    );
}

// NO_XDEV: movement that stays WITHIN one filesystem is fine. START inside the
// mount, resolving `sub` (a child in the SAME mounted fs) succeeds.
#[test]
fn no_xdev_allows_intra_mount() {
    let _g = SERIAL.lock().unwrap();
    let (root, mnt_d) = build_mounted();
    let (i, _) = vfs::path_lookup(mnt_d.clone(), root.clone(), "sub", no_xdev())
        .expect("intra-mount movement is allowed under NO_XDEV");
    assert_eq!(i.ino(), 97);
}
