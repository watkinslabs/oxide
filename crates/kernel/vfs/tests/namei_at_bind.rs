//! D17 / dcache D16: the `*at` walk seeded from a dirfd's REAL `(mnt_id,
//! dentry)` via `path_lookup_at_cred` (`Nameidata::new_at`) — NOT a stringified
//! `absolute_path()` re-walk. A dirfd that names a BIND mount must:
//!   1. resolve a relative child through the BIND's mount identity (the result
//!      `VfsPath.mnt_id` is the bind's, not the canonical mount), and
//!   2. climb `..` via the bind's MOUNTPOINT in the parent mount (the real
//!      mount tree), NOT lexically through the bind-root dentry's own parent.
//!
//! Fails-before: the old `*at` entry stringified `f.dentry().absolute_path()`
//! then re-walked from cwd — losing the bind's mount id and lexically
//! collapsing `..` (the D2 regression).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{Cred, Dentry, FileType, InodeRef, LookupFlags, VfsError};

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

// Register a bind whose ROOT inode is `root` on mountpoint `mp`; return the
// live `Mount` (carries the bind's `mnt_id` + a FRESH `mnt_root` dentry whose
// own `parent()` is self — so a LEXICAL `..` cannot reach the mountpoint's
// parent; only the mount-tree climb can).
fn register_at(mp: &Arc<Dentry>, root: InodeRef) -> Arc<vfs::mount::Mount> {
    ensure_testfs_type();
    vfs::mount::register_bind(Some(mp.clone()), Arc::new(TestMountFs), root).expect("register bind");
    vfs::mount::snapshot_all()
        .into_iter()
        .filter(|m| m.mountpoint().map(|d| Arc::ptr_eq(&d, mp)).unwrap_or(false))
        .last()
        .expect("registered bind visible")
}

// Tree: root(2)/a(10)/{y(11), b(12)}. Bind mounted on /a/b exposes a separate
// fs root(20) holding only x(21). The bind root has NO `y`, so a relative
// `../y` succeeds ONLY by climbing out of the bind via its mountpoint to /a.
fn build() -> (Arc<Dentry>, Arc<vfs::mount::Mount>) {
    let bind_root = dir(20, &[("x", file(21))]);
    let root = Dentry::new_root(dir(2, &[
        ("a", dir(10, &[("y", file(11)), ("b", dir(12, &[]))])),
    ]));
    let (_, mnt_d) = vfs::path_lookup(root.clone(), root.clone(), "/a/b", LookupFlags::default())
        .expect("resolve /a/b mountpoint");
    let bind = register_at(&mnt_d, bind_root);
    (root, bind)
}

// (1) Relative child resolved from the bind dirfd carries the BIND's mnt_id.
#[test]
fn at_relative_keeps_bind_mnt_id() {
    let _g = SERIAL.lock().unwrap();
    let (root, bind) = build();
    let base = bind.mnt_root().expect("bind mnt_root");
    let p = vfs::path_lookup_at_cred(base, bind.mnt_id, root.clone(), "x",
        LookupFlags::default(), Cred::root()).expect("resolve x under bind");
    assert_eq!(p.inode.ino(), 21, "relative `x` resolves the bind's file");
    assert_eq!(p.mnt_id, bind.mnt_id, "result mnt_id is the BIND's, not canonical");
}

// (2) `../y` from the bind dirfd climbs via the bind's MOUNTPOINT (mount tree),
// landing on /a/y (ino 11) — a node UNREACHABLE by a lexical `..` off the
// self-parent bind root. Proves the walk used (mnt,dentry) mount identity.
#[test]
fn at_dotdot_climbs_via_mountpoint_not_lexical() {
    let _g = SERIAL.lock().unwrap();
    let (root, bind) = build();
    let base = bind.mnt_root().expect("bind mnt_root");
    let p = vfs::path_lookup_at_cred(base, bind.mnt_id, root.clone(), "../y",
        LookupFlags::default(), Cred::root())
        .expect("`../y` climbs out of the bind via its mountpoint");
    assert_eq!(p.inode.ino(), 11, "`..` crossed to /a then resolved y (mount-tree, not lexical)");
    assert_ne!(p.mnt_id, bind.mnt_id, "after climbing out, mnt_id is the parent mount, not the bind");
}

#[test]
fn at_relative_bind_result_drives_readonly_mount_decision() {
    let _g = SERIAL.lock().unwrap();
    let (root, bind) = build();
    vfs::mount::remount_flags_by_id(bind.mnt_id, vfs::mount::MS_RDONLY)
        .expect("mark bind readonly");
    let base = bind.mnt_root().expect("bind mnt_root");
    let p = vfs::path_lookup_at_cred(base, bind.mnt_id, root.clone(), "x",
        LookupFlags::default(), Cred::root()).expect("resolve x under bind");
    assert_eq!(p.inode.ino(), 21, "relative `x` resolves the bind's file");
    assert_eq!(p.mnt_id, bind.mnt_id,
        "metadata syscalls must enforce readonly against the bind mount id");
    let m = vfs::mount::mount_by_id(p.mnt_id).expect("resolved mount exists");
    assert_ne!(m.flags() & vfs::mount::MNT_RDONLY, 0,
        "the resolved VfsPath carries the readonly mount, not the canonical source");
}

#[test]
fn bind_path_render_uses_file_mount_not_source_dentry_chain() {
    let _g = SERIAL.lock().unwrap();
    let (root, bind) = build();
    let base = bind.mnt_root().expect("bind mnt_root");
    let p = vfs::path_lookup_at_cred(base, bind.mnt_id, root.clone(), "x",
        LookupFlags::default(), Cred::root()).expect("resolve x under bind");
    assert_eq!(p.inode.ino(), 21, "relative `x` resolves the bind's file");
    assert_eq!(p.mnt_id, bind.mnt_id, "path keeps the bind mount id");
    assert_eq!(vfs::mount::render_path_for_mount(p.mnt_id, &p.dentry), "/a/b/x",
        "getcwd/fchdir display must render through the bind mount, not `/x`");
}

#[test]
fn open_tree_clone_source_uses_walked_mount_id() {
    let _g = SERIAL.lock().unwrap();
    let (root, bind) = build();
    let base = bind.mnt_root().expect("bind mnt_root");
    let p = vfs::path_lookup_at_cred(base, bind.mnt_id, root.clone(), "x",
        LookupFlags::default(), Cred::root()).expect("resolve x under bind");
    assert_eq!(p.mnt_id, bind.mnt_id,
        "open_tree must use the single walked VfsPath mount id, not rendered dentry text");
    let src = vfs::mount::mount_by_id(p.mnt_id).expect("walked mount exists");
    let nodes = vfs::mount::clone_mount_tree(&src, true);
    let root_clone = nodes.iter().find(|n| n.rel.is_empty()).expect("root clone");
    assert_eq!(root_clone.m.mnt_root().and_then(|d| d.inode()).map(|i| i.ino()), Some(20),
        "clone source is the bind root mount selected by VfsPath.mnt_id");
    vfs::mount::release_clone_tree(&nodes);
}
