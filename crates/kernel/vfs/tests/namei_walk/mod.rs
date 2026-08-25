//! path_lookup walker tests on a synthetic inode tree (docs/16§9:
//! ".."/symlinks/depth-limit/mount-transitions/NO_SYMLINKS). No real
//! filesystem — just `Inode` impls — so this exercises the walker in
//! isolation.

use std::collections::BTreeMap;
use std::sync::Arc;

use vfs::inode::Inode;
use vfs::fs::FileSystem;
use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{Dentry, FileType, InodeRef, KResult, LookupFlags, VfsError};

/// Backend state (`i_private`): the static child table this directory resolves.
struct DirData { kids: BTreeMap<String, InodeRef> }

/// `i_op->lookup` over the static `DirData` child table (shared by the plain
/// and perm-bearing directory builders).
struct DirOps;
impl InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<DirData>().ok_or(VfsError::Enotdir)?;
        d.kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}
fn dir_data(kids: &[(&str, InodeRef)]) -> Arc<DirData> {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    Arc::new(DirData { kids: m })
}

fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(DirOps), default_file_ops())
        .private(dir_data(kids)).build()
}
fn file(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}
/// Symlink inode: the target body is stored inline (`i_link`), so `get_link`
/// returns it directly (the walker's symlink fast path).
fn sym(ino: u64, t: &str) -> InodeRef {
    sym_bytes(ino, t.as_bytes())
}
fn sym_bytes(ino: u64, t: &[u8]) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Symlink, 0o777), default_inode_ops(), default_file_ops())
        .size(t.len() as u64)
        .link(t.to_vec().into_boxed_slice())
        .build()
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
        Box::new(|_, _, _, _, _, _| unreachable!("testfs is mounted explicitly via register_bind")));
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

// Synthetic tree:
//   /etc/hostname            (file, ino 11)
//   /etc/localtime -> /usr/share/zoneinfo/UTC   (abs symlink)
//   /usr/share/zoneinfo/UTC  (file, ino 21)
//   /link_rel -> etc/hostname   (rel symlink at root)
//   /link_raw -> raw invalid-UTF8 target bytes
//   /loopa -> loopb, /loopb -> loopa  (mutual loop)
fn build_root() -> (Arc<Dentry>, u64, u64) {
    let hostname = file(11);
    let utc = file(21);
    let raw_name = vfs::path_from_bytes(b"raw-\xff");
    let raw_target = file(41);
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
        ("link_raw", sym_bytes(40, b"raw-\xff")),
        (&raw_name, raw_target),
        ("loopa", sym(31, "loopb")),
        ("loopb", sym(32, "loopa")),
    ]);
    let root = Dentry::new_root(root_inode);
    (root, 11, 21)
}

fn look(root: &Arc<Dentry>, path: &str, f: LookupFlags) -> vfs::KResult<(InodeRef, Arc<Dentry>)> {
    vfs::path_lookup(root.clone(), root.clone(), path, f)
}


fn alloc_ptr_eq(a: &Arc<Dentry>, b: &Arc<Dentry>) -> bool { Arc::ptr_eq(a, b) }

// ===========================================================================
// B4 KEYSTONE + flags + dots + may_lookup acceptance.
// ===========================================================================

// A directory inode that carries explicit POSIX perm (uid/gid 0) so `may_lookup`
// has per-fs perm info. Reuses `DirOps`; only the mode bits differ from `dir`.
fn perm_dir(ino: u64, perm: u16, kids: &[(&str, InodeRef)]) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, perm), Arc::new(DirOps), default_file_ops())
        .owner(0, 0).private(dir_data(kids)).build()
}

// THE KEYSTONE: crossing a mountpoint returns the mounted superblock's `s_root`
// DENTRY (Linux `__follow_mount`) — Arc::ptr_eq to `Mount.sb().s_root()` — NOT
// the covered underlay dentry. Both walking exactly the mountpoint and walking
// a child under it land on the mounted-fs dentry chain.

#[path = "tests/basic.rs"]
mod basic;
#[path = "tests/mounts.rs"]
mod mounts;
#[path = "tests/permissions.rs"]
mod permissions;
#[path = "tests/confinement.rs"]
mod confinement;

