//! rcu-walk (Step C, OPT-IN LOOKUP_RCU) fallback equivalence. The opt-in rcu
//! (lazy) walk is a PURE fast-path overlay over the proven ref/Arc walk: at any
//! complication (symlink, mount crossing, the final component, a dcache miss)
//! it `unlazy_walk`s — and in this Arc-walk substrate (dormant dcache d_count,
//! dcache D11 unwired) the legitimize conservatively FALLS BACK to the ref
//! walk. The contract this test pins: an rcu-mode resolution returns EXACTLY
//! the same result (inode + dentry identity, or the same error) as the ref-mode
//! resolution, across the plain, symlink, mount-crossing, cold-miss and
//! missing-leaf cases.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{Dentry, FileType, InodeRef, KResult, LookupFlags, VfsError};

fn watchdog(secs: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(secs));
        eprintln!("watchdog: rcu_fallback test exceeded {secs}s — aborting");
        std::process::abort();
    });
}

struct DirData { kids: BTreeMap<String, InodeRef> }
fn dir_data(kids: &[(&str, InodeRef)]) -> Arc<DirData> {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    Arc::new(DirData { kids: m })
}
struct DirOps;
impl InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<DirData>().ok_or(VfsError::Enotdir)?;
        d.kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}
fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(DirOps), default_file_ops())
        .private(dir_data(kids)).build()
}
fn file(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}
fn sym(ino: u64, t: &str) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Symlink, 0o777), default_inode_ops(), default_file_ops())
        .size(t.len() as u64).link(t.as_bytes().to_vec().into_boxed_slice()).build()
}
fn rcu() -> LookupFlags { let mut f = LookupFlags::default(); f.rcu = true; f }

struct TestMountFs;
impl FileSystem for TestMountFs { fn name(&self) -> &str { "testfs" } }

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
    vfs::mount::register_bind(Some(mp.clone()), Arc::new(TestMountFs), root).expect("register mount");
    vfs::mount::snapshot_all().into_iter()
        .filter(|m| m.mountpoint().map(|d| Arc::ptr_eq(&d, mp)).unwrap_or(false))
        .last().expect("mount visible").mnt_id
}

#[test]
fn rcu_equals_arc_plain_and_symlink() {
    watchdog(30);
    let leaf = file(0xC);
    let b = dir(0xB, &[("c", leaf)]);
    let a = dir(0xA, &[("b", b)]);
    let root_inode = dir(2, &[("a", a), ("ln", sym(0x30, "a/b/c"))]);
    let root = Dentry::new_root(root_inode);
    // Warm the cache so rcu/arc both hit the same cached dentries.
    let _ = vfs::path_lookup_path(root.clone(), root.clone(), "/a/b/c", LookupFlags::default()).unwrap();

    for path in ["/a/b/c", "/ln"] {
        let arc = vfs::path_lookup_path(root.clone(), root.clone(), path, LookupFlags::default()).unwrap();
        let lazy = vfs::path_lookup_path(root.clone(), root.clone(), path, rcu()).unwrap();
        assert_eq!(arc.inode.ino(), lazy.inode.ino(), "rcu inode == arc inode for {path}");
        assert!(Arc::ptr_eq(&arc.dentry, &lazy.dentry), "rcu dentry identity == arc for {path}");
    }
}

#[test]
fn rcu_falls_back_on_cold_miss() {
    watchdog(30);
    // Cold cache: the rcu walk MUST fall back to the blocking i_op->lookup slow
    // path (not return EAGAIN like RESOLVE_CACHED) and resolve correctly.
    let leaf = file(0x99);
    let d = dir(0xD0, &[("leaf", leaf)]);
    let root_inode = dir(2, &[("d", d)]);
    let root = Dentry::new_root(root_inode);
    let lazy = vfs::path_lookup_path(root.clone(), root.clone(), "/d/leaf", rcu())
        .expect("rcu falls back through the cold-miss slow path");
    assert_eq!(lazy.inode.ino(), 0x99);
}

#[test]
fn rcu_equals_arc_across_mount() {
    watchdog(30);
    let mnt_file = file(99);
    let mnt_root = dir(98, &[("file", mnt_file)]);
    let empty = dir(50, &[]);
    let root_inode = dir(2, &[("mnt", empty)]);
    let root = Dentry::new_root(root_inode);

    let (_, mnt_d) = vfs::path_lookup(root.clone(), root.clone(), "/mnt", LookupFlags::default())
        .expect("resolve /mnt");
    let _id = mount_id_for(&mnt_d, mnt_root);

    let arc = vfs::path_lookup_path(root.clone(), root.clone(), "/mnt/file", LookupFlags::default()).unwrap();
    let lazy = vfs::path_lookup_path(root.clone(), root.clone(), "/mnt/file", rcu()).unwrap();
    assert_eq!(arc.inode.ino(), 99);
    assert_eq!(lazy.inode.ino(), 99, "rcu crosses the mount identically to arc");
    assert!(Arc::ptr_eq(&arc.dentry, &lazy.dentry), "rcu lands on the same mounted-fs dentry");
}

#[test]
fn rcu_equals_arc_on_missing_leaf() {
    watchdog(30);
    let a = dir(0xA, &[]);
    let root = Dentry::new_root(dir(2, &[("a", a)]));
    let arc = vfs::path_lookup_path(root.clone(), root.clone(), "/a/nope", LookupFlags::default()).err();
    let lazy = vfs::path_lookup_path(root.clone(), root.clone(), "/a/nope", rcu()).err();
    assert_eq!(arc, Some(VfsError::Enoent));
    assert_eq!(arc, lazy, "rcu and arc agree on the missing-leaf error");
}
