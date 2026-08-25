//! Reproduces systemd's per-service mount-namespace setup that DEADLOCKED sysinit
//! (pivot_root -EINVAL "put_old mount SHARED"), fully hosted so the propagation
//! bug can be iterated in ms instead of a boot. Sequence (Linux setup_namespace):
//!   1. host `/` + `/run`; make `/` SHARED recursively (systemd `mount --make-rshared /` at boot).
//!   2. `copy_mnt_ns` (unshare CLONE_NEWNS) → sandbox ns; switch to it.
//!   3. make-rslave `/` recursively (break propagation to host).
//!   4. recursive-bind `/` onto a stage dir under `/run` (the service rootfs).
//!   5. pivot_root(stage, stage) — MUST succeed: after make-rslave, `/run` is
//!      slave, so the bind is NOT shared, so pivot_root's "old_mnt shared" check
//!      passes. A SHARED stage ⇒ EINVAL ⇒ this test fails ⇒ the bug.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{default_file_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{Dentry, FileType, InodeRef, KResult, LookupFlags, VfsError};
use vfs::mount::Propagation;
#[path = "../common/mod.rs"]
mod common;
static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

static CUR_NS: AtomicU64 = AtomicU64::new(0);
fn cur_ns() -> vfs::mntns::MntNamespaceRef { common::namespace_for_key(CUR_NS.load(Ordering::Acquire)) }
fn set_ns(ns: u64) { CUR_NS.store(ns, Ordering::Release); }

struct DirData { kids: BTreeMap<String, InodeRef> }
struct DirOps;
impl InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        inode.private::<DirData>().ok_or(VfsError::Enotdir)?
            .kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}
fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(DirOps), default_file_ops())
        .private(Arc::new(DirData { kids: m })).build()
}
// tmpfs-style factory dir (/run): any name → a fresh child dir (models mkdir).
static FAC: AtomicU64 = AtomicU64::new(0x9000);
struct FacOps;
impl InodeOps for FacOps {
    fn lookup(&self, _i: &Inode, _n: &str) -> KResult<InodeRef> { Ok(facdir(FAC.fetch_add(1, Ordering::Relaxed))) }
}
fn facdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(FacOps), default_file_ops()).build()
}
struct NamedFs { n: &'static str, root: InodeRef }
impl FileSystem for NamedFs {
    fn name(&self) -> &str { self.n }
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
}
fn fs_type_for(fs: &Arc<dyn FileSystem>) -> Arc<dyn vfs::FileSystemType> {
    vfs::fs::FsType::new(fs.name(), fs.magic(), fs.fs_flags(), Box::new(|_, _, _, _, _, _| unreachable!("test fs type is mounted explicitly")))
}
fn register_test_mount(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>) -> KResult<()> { vfs::mount::register_typed(fs_type_for(&fs), mp, fs) }
fn register_test_mount_at(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>, parent: Option<u64>) -> KResult<()> { vfs::mount::register_typed_at(fs_type_for(&fs), mp, fs, parent) }
fn register_test_bind(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>, root: InodeRef) -> KResult<()> { vfs::mount::register_bind_typed(fs_type_for(&fs), mp, fs, root) }
fn register_test_bind_path_at(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>, root: Arc<Dentry>, parent: Option<u64>) -> KResult<()> { vfs::mount::register_bind_path_typed_at(fs_type_for(&fs), mp, fs, root, parent) }
static ROOT: OnceLock<Arc<Dentry>> = OnceLock::new();
static HOST_ROOT_INODE: OnceLock<InodeRef> = OnceLock::new();
fn root_provider() -> Option<Arc<Dentry>> { ROOT.get().cloned() }

fn setup_host(host: u64) -> Arc<Dentry> {
    set_ns(host);
    let root_inode = HOST_ROOT_INODE.get().cloned().unwrap_or_else(|| dir(2, &[("run", dir(0x13, &[])), ("etc", dir(0x14, &[])),
        ("proc", dir(0x15, &[])), ("sys", dir(0x16, &[])), ("dev", dir(0x17, &[])),
        ("var", dir(0x18, &[("tmp", dir(0x19, &[]))]))]));
    let root = ROOT.get_or_init(|| Dentry::new_root(root_inode.clone())).clone();
    let _ = HOST_ROOT_INODE.set(root_inode.clone());
    vfs::set_root_dentry_provider(root_provider);
    register_test_mount(None, Arc::new(NamedFs { n: "ext4", root: root_inode })).expect("root mount");
    let (_, d) = vfs::path_lookup(root.clone(), root.clone(), "/run", LookupFlags::default()).expect("run dir");
    register_test_mount(Some(d), Arc::new(NamedFs { n: "tmpfs", root: facdir(0x400) })).expect("mount /run");
    root
}


fn mount_pseudo(root: &Arc<Dentry>, path: &str, name: &'static str, ino: u64) -> Arc<Dentry> {
    let (_, d) = vfs::path_lookup(root.clone(), root.clone(), path, LookupFlags::default()).expect(path);
    register_test_mount(Some(d.clone()), Arc::new(NamedFs { n: name, root: facdir(ino) })).expect("pseudo mount");
    d
}

/// END-TO-END model of the COMPLETE systemd per-service mount-namespace +
/// switch-root idiom sysinit runs, so post-pivot behavior (`umount2` MNT_DETACH,
/// `MS_MOVE`) is pinned hosted instead of discovered one-boot-at-a-time. Sequence
/// (systemd `setup_namespace` + `mount_switch_root`):
///   1. boot: make-rshared `/` (recursive).
///   2. per service: unshare(CLONE_NEWNS) -> sandbox ns.
///   3. make-rslave `/` (recursive) — detach propagation from host.
///   4. mount /proc /sys /dev, then recursive-bind `/` -> /run/mount-rootfs.
///   5. pivot_root(stage, stage) [stacked] — MUST succeed; stage becomes `/`.
///   6. umount2(old_root, MNT_DETACH) — the old root is stacked; MUST detach.
/// Asserts the tree at each step. A SHARED bind (the fixed bug) fails step 5; a
/// broken post-pivot detach fails step 6.

#[path = "tests/namespace.rs"]
mod namespace;
#[path = "tests/pivot.rs"]
mod pivot;
#[path = "tests/devices.rs"]
mod devices;
#[path = "tests/proc_bind.rs"]
mod proc_bind;
#[path = "tests/bind_identity.rs"]
mod bind_identity;
