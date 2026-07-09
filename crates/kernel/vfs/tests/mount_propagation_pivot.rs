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

static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

static CUR_NS: AtomicU64 = AtomicU64::new(0);
fn cur_ns() -> u64 { CUR_NS.load(Ordering::Acquire) }
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
static ROOT: OnceLock<Arc<Dentry>> = OnceLock::new();
static HOST_ROOT_INODE: OnceLock<InodeRef> = OnceLock::new();
fn root_provider() -> Option<Arc<Dentry>> { ROOT.get().cloned() }

fn setup_host(host: u64) -> Arc<Dentry> {
    set_ns(host);
    let root_inode = dir(2, &[("run", dir(0x13, &[])), ("etc", dir(0x14, &[]))]);
    let root = ROOT.get_or_init(|| Dentry::new_root(root_inode.clone())).clone();
    let _ = HOST_ROOT_INODE.set(root_inode.clone());
    vfs::set_root_dentry_provider(root_provider);
    vfs::mount::register(None, Arc::new(NamedFs { n: "ext4", root: root_inode })).expect("root mount");
    let (_, d) = vfs::path_lookup(root.clone(), root.clone(), "/run", LookupFlags::default()).expect("run dir");
    vfs::mount::register(Some(d), Arc::new(NamedFs { n: "tmpfs", root: facdir(0x400) })).expect("mount /run");
    root
}

#[test]
fn service_namespace_bind_stays_private_pivot_succeeds() {
    let _g = guard();
    let host: u64 = 0x5150_1000;
    let sandbox: u64 = 0x5150_1001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);

    // 1. systemd makes / SHARED recursively at boot.
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");

    // 2. per-service: unshare mount ns → sandbox, switch to it.
    vfs::mount::copy_mnt_ns(host, sandbox);
    set_ns(sandbox);

    // 3. make-rslave / (recursive) to break propagation to host.
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    // 4. recursive-bind / onto /run/mount-rootfs (the service rootfs).
    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/mount-rootfs", LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    vfs::mount::register_bind(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }), hri).expect("bind /");
    vfs::mount::bind_submounts_rec(&root, &stage_d);

    // 5. pivot_root(stage, stage): after make-rslave, the bind is NOT shared, so
    //    pivot_root's "old_mnt shared" check MUST pass. If the stage mount is
    //    still SHARED (the bug), this returns EINVAL.
    vfs::mount::pivot_root(&stage_d, &stage_d)
        .expect("pivot_root(stage,stage) — fails EINVAL if the bind stayed SHARED (the sysinit-deadlock bug)");
}

/// The boot does NOT bind `/` directly — it `open_tree(OPEN_TREE_CLONE)`s `/`
/// (while `/` is still SHARED from the boot-time make-rshared) into a DETACHED
/// tree, then binds that fd. Linux `copy_tree` for an open_tree copy makes the
/// clone PRIVATE (no CL_MAKE_SHARED). If ours keeps it SHARED, the service
/// rootfs is shared -> pivot_root EINVAL -> the sysinit deadlock. Isolates that.
#[test]
fn open_tree_clone_of_shared_mount_is_private() {
    let _g = guard();
    let host: u64 = 0x5150_2000;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    let rootm = vfs::mount::mount_at_path_exact(&root).expect("root mount");
    assert_eq!(rootm.propagation.load(Ordering::Acquire), Propagation::Shared as u8, "precondition: / is shared");
    let clone = vfs::mount::clone_mount_tree(&rootm, true);
    let top = &clone[0].m;
    assert_ne!(top.propagation.load(Ordering::Acquire), Propagation::Shared as u8,
        "open_tree(OPEN_TREE_CLONE) of a SHARED mount must yield a PRIVATE clone");
}
