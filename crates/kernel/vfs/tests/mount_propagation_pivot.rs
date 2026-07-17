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
    vfs::fs::FsType::new(fs.name(), fs.magic(), fs.fs_flags(), Box::new(|_, _, _, _| unreachable!("test fs type is mounted explicitly")))
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
    common::copy_mnt_ns(host, sandbox).unwrap();
    set_ns(sandbox);

    // 3. make-rslave / (recursive) to break propagation to host.
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    // 4. recursive-bind / onto /run/mount-rootfs (the service rootfs).
    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/mount-rootfs", LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    register_test_bind_path_at(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }), root.clone(), None).expect("bind /");
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

#[test]
fn copy_mnt_ns_reports_old_to_new_mount_ids_for_fs_path_remap() {
    let _g = guard();
    let host: u64 = 0x5150_2500;
    let sandbox: u64 = 0x5150_2501;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    let old_root_id = vfs::mount::root_mount_id(common::namespace_id(host)).expect("host root id");
    let run_d = vfs::d_lookup(&root, "run").expect("/run mountpoint dentry");
    let old_run_id = vfs::mount::mount_at_path_exact(&run_d).expect("/run mount").mnt_id;

    let map = common::snapshot_ns_map(host, sandbox).unwrap();
    let mapped = |old| map.iter().find_map(|(o, n)| if *o == old { Some(*n) } else { None });
    let new_root_id = mapped(old_root_id).expect("root mount id remapped");
    let new_run_id = mapped(old_run_id).expect("/run mount id remapped");

    assert_ne!(new_root_id, old_root_id, "namespace copy must mint a new root mount id");
    assert_ne!(new_run_id, old_run_id, "namespace copy must mint a new /run mount id");
    assert_eq!(vfs::mount::root_mount_id(common::namespace_id(sandbox)), Some(new_root_id));
    let new_run = vfs::mount::mount_by_id(new_run_id).expect("new /run mount exists");
    assert_eq!(new_run.namespace_id(), common::namespace_id(sandbox));
    assert_eq!(new_run.mount_point_str(), "/run");
}

/// The `mount(MS_BIND, source, target)` syscall must NOT make the new mount a
/// peer of the SOURCE. Linux `do_loopback` clones with flag 0 (no CL_MAKE_SHARED):
/// a bind's shared-ness comes ONLY from the destination. This is exactly the
/// `165_mount.rs` regression that EINVAL'd pivot_root — the syscall used to
/// `join_peer_group(target, peer_group_of(source))`, so binding a SHARED source
/// onto a NON-shared dest wrongly produced a SHARED mount. Pin it: bind a shared
/// source onto a private `/run` child; the bind must stay PRIVATE (pg 0).
#[test]
fn bind_of_shared_source_onto_private_dest_stays_private() {
    let _g = guard();
    let host: u64 = 0x5150_3000;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    // Make the SOURCE (`/`) shared — the boot's `make-rshared /`.
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    let srcm = vfs::mount::mount_at_path_exact(&root).expect("root mount");
    assert_ne!(srcm.peer_group.load(Ordering::Acquire), 0, "precondition: source is in a peer group");
    // `/run` (the destination parent) is a PLAIN mount (private) — models the
    // per-service ns where `make-rslave /` already broke propagation.
    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/mount-rootfs", LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    // The Linux-correct bind path (register_bind + dest-based propagate_mount),
    // WITHOUT the removed source-peer-group inheritance.
    register_test_bind(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }), hri).expect("bind");
    let _ = vfs::mount::propagate_mount(&stage_d);
    let bindm = vfs::mount::mount_at_path_exact(&stage_d).expect("bind mount");
    assert_ne!(bindm.propagation.load(Ordering::Acquire), Propagation::Shared as u8,
        "bind of a SHARED source onto a private dest must NOT be shared (Linux do_loopback flag 0)");
    assert_eq!(bindm.peer_group.load(Ordering::Acquire), 0,
        "bind must NOT inherit the source's peer group");
}

// Small helper: register a pseudo-fs submount at `path` under the ns root.
fn mount_pseudo(root: &Arc<Dentry>, path: &str, name: &'static str, ino: u64) -> Arc<Dentry> {
    let (_, d) = vfs::path_lookup(root.clone(), root.clone(), path, LookupFlags::default()).expect(path);
    register_test_mount(Some(d.clone()), Arc::new(NamedFs { n: name, root: facdir(ino) })).expect("pseudo mount");
    d
}

/// END-TO-END model of the COMPLETE systemd per-service mount-namespace +
/// switch-root idiom sysinit runs, so post-pivot behavior (`umount2` MNT_DETACH,
/// `MS_MOVE`) is pinned hosted instead of discovered one-boot-at-a-time. Sequence
/// (systemd `setup_namespace` + `mount_switch_root`, Linux fs/namespace.c):
///   1. boot: make-rshared `/` (recursive).
///   2. per service: unshare(CLONE_NEWNS) -> sandbox ns.
///   3. make-rslave `/` (recursive) — detach propagation from host.
///   4. mount /proc /sys /dev, then recursive-bind `/` -> /run/mount-rootfs.
///   5. pivot_root(stage, stage) [stacked] — MUST succeed; stage becomes `/`.
///   6. umount2(old_root, MNT_DETACH) — the old root is stacked; MUST detach.
/// Asserts the tree at each step. A SHARED bind (the fixed bug) fails step 5; a
/// broken post-pivot detach fails step 6.
#[test]
fn full_service_setup_pivot_and_switch_root_detach() {
    let _g = guard();
    let host: u64 = 0x5150_4000;
    let sandbox: u64 = 0x5150_4001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    // Real submounts under `/` so the recursive bind + pivot carry a subtree.
    mount_pseudo(&root, "/proc", "procfs", 0x500);
    mount_pseudo(&root, "/sys", "sysfs", 0x501);
    mount_pseudo(&root, "/dev", "devtmpfs", 0x502);

    // 1. make-rshared / at boot.
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    // 2. unshare -> sandbox.
    common::copy_mnt_ns(host, sandbox).unwrap();
    set_ns(sandbox);
    // 3. make-rslave / (recursive) — breaks propagation to host.
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    // 4. recursive-bind / onto the stage (+ its /proc,/sys,/dev submounts).
    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/mount-rootfs", LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    register_test_bind_path_at(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }), root.clone(), None).expect("bind /");
    vfs::mount::propagate_mount(&stage_d);
    let root_id = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("source root id");
    let target_parent = vfs::mount::containing_mount_id(common::namespace_id(sandbox), &stage_d);
    vfs::mount::bind_submounts_rec_at(Some(root_id), &root, &stage_d, Some(target_parent));
    // The bind must be PRIVATE (the fix): a shared put_old EINVALs pivot_root.
    let bindm = vfs::mount::mount_at_path_exact(&stage_d).expect("bind mount");
    assert_ne!(bindm.propagation.load(Ordering::Acquire), Propagation::Shared as u8,
        "service rootfs bind must be PRIVATE, not SHARED");
    let stage_id = bindm.mnt_id;

    // Submount carry-through: bind_submounts_rec MUST replicate the tmpfs /run
    // (and pseudo-fs) UNDER the stage, so after pivot `/run` resolves to tmpfs,
    // not the ext4 underlay. If the tmpfs submount is dropped, `mkdir /run/udev`
    // lands on ext4 -> the boot's `mkdir /run/udev err=5`. Assert a tmpfs mount
    // now lives inside the stage subtree.
    let is_under = |m: &Arc<vfs::mount::Mount>, top: u64| -> bool {
        let mut id = m.parent_id.load(Ordering::Acquire);
        for _ in 0..64 { if id == top { return true; } match vfs::mount::mount_by_id(id) {
            Some(p) => { let np = p.parent_id.load(Ordering::Acquire); if np == id { break; } id = np; }
            None => break, } }
        false
    };
    let tmpfs_under_stage = vfs::mount::all_mounts().iter()
        .filter(|m| m.namespace_id() == common::namespace_id(sandbox) && m.sb().s_type.name() == "tmpfs" && is_under(m, stage_id))
        .count();
    assert!(tmpfs_under_stage >= 1,
        "tmpfs /run must be carried UNDER the stage by bind_submounts_rec (else mkdir /run/udev hits ext4 -> EIO)");

    // 5. pivot_root(stage, stage) — stacked. MUST succeed; stage becomes `/`.
    let old_root_id = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("pre-pivot root id");
    assert_ne!(old_root_id, stage_id, "precondition: stage != old root");
    vfs::mount::pivot_root(&stage_d, &stage_d).expect("pivot_root(stage, stage)");
    let new_root_id = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("post-pivot root id");
    assert_eq!(new_root_id, stage_id, "after pivot_root the stage bind IS the ns root");
    let new_root = vfs::mount::root_dentry_for_mount_id(stage_id).expect("post-pivot root dentry");
    let dev = vfs::path_lookup_at_root_cred(
        new_root.clone(), stage_id, new_root.clone(), stage_id, "/dev",
        LookupFlags::default(), vfs::Cred::root())
        .expect("post-pivot /dev must resolve");
    assert_ne!(dev.mnt_id, stage_id, "post-pivot /dev must remain a carried submount");
    assert_eq!(dev.inode.ino(), 0x502, "post-pivot /dev must resolve the carried devtmpfs root");

    // 6. umount2(old_root, MNT_DETACH): the old root is now stacked under `/`.
    //    systemd's `pivot_root(., .); umount2(., MNT_DETACH)` idiom. The old-root
    //    mount must still exist and detach cleanly (recursive == MNT_DETACH lazy).
    let om = vfs::mount::mount_by_id(old_root_id).expect("old root still present after pivot");
    let omp = om.mountpoint().expect("old root has a mountpoint after stacking pivot");
    // Overmount lookup (Linux `lookup_mnt`): resolving the mountpoint dentry that
    // `.`/`/` map to after the stacking pivot MUST find the STACKED old root, not
    // the underlay ns-root. This is precisely what lets the syscall's
    // `umount2(".", MNT_DETACH)` (resolved via the live cwd dentry) reach the old
    // root instead of the ns-root — without it, the switch-root cleanup EINVALs.
    assert_eq!(vfs::mount::mount_at_path_exact(&omp).map(|m| m.mnt_id), Some(old_root_id),
        "mountpoint dentry must resolve to the stacked old root (overmount), not the ns-root");
    let n = vfs::mount::unregister_top(&omp, true);
    assert!(n > 0, "umount2(old_root, MNT_DETACH) must detach the stacked old root (got {n})");
    assert!(vfs::mount::mount_by_id(old_root_id).is_none(),
        "old root gone from the ns after detach");
    // The ns root is still the stage bind — the switch-root completed.
    assert_eq!(vfs::mount::root_mount_id(common::namespace_id(sandbox)), Some(stage_id),
        "ns root remains the stage bind after old-root detach");
    let new_root = vfs::mount::root_dentry_for_mount_id(stage_id).expect("post-pivot root dentry");
    let run_dir = vfs::path_lookup_at_root_cred(
        new_root.clone(), stage_id, new_root, stage_id, "/run",
        LookupFlags::default(), vfs::Cred::root())
        .expect("post-pivot /run must resolve through tmpfs, not ext4 underlay");
    assert_ne!(run_dir.inode.ino(), 0x13, "/run fell back to ext4 underlay");
}

#[test]
fn staged_root_exposes_plain_ext4_var_tmp_before_pivot() {
    let _g = guard();
    let host: u64 = 0x5150_4100;
    let sandbox: u64 = 0x5150_4101;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    common::copy_mnt_ns(host, sandbox).unwrap();
    set_ns(sandbox);
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/systemd/mount-rootfs",
        LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    register_test_bind_path_at(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri }),
        root.clone(), None).expect("bind /");
    let source_root = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("source root id");
    let stage_parent = vfs::mount::containing_mount_id(common::namespace_id(sandbox), &stage_d);
    vfs::mount::bind_submounts_rec_at(Some(source_root), &root, &stage_d, Some(stage_parent));

    let var_tmp = vfs::path_lookup_at_root_cred(
        root.clone(), source_root, root.clone(), source_root,
        "/run/systemd/mount-rootfs/var/tmp", LookupFlags::default(), vfs::Cred::root())
        .expect("systemd destination /run/systemd/mount-rootfs/var/tmp must resolve through staged /");
    assert_eq!(var_tmp.inode.ino(), 0x19, "staged root must expose the source rootfs /var/tmp dentry");
    assert_eq!(vfs::mount::render_path_for_mount(var_tmp.mnt_id, &var_tmp.dentry),
        "/run/systemd/mount-rootfs/var/tmp",
        "rendered identity for plain rootfs children must stay under the staged root");
}

#[test]
fn private_devices_tmpfs_dev_move_into_staged_root_succeeds() {
    let _g = guard();
    let host: u64 = 0x5150_5000;
    let sandbox: u64 = 0x5150_5001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    let dev_d = mount_pseudo(&root, "/dev", "devtmpfs", 0x600);
    mount_pseudo(&root, "/dev/pts", "devpts", 0x601);
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    common::copy_mnt_ns(host, sandbox).unwrap();
    set_ns(sandbox);
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/systemd/mount-rootfs",
        LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    register_test_bind_path_at(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }),
        root.clone(), None).expect("bind /");
    let stage_id = vfs::mount::mount_at_path_exact(&stage_d).expect("stage bind").mnt_id;
    let source_root = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("source root id");
    let stage_parent = vfs::mount::containing_mount_id(common::namespace_id(sandbox), &stage_d);
    vfs::mount::bind_submounts_rec_at(Some(source_root), &root, &stage_d, Some(stage_parent));

    let (_, tmp_dev_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/systemd/namespace-test/dev",
        LookupFlags::default()).expect("tmp private dev path");
    let tmp_parent = vfs::mount::containing_mount_id(common::namespace_id(sandbox), &tmp_dev_d);
    register_test_mount_at(Some(tmp_dev_d.clone()), Arc::new(NamedFs { n: "tmpfs", root: facdir(0x602) }),
        Some(tmp_parent)).expect("tmpfs private /dev");
    let tmp_dev_id = vfs::mount::__lookup_mnt(tmp_parent, &tmp_dev_d).expect("private dev mount").mnt_id;

    assert!(vfs::mount::__lookup_mnt(stage_id, &dev_d).is_some(),
        "recursive bind should place a /dev submount under the staged root");
    vfs::mount::unregister_top(&dev_d, true);

    vfs::mount::move_mount_by_id_to(tmp_dev_id, Some(stage_id), &dev_d)
        .expect("MS_MOVE private tmpfs /dev onto staged /dev must not EINVAL");
    let moved = vfs::mount::__lookup_mnt(stage_id, &dev_d).expect("moved private dev under stage");
    assert_eq!(moved.mnt_id, tmp_dev_id, "private /dev mount moved to the staged root");
    assert_eq!(moved.parent_id.load(Ordering::Acquire), stage_id,
        "moved private /dev parent must be the walked staged root");
    vfs::mount::pivot_root(&stage_d, &stage_d).expect("pivot_root after private /dev move");
    let new_root_id = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("post-pivot root id");
    let new_root = vfs::mount::root_dentry_for_mount_id(new_root_id).expect("post-pivot root dentry");
    let dev = vfs::path_lookup_at_root_cred(
        new_root.clone(), new_root_id, new_root.clone(), new_root_id, "/dev",
        LookupFlags::default(), vfs::Cred::root())
        .expect("private /dev must survive pivot");
    assert_eq!(dev.mnt_id, tmp_dev_id, "private /dev mount identity must survive pivot");
    assert_eq!(dev.inode.ino(), 0x602, "post-pivot /dev must resolve private tmpfs root");
}

#[test]
fn staged_proc_leaf_self_bind_uses_staged_parent() {
    let _g = guard();
    let host: u64 = 0x5150_6000;
    let sandbox: u64 = 0x5150_6001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    mount_pseudo(&root, "/proc", "procfs", 0x700);
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    common::copy_mnt_ns(host, sandbox).unwrap();
    set_ns(sandbox);
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/systemd/mount-rootfs",
        LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    register_test_bind_path_at(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }),
        root.clone(), None).expect("bind /");
    let _stage_id = vfs::mount::mount_at_path_exact(&stage_d).expect("stage bind").mnt_id;
    let source_root = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("source root id");
    let stage_parent = vfs::mount::containing_mount_id(common::namespace_id(sandbox), &stage_d);
    vfs::mount::bind_submounts_rec_at(Some(source_root), &root, &stage_d, Some(stage_parent));

    let src = vfs::path_lookup_at_root_cred(
        root.clone(), source_root, root.clone(), source_root, "/run/systemd/mount-rootfs/proc/sys/kernel/domainname",
        LookupFlags::default(), vfs::Cred::root()).expect("source proc leaf");
    let tgt = vfs::path_lookup_at_root_cred(
        root.clone(), source_root, root.clone(), source_root, "/proc/sys/kernel/domainname",
        LookupFlags::default(), vfs::Cred::root()).expect("target proc leaf");
    assert!(Arc::ptr_eq(&src.dentry, &tgt.dentry), "proc leaf dentry is shared across the staged bind");

    register_test_bind_path_at(Some(tgt.dentry.clone()), Arc::new(NamedFs { n: "bind", root: tgt.inode.clone() }),
        src.dentry.clone(), Some(src.mnt_id)).expect("self bind proc leaf");
    let b = vfs::mount::__lookup_mnt(src.mnt_id, &tgt.dentry).expect("bind must be under staged proc parent");
    assert_eq!(b.parent_id.load(Ordering::Acquire), src.mnt_id,
        "self-bind parent must be the source/staged proc mount, not the old /proc mount");
    assert_eq!(b.mount_point_str(), "/run/systemd/mount-rootfs/proc/sys/kernel/domainname",
        "mountinfo-visible path must be the staged prefix systemd is scanning");
    vfs::mount::remount_flags_by_id(b.mnt_id, vfs::mount::MS_RDONLY).expect("remount read-only");
    assert_ne!(b.flags.load(Ordering::Acquire) & vfs::mount::MNT_RDONLY, 0,
        "recursive bind-remount convergence requires the top leaf mount to read back ro");
}

#[test]
fn bind_under_derives_rendered_path_from_parent_mount_identity() {
    let _g = guard();
    let host: u64 = 0x5150_7000;
    let sandbox: u64 = 0x5150_7001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    mount_pseudo(&root, "/proc", "procfs", 0x710);
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    common::copy_mnt_ns(host, sandbox).unwrap();
    set_ns(sandbox);
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/systemd/mount-rootfs",
        LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    register_test_bind_path_at(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }),
        root.clone(), None).expect("bind /");
    let source_root = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("source root id");
    let stage_parent = vfs::mount::containing_mount_id(common::namespace_id(sandbox), &stage_d);
    vfs::mount::bind_submounts_rec_at(Some(source_root), &root, &stage_d, Some(stage_parent));

    let src = vfs::path_lookup_at_root_cred(
        root.clone(), source_root, root.clone(), source_root, "/run/systemd/mount-rootfs/proc/kallsyms",
        LookupFlags::default(), vfs::Cred::root()).expect("staged kallsyms");
    let tgt = vfs::path_lookup_at_root_cred(
        root.clone(), source_root, root.clone(), source_root, "/proc/kallsyms",
        LookupFlags::default(), vfs::Cred::root()).expect("global kallsyms alias");
    assert!(Arc::ptr_eq(&src.dentry, &tgt.dentry), "proc leaf dentry is shared across staged and global proc");

    vfs::mount::register_bind_clone_under(src.mnt_id, tgt.dentry.clone(), src.mnt_id, src.dentry.clone())
        .expect("bind under staged proc");
    let b = vfs::mount::__lookup_mnt(src.mnt_id, &tgt.dentry).expect("bind under staged proc parent");
    assert_eq!(b.mount_point_str(), "/run/systemd/mount-rootfs/proc/kallsyms",
        "bind-under must derive rendered path from parent mount identity, not caller's stale global string");
}

#[test]
fn bind_clone_shares_source_superblock_and_staged_identity() {
    let _g = guard();
    let host: u64 = 0x5150_8000;
    let sandbox: u64 = 0x5150_8001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    mount_pseudo(&root, "/proc", "procfs", 0x720);
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    common::copy_mnt_ns(host, sandbox).unwrap();
    set_ns(sandbox);
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/systemd/mount-rootfs",
        LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    register_test_bind_path_at(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }),
        root.clone(), None).expect("bind /");
    let source_root = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("source root id");
    let stage_parent = vfs::mount::containing_mount_id(common::namespace_id(sandbox), &stage_d);
    vfs::mount::bind_submounts_rec_at(Some(source_root), &root, &stage_d, Some(stage_parent));

    let src = vfs::path_lookup_at_root_cred(
        root.clone(), source_root, root.clone(), source_root, "/run/systemd/mount-rootfs/proc/sys/kernel/domainname",
        LookupFlags::default(), vfs::Cred::root()).expect("staged domainname");
    let tgt = vfs::path_lookup_at_root_cred(
        root.clone(), source_root, root.clone(), source_root, "/proc/sys/kernel/domainname",
        LookupFlags::default(), vfs::Cred::root()).expect("global domainname alias");
    assert!(Arc::ptr_eq(&src.dentry, &tgt.dentry), "proc leaf dentry is shared across staged and global proc");
    let src_m = vfs::mount::mount_by_id(src.mnt_id).expect("source proc mount");
    assert_eq!(src_m.sb().s_type.name(), "procfs", "precondition: source is procfs");

    vfs::mount::register_bind_clone_under(src.mnt_id, tgt.dentry.clone(), src.mnt_id, src.dentry.clone())
        .expect("bind clone under staged proc");
    let b = vfs::mount::__lookup_mnt(src.mnt_id, &tgt.dentry).expect("bind clone under staged proc parent");
    assert_eq!(b.parent_id.load(Ordering::Acquire), src.mnt_id,
        "bind clone parent must be the walked staged proc mount");
    assert_eq!(b.mount_point_str(), "/run/systemd/mount-rootfs/proc/sys/kernel/domainname",
        "mountinfo-visible path must be the staged prefix");
    assert_eq!(vfs::mount::mountinfo_root_field(&b), "/sys/kernel/domainname",
        "bind mountinfo root must be the source path relative to the source superblock root");
    assert!(Arc::ptr_eq(b.sb(), src_m.sb()),
        "Linux bind clone shares the source superblock; no synthetic bind SB");
    assert_eq!(b.sb().s_type.name(), "procfs",
        "bind mount fstype must be the source fstype, not a fake bind filesystem");
    assert_eq!(b.mnt_root().and_then(|d| d.inode()).map(|i| i.ino()), Some(src.inode.ino()),
        "bind mnt_root must be the source leaf dentry");
    vfs::mount::remount_flags_by_id(b.mnt_id, vfs::mount::MS_RDONLY).expect("remount read-only");
    assert_ne!(b.flags.load(Ordering::Acquire) & vfs::mount::MNT_RDONLY, 0,
        "mountinfo convergence must observe the remounted bind clone as ro");
}
