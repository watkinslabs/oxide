use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{default_file_ops, mk_mode, Dentry, FileSystemType, FileType, InodeBuilder, InodeOps, InodeRef, KResult, LookupFlags, VfsError};
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
fn fs_type_for(fs: &Arc<dyn FileSystem>) -> Arc<dyn FileSystemType> {
    vfs::fs::FsType::new(fs.name(), fs.magic(), fs.fs_flags(), Box::new(|_, _, _, _, _, _| unreachable!("test fs type is mounted explicitly")))
}
fn register_test_mount(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>) -> KResult<()> {
    vfs::mount::register_typed(fs_type_for(&fs), mp, fs)
}
fn register_test_bind_path_at(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>,
    root_dentry: Arc<Dentry>, parent_hint: Option<u64>) -> KResult<()> {
    vfs::mount::register_bind_path_typed_at(fs_type_for(&fs), mp, fs, root_dentry, parent_hint)
}
static ROOT: OnceLock<Arc<Dentry>> = OnceLock::new();
static HOST_ROOT_INODE: OnceLock<InodeRef> = OnceLock::new();
fn root_provider() -> Option<Arc<Dentry>> { ROOT.get().cloned() }

fn setup_host(host: u64) -> Arc<Dentry> {
    set_ns(host);
    let root_inode = dir(2, &[("run", dir(0x13, &[])), ("etc", dir(0x14, &[])),
        ("proc", dir(0x15, &[])), ("sys", dir(0x16, &[])), ("dev", dir(0x17, &[]))]);
    let root = ROOT.get_or_init(|| Dentry::new_root(root_inode.clone())).clone();
    let _ = HOST_ROOT_INODE.set(root_inode.clone());
    vfs::set_root_dentry_provider(root_provider);
    register_test_mount(None, Arc::new(NamedFs { n: "ext4", root: root_inode })).expect("root mount");
    let (_, d) = vfs::path_lookup(root.clone(), root.clone(), "/run", LookupFlags::default()).expect("run dir");
    register_test_mount(Some(d), Arc::new(NamedFs { n: "tmpfs", root: facdir(0x400) })).expect("mount /run");
    root
}

fn mount_pseudo(root: &Arc<Dentry>, path: &str, name: &'static str, ino: u64) {
    let (_, d) = vfs::path_lookup(root.clone(), root.clone(), path, LookupFlags::default()).expect(path);
    register_test_mount(Some(d), Arc::new(NamedFs { n: name, root: facdir(ino) })).expect("pseudo mount");
}

fn assert_staged_proc_identity(root: &Arc<Dentry>, root_mnt: u64) {
    let proc_vp = vfs::path_lookup_at_root_cred(
        root.clone(), root_mnt, root.clone(), root_mnt, "/run/systemd/mount-rootfs/proc",
        LookupFlags::default(), vfs::Cred::root()).expect("staged proc path");
    let proc_m = vfs::mount::mount_by_id(proc_vp.mnt_id).expect("staged proc mount");
    assert_eq!(proc_m.mount_point_str(), "/run/systemd/mount-rootfs/proc",
        "recursive bind clone of /proc must render at the staged root before switch-root");
    let leaf_vp = vfs::path_lookup_at_root_cred(
        root.clone(), root_mnt, root.clone(), root_mnt, "/run/systemd/mount-rootfs/proc/sys/kernel/domainname",
        LookupFlags::default(), vfs::Cred::root()).expect("staged proc leaf path");
    assert_eq!(vfs::mount::render_path_for_mount(leaf_vp.mnt_id, &leaf_vp.dentry),
        "/run/systemd/mount-rootfs/proc/sys/kernel/domainname",
        "an fd opened on the staged proc leaf must keep staged mount identity");
}

fn systemd_bind_remount_recursive_staged(root: &Arc<Dentry>, root_mnt: u64, prefix: &str) {
    let mut done: Vec<String> = Vec::new();
    for _ in 0..8 {
        let mut todo: Vec<String> = vfs::mount::snapshot().iter()
            .map(|m| m.mount_point_str())
            .filter(|p| p == prefix || p.strip_prefix(prefix).map(|r| r.starts_with('/')).unwrap_or(false))
            .filter(|p| !done.iter().any(|d| d == p))
            .collect();
        todo.sort();
        todo.dedup();
        if !done.iter().any(|d| d == prefix) && !todo.iter().any(|p| p == prefix) {
            let target = vfs::mountpoint_lookup_at_root_cred(
                root.clone(), root_mnt, root.clone(), root_mnt, prefix, vfs::Cred::root())
                .expect("systemd prefix self-bind target");
            let source = vfs::path_lookup_at_root_cred(
                root.clone(), root_mnt, root.clone(), root_mnt, prefix,
                LookupFlags::default(), vfs::Cred::root()).expect("systemd prefix self-bind source");
            vfs::mount::register_bind_clone_under(target.parent.mnt_id, target.mountpoint.clone(),
                source.mnt_id, source.dentry.clone()).expect("systemd prefix self-bind");
            continue;
        }
        if todo.is_empty() { return; }
        for p in todo {
            let vp = vfs::path_lookup_at_root_cred(
                root.clone(), root_mnt, root.clone(), root_mnt, &p,
                LookupFlags::default(), vfs::Cred::root()).expect("systemd remount target");
            vfs::mount::remount_flags_by_id(vp.mnt_id, vfs::mount::MS_RDONLY)
                .expect("systemd read-only bind remount");
            done.push(p);
        }
    }
    panic!("systemd bind-remount-recursive staged prefix did not converge");
}

#[test]
fn staged_proc_leaf_self_bind_is_visible_to_later_path_remounts() {
    let _g = guard();
    let host: u64 = 0x5150_9000;
    let sandbox: u64 = 0x5150_9001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    mount_pseudo(&root, "/proc", "procfs", 0x730);
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    common::copy_mnt_ns(host, sandbox).unwrap();
    set_ns(sandbox);
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/systemd/mount-rootfs",
        LookupFlags::default()).expect("stage");
    assert_eq!(String::from_utf8(stage_d.absolute_path()).unwrap(), "/run/systemd/mount-rootfs",
        "stage dentry should be inside /run tmpfs before bind");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    register_test_bind_path_at(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }),
        root.clone(), None).expect("bind /");
    let source_root = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("source root id");
    let stage_parent = vfs::mount::containing_mount_id(common::namespace_id(sandbox), &stage_d);
    vfs::mount::bind_submounts_rec_at(Some(source_root), &root, &stage_d, Some(stage_parent));
    assert_staged_proc_identity(&root, source_root);
    systemd_bind_remount_recursive_staged(&root, source_root, "/run/systemd/mount-rootfs/proc/sys/kernel/domainname");

    for _ in 0..4 {
        let target = vfs::mountpoint_lookup_at_root_cred(
            root.clone(), source_root, root.clone(), source_root,
            "/run/systemd/mount-rootfs/proc/sys/kernel/domainname", vfs::Cred::root())
            .expect("staged domainname mount target");
        let source = vfs::path_lookup_at_root_cred(
            root.clone(), source_root, root.clone(), source_root,
            "/run/systemd/mount-rootfs/proc/sys/kernel/domainname",
            LookupFlags::default(), vfs::Cred::root()).expect("staged domainname source");
        vfs::mount::register_bind_clone_under(target.parent.mnt_id, target.mountpoint.clone(),
            source.mnt_id, source.dentry.clone()).expect("self bind staged domainname");
        let stacked = vfs::mount::__lookup_mnt(target.parent.mnt_id, &target.mountpoint)
            .expect("self bind must be visible at the walked parent/dentry");
        let source_was_ro = vfs::mount::mount_by_id(source.mnt_id)
            .map(|m| (m.flags.load(Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0)
            .unwrap_or(false);
        if source_was_ro {
            assert_ne!(stacked.flags.load(Ordering::Acquire) & vfs::mount::MNT_RDONLY, 0,
                "bind clone of a read-only source mount must inherit read-only");
        }
        let walked = vfs::path_lookup_at_root_cred(
            root.clone(), source_root, root.clone(), source_root,
            "/run/systemd/mount-rootfs/proc/sys/kernel/domainname",
            LookupFlags::default(), vfs::Cred::root()).expect("path lookup after self bind");
        assert_eq!(walked.mnt_id, stacked.mnt_id,
            "later path remounts must resolve to the newly stacked self-bind");
        let parent = vfs::path_lookup_at_root_cred(
            root.clone(), source_root, root.clone(), source_root,
            "/run/systemd/mount-rootfs/proc/sys/kernel",
            LookupFlags::default(), vfs::Cred::root()).expect("systemd open_parent parent");
        let child = vfs::path_lookup_at_root_cred(
            parent.dentry.clone(), parent.mnt_id, root.clone(), source_root, "domainname",
            LookupFlags::default(), vfs::Cred::root()).expect("systemd fd_is_mount_point child");
        assert_eq!(child.mnt_id, stacked.mnt_id,
            "statx(parent_fd,\"domainname\") must see the visible top self-bind");
        let child_root = vfs::mount::root_dentry_for_mount_id(child.mnt_id).expect("child mount root");
        assert!(Arc::ptr_eq(&child_root, &child.dentry),
            "statx(parent_fd,\"domainname\") must report STATX_ATTR_MOUNT_ROOT");
        vfs::mount::remount_flags_by_id(walked.mnt_id, vfs::mount::MS_RDONLY)
            .expect("path-selected self bind remounts read-only");
        assert_ne!(stacked.flags.load(Ordering::Acquire) & vfs::mount::MNT_RDONLY, 0,
            "remounted bind must read back read-only for systemd convergence");
    }
}

#[test]
fn post_pivot_proc_leaf_bind_remount_loop_converges() {
    let _g = guard();
    let host: u64 = 0x5150_9002;
    let sandbox: u64 = 0x5150_9003;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    mount_pseudo(&root, "/proc", "procfs", 0x740);
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    common::copy_mnt_ns(host, sandbox).unwrap();
    set_ns(sandbox);
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/systemd/mount-rootfs",
        LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    let stage_parent = vfs::mount::containing_mount_id(common::namespace_id(sandbox), &stage_d);
    register_test_bind_path_at(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }),
        root.clone(), Some(stage_parent)).expect("bind /");
    let stage_id = vfs::mount::mount_at_path_exact(&stage_d).expect("stage bind").mnt_id;
    let source_root = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("source root id");
    vfs::mount::bind_submounts_rec_at(Some(source_root), &root, &stage_d, Some(stage_parent));
    assert_staged_proc_identity(&root, source_root);
    vfs::mount::pivot_root(&stage_d, &stage_d).expect("service pivot_root");
    let post_root_id = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("post-pivot root id");
    assert_eq!(post_root_id, stage_id, "pivot_root should make the stage bind the namespace root");
    let new_root = vfs::mount::root_dentry_for_mount_id(post_root_id).expect("new root");
    let proc_rows: Vec<String> = vfs::mount::snapshot().iter()
        .filter(|m| m.mount_point_str().contains("/proc"))
        .map(|m| format!("{} parent={} mp={} root_ino={:?}", m.mnt_id, m.parent_id.load(Ordering::Acquire),
            m.mount_point_str(), m.mnt_root().and_then(|d| d.inode()).map(|i| i.ino())))
        .collect();
    let proc_d = vfs::d_lookup(&new_root, "proc").expect("proc dentry cached");
    let proc_m = vfs::mount::__lookup_mnt(post_root_id, &proc_d)
        .expect("post-pivot crossing hash lacks /proc under root");
    let proc_root = proc_m.mnt_root().expect("proc root dentry");
    assert!(proc_root.inode().and_then(|i| i.lookup("sys").ok()).is_some(),
        "post-pivot proc mount root cannot look up sys; rows={proc_rows:?}");
    let proc_vp = vfs::path_lookup_at_root_cred(
        new_root.clone(), post_root_id, new_root.clone(), post_root_id, "/proc",
        LookupFlags::default(), vfs::Cred::root()).expect("/proc vp");
    assert_eq!(proc_vp.mnt_id, proc_m.mnt_id,
        "path walk to /proc crossed into wrong mount; rows={proc_rows:?}");
    assert_eq!(proc_vp.inode.ino(), 0x740,
        "path walk to /proc landed on wrong inode; rows={proc_rows:?}");
    assert!(vfs::path_lookup_at_root_cred(
        new_root.clone(), post_root_id, new_root.clone(), post_root_id, "/proc",
        LookupFlags::default(), vfs::Cred::root()).is_ok(), "post-pivot /proc missing; rows={proc_rows:?}");
    assert!(vfs::path_lookup_at_root_cred(
        new_root.clone(), post_root_id, new_root.clone(), post_root_id, "/proc/sys",
        LookupFlags::default(), vfs::Cred::root()).is_ok(), "post-pivot /proc/sys missing; rows={proc_rows:?}");

    for _ in 0..4 {
        let target = vfs::mountpoint_lookup_at_root_cred(
            new_root.clone(), post_root_id, new_root.clone(), post_root_id,
            "/proc/sys/kernel/domainname", vfs::Cred::root())
            .expect("post-pivot domainname mount target");
        let source = vfs::path_lookup_at_root_cred(
            new_root.clone(), post_root_id, new_root.clone(), post_root_id,
            "/proc/sys/kernel/domainname",
            LookupFlags::default(), vfs::Cred::root()).expect("post-pivot domainname source");
        vfs::mount::register_bind_clone_under(target.parent.mnt_id, target.mountpoint.clone(),
            source.mnt_id, source.dentry.clone()).expect("self bind post-pivot domainname");
        assert_eq!(vfs::mount::propagate_mount(&target.mountpoint), 0,
            "post-pivot proc leaf self-bind must not originate propagation from an rslave service tree");
        let stacked = vfs::mount::__lookup_mnt(target.parent.mnt_id, &target.mountpoint)
            .expect("self bind must be visible at the walked parent/dentry");
        assert_eq!(stacked.mount_point_str(), "/proc/sys/kernel/domainname",
            "post-pivot mountinfo target must be visible under /proc, not the old stage path");
        let parent = vfs::path_lookup_at_root_cred(
            new_root.clone(), post_root_id, new_root.clone(), post_root_id,
            "/proc/sys/kernel", LookupFlags::default(), vfs::Cred::root())
            .expect("systemd open_parent parent after pivot");
        let child = vfs::path_lookup_at_root_cred(
            parent.dentry.clone(), parent.mnt_id, new_root.clone(), post_root_id, "domainname",
            LookupFlags::default(), vfs::Cred::root())
            .expect("systemd fd_is_mount_point child after pivot");
        assert_eq!(child.mnt_id, stacked.mnt_id,
            "statx(parent_fd,\"domainname\") must see the visible top post-pivot self-bind");
        let child_root = vfs::mount::root_dentry_for_mount_id(child.mnt_id).expect("child mount root");
        assert!(Arc::ptr_eq(&child_root, &child.dentry),
            "post-pivot statx(parent_fd,\"domainname\") must report STATX_ATTR_MOUNT_ROOT");
    }

    let mut seen_top = None;
    for m in vfs::mount::snapshot() {
        if m.mount_point_str() == "/proc/sys/kernel/domainname" {
            seen_top = Some(m.mnt_id);
        }
    }
    let top = seen_top.expect("systemd mountinfo scan must see the bind prefix");
    vfs::mount::mnt_setattr_tree_by_id(top, vfs::mount::MNT_RDONLY, 0)
        .expect("recursive mount_setattr on the top proc leaf must not EBUSY");
    let top_m = vfs::mount::mount_by_id(top).expect("top mount");
    assert_ne!(top_m.flags.load(Ordering::Acquire) & vfs::mount::MNT_RDONLY, 0,
        "systemd convergence must read back the top proc leaf as read-only");
}

#[test]
fn post_ms_move_root_uses_mount_identity_not_stale_dentry_path() {
    let _g = guard();
    let host: u64 = 0x5150_9004;
    let sandbox: u64 = 0x5150_9005;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    mount_pseudo(&root, "/proc", "procfs", 0x750);
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    common::copy_mnt_ns(host, sandbox).unwrap();
    set_ns(sandbox);
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/systemd/mount-rootfs",
        LookupFlags::default()).expect("stage");
    assert_eq!(String::from_utf8(stage_d.absolute_path()).unwrap(), "/run/systemd/mount-rootfs",
        "stage dentry should be inside /run tmpfs before bind");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    let stage_parent = vfs::mount::containing_mount_id(common::namespace_id(sandbox), &stage_d);
    register_test_bind_path_at(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }),
        root.clone(), Some(stage_parent)).expect("bind /");
    let stage_id = vfs::mount::mount_at_path_exact(&stage_d).expect("stage bind").mnt_id;
    let source_root = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("source root id");
    vfs::mount::bind_submounts_rec_at(Some(source_root), &root, &stage_d, Some(stage_parent));
    assert_staged_proc_identity(&root, source_root);
    let before_rows: Vec<String> = vfs::mount::snapshot().iter()
        .map(|m| format!("{} parent={} mp={}", m.mnt_id, m.parent_id.load(Ordering::Acquire), m.mount_point_str()))
        .collect();

    vfs::mount::move_mount_by_id_to(stage_id, Some(source_root), &root).expect("MS_MOVE stage to /");
    assert_eq!(vfs::mount::root_mount_id(common::namespace_id(sandbox)), Some(stage_id),
        "MS_MOVE to / must make the moved mount the namespace root");
    let moved_root = vfs::mount::root_dentry_for_mount_id(stage_id).expect("moved root dentry");
    assert_eq!(vfs::mount::render_path_for_mount(stage_id, &moved_root), "/",
        "relative chroot(\".\") must store the mount-aware path, not dentry.absolute_path()");
    assert_eq!(String::from_utf8(moved_root.absolute_path()).unwrap(), "/",
        "bind-root dentry for / carries source identity");

    for _ in 0..4 {
        let target = vfs::mountpoint_lookup_at_root_cred(
            moved_root.clone(), stage_id, moved_root.clone(), stage_id,
            "/proc/sys/kernel/domainname", vfs::Cred::root())
            .expect("post-MS_MOVE domainname mount target");
        let source = vfs::path_lookup_at_root_cred(
            moved_root.clone(), stage_id, moved_root.clone(), stage_id,
            "/proc/sys/kernel/domainname",
            LookupFlags::default(), vfs::Cred::root()).expect("post-MS_MOVE domainname source");
        let fd_target = vfs::mount_target_from_resolved_path(source.clone());
        assert_eq!(fd_target.parent.mnt_id, source.mnt_id,
            "mount target through /proc/self/fd/N must use the resolved fd vfsmount");
        assert!(Arc::ptr_eq(&fd_target.mountpoint, &source.dentry),
            "mount target through /proc/self/fd/N must keep the resolved fd dentry");
        vfs::mount::register_bind_clone_under(fd_target.parent.mnt_id, fd_target.mountpoint.clone(),
            source.mnt_id, source.dentry.clone()).expect("self bind post-MS_MOVE domainname");
        let stacked = vfs::mount::__lookup_mnt(fd_target.parent.mnt_id, &fd_target.mountpoint)
            .expect("self bind visible after MS_MOVE");
        let rows: Vec<String> = vfs::mount::snapshot().iter()
            .map(|m| format!("{} parent={} mp={}", m.mnt_id, m.parent_id.load(Ordering::Acquire), m.mount_point_str()))
            .collect();
        assert_eq!(stacked.mount_point_str(), "/proc/sys/kernel/domainname",
            "mountinfo target after MS_MOVE must be rooted at /proc, not /run/systemd/mount-rootfs/proc; target_parent={} source_mnt={} stage_id={} source_root={} before={:?} rows={rows:?}",
            target.parent.mnt_id, source.mnt_id, stage_id, source_root, before_rows);
        let parent = vfs::path_lookup_at_root_cred(
            moved_root.clone(), stage_id, moved_root.clone(), stage_id,
            "/proc/sys/kernel", LookupFlags::default(), vfs::Cred::root())
            .expect("systemd open_parent parent after MS_MOVE");
        let child = vfs::path_lookup_at_root_cred(
            parent.dentry.clone(), parent.mnt_id, moved_root.clone(), stage_id, "domainname",
            LookupFlags { no_follow_final: true, follow: false, ..Default::default() }, vfs::Cred::root())
            .expect("systemd statx(parent_fd,\"domainname\",AT_SYMLINK_NOFOLLOW) after MS_MOVE");
        assert_eq!(child.mnt_id, stacked.mnt_id,
            "statx(parent_fd,\"domainname\") must resolve to the newest top self-bind after MS_MOVE; rows={rows:?}");
        let child_root = vfs::mount::root_dentry_for_mount_id(child.mnt_id).expect("child mount root");
        assert!(Arc::ptr_eq(&child_root, &child.dentry),
            "statx(parent_fd,\"domainname\") must report STATX_ATTR_MOUNT_ROOT after MS_MOVE; rows={rows:?}");
        vfs::mount::mnt_setattr_tree_by_id(stacked.mnt_id, vfs::mount::MNT_RDONLY, 0)
            .expect("recursive mount_setattr on the post-MS_MOVE proc leaf must not EBUSY");
        assert_ne!(stacked.flags.load(Ordering::Acquire) & vfs::mount::MNT_RDONLY, 0,
            "post-MS_MOVE recursive mount_setattr must read back read-only");
        vfs::mount::remount_flags_by_id(stacked.mnt_id, vfs::mount::MS_RDONLY)
            .expect("path-selected post-MS_MOVE self bind remounts read-only");
        assert_ne!(stacked.flags.load(Ordering::Acquire) & vfs::mount::MNT_RDONLY, 0,
            "post-MS_MOVE self bind must read back read-only for systemd convergence");
    }
}

#[test]
fn post_ms_move_domainname_reused_procfd_target_converges() {
    let _g = guard();
    let host: u64 = 0x5150_9008;
    let sandbox: u64 = 0x5150_9009;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    mount_pseudo(&root, "/proc", "procfs", 0x770);
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    common::copy_mnt_ns(host, sandbox).unwrap();
    set_ns(sandbox);
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/systemd/mount-rootfs",
        LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    let stage_parent = vfs::mount::containing_mount_id(common::namespace_id(sandbox), &stage_d);
    register_test_bind_path_at(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }),
        root.clone(), Some(stage_parent)).expect("bind /");
    let stage_id = vfs::mount::mount_at_path_exact(&stage_d).expect("stage bind").mnt_id;
    let source_root = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("source root id");
    vfs::mount::bind_submounts_rec_at(Some(source_root), &root, &stage_d, Some(stage_parent));
    assert_staged_proc_identity(&root, source_root);
    vfs::mount::move_mount_by_id_to(stage_id, Some(source_root), &root).expect("MS_MOVE stage to /");
    let moved_root = vfs::mount::root_dentry_for_mount_id(stage_id).expect("moved root dentry");

    let fd_path = vfs::path_lookup_at_root_cred(
        moved_root.clone(), stage_id, moved_root.clone(), stage_id,
        "/proc/sys/kernel/domainname", LookupFlags::default(), vfs::Cred::root())
        .expect("open /proc/sys/kernel/domainname before bind loop");
    let fd_target = vfs::mount_target_from_resolved_path(fd_path.clone());
    assert_eq!(fd_target.parent.mnt_id, fd_path.mnt_id,
        "pre-bind procfd target for a non-mount-root leaf starts at the fd's vfsmount");

    for _ in 0..4 {
        let source = vfs::path_lookup_at_root_cred(
            moved_root.clone(), stage_id, moved_root.clone(), stage_id,
            "/proc/sys/kernel/domainname", LookupFlags::default(), vfs::Cred::root())
            .expect("source through newest visible bind");
        vfs::mount::register_bind_clone_under(fd_target.parent.mnt_id, fd_target.mountpoint.clone(),
            source.mnt_id, source.dentry.clone()).expect("self bind through reused procfd target");
        let stacked = vfs::mount::__lookup_mnt(fd_target.parent.mnt_id, &fd_target.mountpoint)
            .expect("reused procfd self bind visible at fd parent/dentry");
        let parent = vfs::path_lookup_at_root_cred(
            moved_root.clone(), stage_id, moved_root.clone(), stage_id,
            "/proc/sys/kernel", LookupFlags::default(), vfs::Cred::root())
            .expect("systemd open_parent parent after reused-procfd bind");
        let child = vfs::path_lookup_at_root_cred(
            parent.dentry.clone(), parent.mnt_id, moved_root.clone(), stage_id, "domainname",
            LookupFlags { no_follow_final: true, follow: false, ..Default::default() }, vfs::Cred::root())
            .expect("systemd statx(parent_fd,\"domainname\") after reused-procfd bind");
        assert_eq!(child.mnt_id, stacked.mnt_id,
            "statx(parent_fd,\"domainname\") must see reused-procfd top bind");
        let root_d = vfs::mount::root_dentry_for_mount_id(child.mnt_id).expect("child mount root");
        assert!(Arc::ptr_eq(&root_d, &child.dentry),
            "reused-procfd top bind must report STATX_ATTR_MOUNT_ROOT");
    }
}

#[test]
fn ms_move_to_procfd_preserves_staged_target_render_path() {
    let _g = guard();
    let host: u64 = 0x5150_9006;
    let sandbox: u64 = 0x5150_9007;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    mount_pseudo(&root, "/proc", "procfs", 0x760);
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    common::copy_mnt_ns(host, sandbox).unwrap();
    set_ns(sandbox);
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/systemd/mount-rootfs",
        LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    let stage_parent = vfs::mount::containing_mount_id(common::namespace_id(sandbox), &stage_d);
    register_test_bind_path_at(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }),
        root.clone(), Some(stage_parent)).expect("bind /");
    let source_root = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("source root id");
    vfs::mount::bind_submounts_rec_at(Some(source_root), &root, &stage_d, Some(stage_parent));

    let proc_target = vfs::mountpoint_lookup_at_root_cred(
        root.clone(), source_root, root.clone(), source_root,
        "/run/systemd/mount-rootfs/proc", vfs::Cred::root()).expect("staged proc mountpoint");
    let target_display = vfs::mount::render_path_for_mount(proc_target.parent.mnt_id, &proc_target.mountpoint);
    assert_eq!(target_display, "/run/systemd/mount-rootfs/proc");
    assert_ne!(String::from_utf8(proc_target.mountpoint.absolute_path()).unwrap(), target_display,
        "regression requires a bind-shared dentry whose bare path differs from mount-tree display");
    assert_ne!(vfs::mount::unregister_top(&proc_target.mountpoint, true), 0,
        "systemd detaches the staged proc mount before moving in the private procfs instance");

    let (_, tmp_proc_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/systemd/namespace-proc",
        LookupFlags::default()).expect("private proc staging point");
    register_test_mount(Some(tmp_proc_d.clone()), Arc::new(NamedFs { n: "procfs", root: facdir(0x761) }))
        .expect("private procfs mount");
    let private_proc_id = vfs::mount::mount_at_path_exact(&tmp_proc_d).expect("private proc mount").mnt_id;
    vfs::mount::move_mount_by_id_to_rendered(private_proc_id, Some(proc_target.parent.mnt_id),
        &proc_target.mountpoint, target_display.clone()).expect("MS_MOVE private proc to staged proc");
    let moved = vfs::mount::mount_by_id(private_proc_id).expect("moved proc mount");
    assert_eq!(moved.mount_point_str(), target_display,
        "MS_MOVE through /proc/self/fd/N must keep the target's mount-aware staged path");

    systemd_bind_remount_recursive_staged(&root, source_root, "/run/systemd/mount-rootfs/proc/sys/kernel/domainname");
}
