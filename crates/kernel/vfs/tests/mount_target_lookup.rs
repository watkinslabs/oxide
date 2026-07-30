mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::{Cred, InodeRef, LookupFlags};

static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

static CUR_NS: AtomicU64 = AtomicU64::new(0);
fn cur_ns() -> vfs::mntns::MntNamespaceRef { common::namespace_for_key(CUR_NS.load(Ordering::Acquire)) }
fn set_ns(ns: u64) { CUR_NS.store(ns, Ordering::Release); }

struct NamedFs { n: &'static str, root: InodeRef }
impl FileSystem for NamedFs {
    fn name(&self) -> &str { self.n }
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
}

fn fs(name: &'static str, root: InodeRef) -> Arc<dyn FileSystem> {
    Arc::new(NamedFs { n: name, root })
}

#[test]
fn mount_target_keeps_walked_parent_mount_identity_for_shared_dentry() {
    let _g = guard();
    let ns = 0x7a13_1000;
    set_ns(ns);
    vfs::mount::set_current_ns_provider(cur_ns);
    common::install();

    let root = common::dentry("/");
    let root_inode = root.inode().expect("root inode");
    common::register("/", fs("rootfs", root_inode)).expect("root mount");
    let root_id = vfs::mount::root_mount_id(common::namespace_id(ns)).expect("root id");

    let proc_mp = common::dentry("/proc");
    common::register("/proc", fs("procfs", proc_mp.inode().unwrap())).expect("proc mount");
    let proc_vp = vfs::path_lookup_at_root_cred(
        root.clone(), root_id, root.clone(), root_id, "/proc",
        LookupFlags::default(), Cred::root()).expect("proc path");
    let proc_id = proc_vp.mnt_id;

    let stage_proc = common::dentry("/stage/proc");
    vfs::mount::register_bind_clone_under(root_id, stage_proc.clone(), proc_id, proc_vp.dentry.clone())
        .expect("stage proc bind");
    let stage_proc_id = vfs::mount::mount_at_path_exact(&stage_proc).expect("stage proc mount").mnt_id;

    let src = vfs::path_lookup_at_root_cred(
        root.clone(), root_id, root.clone(), root_id, "/proc/kallsyms",
        LookupFlags::default(), Cred::root()).expect("source kallsyms");
    let target = vfs::mountpoint_lookup_at_root_cred(
        root.clone(), root_id, root, root_id, "/stage/proc/kallsyms", Cred::root())
        .expect("staged kallsyms target");

    assert!(Arc::ptr_eq(&src.dentry, &target.mountpoint),
        "bind clone should share the procfs leaf dentry");
    assert_eq!(target.parent.mnt_id, stage_proc_id,
        "mount-target lookup must return the walked bind mount parent, not the source /proc parent");
}

#[test]
fn mount_target_accepts_resolved_dot_components() {
    let _g = guard();
    let ns = 0x7a13_1001;
    set_ns(ns);
    vfs::mount::set_current_ns_provider(cur_ns);
    common::install();

    let root = common::dentry("/");
    let root_inode = root.inode().expect("root inode");
    common::register("/", fs("rootfs", root_inode)).expect("root mount");
    let root_id = vfs::mount::root_mount_id(common::namespace_id(ns)).expect("root id");

    let work = common::dentry("/work");
    let dot = vfs::mountpoint_lookup_at_root_cred(
        work.clone(), root_id, root.clone(), root_id, ".", Cred::root(),
    ).expect("relative dot mount target");
    assert_eq!(dot.parent.mnt_id, root_id);
    assert!(Arc::ptr_eq(&dot.mountpoint, &work));

    let dotdot = vfs::mountpoint_lookup_at_root_cred(
        work, root_id, root.clone(), root_id, "..", Cred::root(),
    ).expect("relative dotdot mount target");
    assert_eq!(dotdot.parent.mnt_id, root_id);
    assert!(Arc::ptr_eq(&dotdot.mountpoint, &root));
}
