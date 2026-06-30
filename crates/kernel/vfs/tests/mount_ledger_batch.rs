//! Mount-ledger batch wiring: [D11] MNT_LOCKED enforcement + MNT_INTERNAL on
//! the namespace-root producer; [D14] atomic `attach_recursive_mnt`
//! (attach+propagate as one engine call); [D26] the production
//! `sweep_expired_mounts` entry point; [D32] uniform `check_mnt` gate on the
//! by-id mutators. Exercises the real global mount engine via the hosted
//! dentry-identity fixture; process-global table ⇒ SERIAL-guarded with a fresh
//! ns id per test so re-registering "/" never collides.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::mount::{MNT_INTERNAL, MNT_LOCKED, MS_RDONLY};
use vfs::{FileType, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, default_file_ops, mk_mode};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());
static CUR_NS: AtomicU64 = AtomicU64::new(0);
fn ns_provider() -> u64 { CUR_NS.load(Ordering::Relaxed) }
fn set_ns(ns: u64) {
    CUR_NS.store(ns, Ordering::Relaxed);
    vfs::mount::set_current_ns_provider(ns_provider);
}
fn guard(ns: u64) -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    common::install();
    set_ns(ns);
    g
}

struct TFs { root_ino: u64 }
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
    fn root(&self) -> Option<InodeRef> { Some(make_tdir(self.root_ino)) }
}
struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn make_tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TFs { root_ino: ino }) }
fn mount_obj(p: &str) -> Arc<vfs::mount::Mount> {
    common::mount_at_path_exact(p).expect("mount exists")
}
fn mounted(p: &str) -> bool { common::mount_at_path_exact(p).is_some() }

// [D11] The namespace-root mount is MNT_INTERNAL (Linux marks rootfs/kern_mount
// internal); a non-root child is not.
#[test]
fn ns_root_mount_is_internal() {
    let _g = guard(0xD110);
    common::register("/", fs(0x1)).expect("root");
    common::register("/child", fs(0xA)).expect("child");
    assert!(mount_obj("/").is_internal(), "ns root mount is MNT_INTERNAL");
    assert!(!mount_obj("/child").is_internal(), "a normal child mount is not internal");
    assert_eq!(mount_obj("/child").internal_flags() & MNT_INTERNAL, 0);
}

// [D11] umount of a MNT_LOCKED mount is rejected (unregister_top removes
// nothing → EINVAL at the syscall); clearing the lock lets it umount.
#[test]
fn locked_mount_rejects_umount() {
    let _g = guard(0xD111);
    common::register("/", fs(0x1)).expect("root");
    common::register("/lk", fs(0xB)).expect("lk");
    let m = mount_obj("/lk");
    m.set_internal_flag(MNT_LOCKED);
    assert_eq!(vfs::mount::unregister_top(&common::dentry("/lk"), false), 0,
        "locked mount is not unmountable");
    assert!(mounted("/lk"), "locked mount survives the umount attempt");
    // Unlocked → umount succeeds.
    m.clear_internal_flag(MNT_LOCKED);
    assert_eq!(vfs::mount::unregister_top(&common::dentry("/lk"), false), 1, "unlocked umounts");
    assert!(!mounted("/lk"));
}

// [D11] move of a MNT_LOCKED mount is rejected with EINVAL.
#[test]
fn locked_mount_rejects_move() {
    let _g = guard(0xD112);
    common::register("/", fs(0x1)).expect("root");
    common::register("/ms", fs(0xC)).expect("ms");
    mount_obj("/ms").set_internal_flag(MNT_LOCKED);
    assert!(matches!(common::move_mount("/ms", "/md"), Err(VfsError::Einval)),
        "locked mount cannot be moved");
    assert!(mounted("/ms"), "still at the original point");
    // Unlocked → move works.
    mount_obj("/ms").clear_internal_flag(MNT_LOCKED);
    common::move_mount("/ms", "/md").expect("unlocked move");
    assert!(mounted("/md") && !mounted("/ms"));
}

// [D14] attach_recursive_mnt grafts AND propagates in a single engine call: a
// mount established under a SHARED parent reaches the parent's peer at the
// mirrored path with no separate propagate_mount step.
#[test]
fn attach_recursive_mnt_attaches_and_propagates_atomically() {
    use vfs::mount::Propagation;
    let _g = guard(0xD140);
    common::register("/", fs(0x1)).expect("root");
    common::register("/ra", fs(0xA)).expect("ra");
    common::set_propagation("/ra", Propagation::Shared).expect("share ra");
    let pg = common::peer_group_of("/ra");
    common::register("/rb", fs(0xB)).expect("rb");
    common::join_peer_group("/rb", pg);

    // One call attaches /ra/x and propagates it to the peer /rb/x.
    let n = vfs::mount::attach_recursive_mnt(Some(common::dentry("/ra/x")), fs(0x11), None)
        .expect("attach_recursive_mnt");
    assert_eq!(n, 1, "propagated to the one peer in a single call");
    assert!(mounted("/ra/x"), "primary attached");
    let r = common::mount_root_at("/rb/x").expect("propagated mirror present");
    assert_eq!(r.ino(), 0x11, "peer mirror has the source fs root");
}

// [D26] sweep_expired_mounts runs the two-pass grace across all expire lists:
// an idle member survives the first sweep and is reaped on the second.
#[test]
fn sweep_expired_mounts_runs_two_pass_grace() {
    let _g = guard(0xD260);
    common::register("/", fs(0x1)).expect("root");
    common::register("/se", fs(0xE)).expect("se");
    let list = vfs::mount::expire_list_create();
    vfs::mount::mnt_expire_add(list, &mount_obj("/se"));
    assert_eq!(vfs::mount::sweep_expired_mounts(), 0, "first sweep only marks");
    assert!(mounted("/se"), "survives first sweep");
    assert_eq!(vfs::mount::sweep_expired_mounts(), 1, "second sweep reaps the idle mount");
    assert!(!mounted("/se"), "auto-umounted");
}

// [D32] the by-id mutators uniformly gate on check_mnt: a mnt_id from one ns
// cannot be remounted or moved from another ns.
#[test]
fn by_id_mutators_reject_foreign_ns() {
    let _g = guard(0x3220);
    common::register("/", fs(0x1)).expect("ns A root");
    common::register("/m", fs(0xA)).expect("ns A m");
    let id = mount_obj("/m").mnt_id;

    // Same ns → operations are admitted (remount succeeds).
    vfs::mount::remount_flags_by_id(id, MS_RDONLY).expect("same-ns remount");

    // Switch to a foreign ns → the by-id handle now fails the guard.
    set_ns(0x3221);
    common::register("/", fs(0xB)).expect("ns B root");
    assert!(matches!(vfs::mount::remount_flags_by_id(id, MS_RDONLY), Err(VfsError::Einval)),
        "foreign-ns remount_flags_by_id rejected");
    assert!(matches!(vfs::mount::move_mount_by_id(id, &common::dentry("/x")), Err(VfsError::Einval)),
        "foreign-ns move_mount_by_id rejected");
}
