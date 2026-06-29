//! B5: the intrusive mount tree + namespaces + propagation + MNT_* writers +
//! the POLLPRI mount-generation notify. Exercises the real (global) mount
//! engine via the hosted dentry-identity fixture (`common`), no QEMU.
//!
//! Serializes on `SERIAL` and resets the ns provider on entry, like
//! `mount_resolver.rs` (one process-global table).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::mount::Propagation;
use vfs::{FileType, InodeRef, KResult, VfsError};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0);
    common::install();
    g
}

struct TFs { root_ino: u64 }
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
    fn root(&self) -> Option<InodeRef> { Some(Arc::new(TDir { ino: self.root_ino })) }
}
struct TDir { ino: u64 }
impl Inode for TDir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TFs { root_ino: ino }) }

// (1) children-of(parent) via the intrusive tree (mnt_mounts), not a scan:
// has_child_mounts reads the child list; it falls to false when the children
// are unmounted.
#[test]
fn children_via_intrusive_tree() {
    let _g = guard();
    vfs::mount::set_current_ns_provider(|| 0xC1);
    common::register("/", fs(0x1)).expect("root");
    common::register("/a", fs(0x2)).expect("a");
    common::register("/a/b", fs(0x3)).expect("b");
    common::register("/a/c", fs(0x4)).expect("c");
    assert!(vfs::mount::has_child_mounts(&common::dentry("/a"), 0xC1), "/a has children");
    assert!(!vfs::mount::has_child_mounts(&common::dentry("/a/b"), 0xC1), "/a/b is a leaf");
    // Children of /a are exactly {b, c} by parent_id (the tree), derived from
    // the snapshot — the parent link the child list rebuilds from.
    let a_id = common::mount_at_path_exact("/a").unwrap().mnt_id;
    let kids: Vec<u64> = vfs::mount::snapshot().into_iter()
        .filter(|m| vfs::mount::parent_mnt_id(m) == a_id && m.mnt_id != a_id)
        .map(|m| m.mnt_id).collect();
    assert_eq!(kids.len(), 2, "two children of /a");
    common::unregister("/a/b");
    let kids2: Vec<u64> = vfs::mount::snapshot().into_iter()
        .filter(|m| vfs::mount::parent_mnt_id(m) == a_id && m.mnt_id != a_id).collect::<Vec<_>>()
        .into_iter().map(|m| m.mnt_id).collect();
    assert_eq!(kids2.len(), 1, "one child of /a after umount /a/b");
    assert!(vfs::mount::has_child_mounts(&common::dentry("/a"), 0xC1), "/a still has /a/c");
    common::unregister("/a/c");
    assert!(!vfs::mount::has_child_mounts(&common::dentry("/a"), 0xC1), "/a now a leaf");
}

// (2) propagation: a mount under a SHARED parent replicates to peers AND to a
// slave of the group; the slave does NOT propagate back up to the master.
#[test]
fn propagation_peers_and_slave() {
    let _g = guard();
    vfs::mount::set_current_ns_provider(|| 0xC2);
    common::register("/", fs(0x1)).expect("root");
    common::register("/sa", fs(0xA)).expect("sa");
    common::set_propagation("/sa", Propagation::Shared).expect("share sa");
    let pg = common::peer_group_of("/sa");
    common::register("/sb", fs(0xB)).expect("sb");
    common::join_peer_group("/sb", pg);            // peer of sa
    common::register("/sc", fs(0xC)).expect("sc");
    common::join_peer_group("/sc", pg);            // joins group...
    common::set_propagation("/sc", Propagation::Slave).expect("slave sc"); // ...then slave
    // Mount under sa, propagate → reaches peer sb AND slave sc.
    common::register("/sa/x", fs(0x11)).expect("under sa");
    let n = common::propagate_mount("/sa/x");
    assert_eq!(n, 2, "propagated to peer + slave");
    assert_eq!(common::mount_root_at("/sb/x").map(|i| i.ino()), Some(0x11), "peer got it");
    assert_eq!(common::mount_root_at("/sc/x").map(|i| i.ino()), Some(0x11), "slave got it");
    // A mount under the SLAVE does NOT propagate up to the master/peers.
    common::register("/sc/y", fs(0x22)).expect("under slave");
    assert_eq!(common::propagate_mount("/sc/y"), 0, "slave does not propagate to master");
    assert!(common::mount_root_at("/sa/y").is_none(), "master unaffected by slave event");
}

// (2b) regression: propagation ORIGINATES only from a SHARED parent (Linux
// IS_MNT_SHARED(dest) gate in attach_recursive_mnt/propagate_umount). A master
// demoted to a pure SLAVE keeps a stale mnt_slave_list, but a mount under it
// must NOT reach those slaves — a slave receives from its master, never sends.
#[test]
fn slave_parent_does_not_originate_propagation() {
    let _g = guard();
    vfs::mount::set_current_ns_provider(|| 0xC2B);
    common::register("/", fs(0x1)).expect("root");
    common::register("/m1", fs(0xA1)).expect("m1");
    common::set_propagation("/m1", Propagation::Shared).expect("share m1");
    let pg = common::peer_group_of("/m1");
    common::register("/m2", fs(0xA2)).expect("m2");
    common::join_peer_group("/m2", pg);                                    // peer of m1
    common::set_propagation("/m2", Propagation::Slave).expect("slave m2"); // → m1.slave_list=[m2]
    // While m1 is SHARED the slave link is live: a mount under m1 reaches m2.
    common::register("/m1/probe", fs(0x99)).expect("probe under m1");
    assert_eq!(common::propagate_mount("/m1/probe"), 1, "shared master reaches its slave");
    assert_eq!(common::mount_root_at("/m2/probe").map(|i| i.ino()), Some(0x99), "slave got probe");
    // Demote the master to a PURE SLAVE (its stale mnt_slave_list still holds m2).
    common::set_propagation("/m1", Propagation::Slave).expect("demote m1");
    // Same topology, only m1's propagation type changed: it must NOT originate.
    common::register("/m1/x", fs(0x11)).expect("under demoted m1");
    assert_eq!(common::propagate_mount("/m1/x"), 0, "pure slave does not originate propagation");
    assert!(common::mount_root_at("/m2/x").is_none(), "stale slave must not receive a non-shared parent's event");
}

// (3) MNT_RDONLY → EROFS on write; mnt_writers blocks remount-RO.
#[test]
fn rdonly_blocks_write_and_remount_holds_writers() {
    let _g = guard();
    vfs::mount::set_current_ns_provider(|| 0xC3);
    common::register("/", fs(0x1)).expect("root");
    common::register("/rw", fs(0x2)).expect("rw");
    let m = common::mount_at_path_exact("/rw").expect("mount");
    // Writable: want_write succeeds and bumps the writer count.
    vfs::mount::mnt_want_write(&m).expect("rw allows write");
    assert!(m.writers() > 0, "writer counted");
    // remount-RO is refused while a writer is held (Linux mnt_hold_writers).
    assert!(matches!(
        vfs::mount::remount_flags(&common::dentry("/rw"), vfs::mount::MNT_RDONLY),
        Err(VfsError::Ebusy)), "remount-RO blocked by active writer");
    vfs::mount::mnt_drop_write(&m);
    // Now remount-RO succeeds; subsequent want_write → EROFS.
    vfs::mount::remount_flags(&common::dentry("/rw"), vfs::mount::MNT_RDONLY).expect("remount ro");
    assert!(matches!(vfs::mount::mnt_want_write(&m), Err(VfsError::Erofs)), "RO → EROFS");
    // Clearing RDONLY re-allows writes.
    vfs::mount::remount_flags(&common::dentry("/rw"), 0).expect("remount rw");
    vfs::mount::mnt_want_write(&m).expect("writable again");
    vfs::mount::mnt_drop_write(&m);
}

// (4) mount-generation bumps on every tree mutation; the mountinfo poll helper
// returns POLLPRI when a reader's last-seen gen is stale, then clears.
#[test]
fn mount_generation_and_pollpri() {
    let _g = guard();
    vfs::mount::set_current_ns_provider(|| 0xC4);
    let last = AtomicU64::new(vfs::mount::mount_generation());
    // Current → no POLLPRI (just readable).
    let m0 = vfs::mount::mountinfo_poll_mask(&last);
    assert_eq!(m0 & vfs::POLL_PRI, 0, "no change → no POLLPRI");
    assert!(m0 & vfs::POLL_IN != 0, "always readable");
    // Each mutation strictly advances the generation.
    let g0 = vfs::mount::mount_generation();
    common::register("/", fs(0x1)).expect("root");
    common::register("/g", fs(0x2)).expect("g");
    let g1 = vfs::mount::mount_generation();
    assert!(g1 > g0, "register advanced gen");
    // Stale reader → POLLPRI signalled, then cleared on the next poll.
    let mp = vfs::mount::mountinfo_poll_mask(&last);
    assert!(mp & vfs::POLL_PRI != 0, "stale gen → POLLPRI");
    assert_eq!(vfs::mount::mountinfo_poll_mask(&last) & vfs::POLL_PRI, 0, "caught up → cleared");
    // umount, remount, set_propagation, move each bump too.
    let g2 = vfs::mount::mount_generation();
    common::set_propagation("/g", Propagation::Shared).expect("share");
    assert!(vfs::mount::mount_generation() > g2, "set_propagation bumped");
    let g3 = vfs::mount::mount_generation();
    common::unregister("/g");
    assert!(vfs::mount::mount_generation() > g3, "umount bumped");
}

// (5) copy_mnt_ns isolates a child ns: it gets an independent copy (fresh
// mnt_id), a later mount in the child is invisible to the parent, and a SHARED
// parent mount is demoted to a SLAVE in the child (no propagate-back leak).
#[test]
fn copy_mnt_ns_isolates_child() {
    let _g = guard();
    vfs::mount::set_current_ns_provider(|| 0x100);
    common::register("/", fs(0x1)).expect("root");
    common::register("/base", fs(0x7001)).expect("base");
    common::set_propagation("/base", Propagation::Shared).expect("share base");
    let base_id = vfs::mount::snapshot().into_iter()
        .find(|m| m.mount_point_str() == "/base").unwrap().mnt_id;
    // Copy ns 0x100 → 0x101.
    vfs::mount::copy_mnt_ns(0x100, 0x101);
    vfs::mount::set_current_ns_provider(|| 0x101);
    assert_eq!(common::mount_root_at("/base").map(|i| i.ino()), Some(0x7001), "child sees copy");
    let child = vfs::mount::snapshot().into_iter()
        .find(|m| m.mount_point_str() == "/base").unwrap();
    assert_ne!(child.mnt_id, base_id, "fresh mnt_id in child");
    // The shared mount became a SLAVE in the child (containment).
    assert_eq!(Propagation::from_u8(child.propagation.load(Ordering::Acquire)), Propagation::Slave,
        "child-ns clone of a shared mount is a slave");
    // A new mount in the child is invisible to the parent.
    common::register("/only-child", fs(0x7002)).expect("child-only");
    vfs::mount::set_current_ns_provider(|| 0x100);
    assert!(common::mount_root_at("/only-child").is_none(), "parent can't see child's mount");
}

// (8) ns reap: when the last task of a child ns exits, its per-ns mounts are
// detached and the ns object is dropped.
#[test]
fn ns_reap_on_last_task_exit() {
    let _g = guard();
    vfs::mount::set_current_ns_provider(|| 0x200);
    common::register("/", fs(0x1)).expect("root");
    vfs::mount::copy_mnt_ns(0x200, 0x201);
    vfs::mount::mnt_ns_enter(0x201);          // one task in the child ns
    vfs::mount::set_current_ns_provider(|| 0x201);
    common::register("/child", fs(0x9)).expect("child mount");
    assert!(!vfs::mount::snapshot().is_empty(), "child ns has mounts");
    // Last task exits → reap.
    let reaped = vfs::mount::mnt_ns_exit(0x201);
    assert!(reaped, "ns reaped at last task exit");
    assert!(vfs::mount::snapshot().is_empty(), "child ns mounts gone after reap");
}

// (6) pivot_root invokes the chroot_fs_refs hook with (old_root, new_root).
static HOOK_OLD: AtomicU64 = AtomicU64::new(0);
static HOOK_NEW: AtomicU64 = AtomicU64::new(0);
fn record_chroot(old: u64, new: u64) { HOOK_OLD.store(old, Ordering::Release); HOOK_NEW.store(new, Ordering::Release); }

#[test]
fn pivot_root_fires_chroot_refs() {
    let _g = guard();
    vfs::mount::set_chroot_refs_hook(record_chroot);
    vfs::mount::set_current_ns_provider(|| 0x300);
    common::register("/", fs(0xA)).expect("root");
    common::register("/nr", fs(0xB)).expect("newroot");
    let old_root = vfs::mount::root_mount_id(0x300).unwrap();
    let nr_id = common::mount_at_path_exact("/nr").unwrap().mnt_id;
    HOOK_OLD.store(0, Ordering::Release); HOOK_NEW.store(0, Ordering::Release);
    common::pivot_root("/nr", "/nr/old").expect("pivot");
    assert_eq!(HOOK_OLD.load(Ordering::Acquire), old_root, "hook got old root id");
    assert_eq!(HOOK_NEW.load(Ordering::Acquire), nr_id, "hook got new root id");
}
