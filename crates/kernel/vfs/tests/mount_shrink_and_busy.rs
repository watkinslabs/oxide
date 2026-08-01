//! B1650: the two halves of `umount(2)`'s busy decision that were missing —
//! `shrink_submounts` (the eager reap of expirable/automounted submounts a
//! non-lazy unmount owes its target) and the PROPAGATION half of
//! `propagate_mount_busy` (a pinned peer/slave copy refuses the unmount even
//! when the mount the caller named is idle).
//!
//! Fails-before: `umount2` refused any mount with children as `EBUSY`, so an
//! autofs-managed directory could never be unmounted without `MNT_DETACH`; and
//! the busy test consulted only the named mount, so an unmount silently yanked
//! a pinned mirror out from under its users.
//!
//! Drives the REAL global mount engine through the hosted dentry-identity
//! fixture (`common`), no QEMU. Serializes on `SERIAL`.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::mount::Propagation;
use vfs::{FileType, InodeBuilder, InodeOps, InodeRef, KResult, default_file_ops, mk_mode};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());
/// Every mount notification the engine fired, as `(ns_id, mnt_id, mask)`.
static NOTIFIED: Mutex<Vec<(u64, u64, u32)>> = Mutex::new(Vec::new());

fn note(ns: u64, mnt: u64, mask: u32) {
    NOTIFIED.lock().unwrap_or_else(|e| e.into_inner()).push((ns, mnt, mask));
}
fn notifications() -> Vec<(u64, u64, u32)> {
    NOTIFIED.lock().unwrap_or_else(|e| e.into_inner()).clone()
}
fn clear_notifications() { NOTIFIED.lock().unwrap_or_else(|e| e.into_inner()).clear(); }

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(common::current_namespace);
    vfs::mount::set_mnt_notify_hook(note);
    common::install();
    clear_notifications();
    g
}

struct TFs { root_ino: u64 }
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
    fn root(&self) -> Option<InodeRef> { Some(make_tdir(self.root_ino)) }
}
struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Ok(make_tdir(0xB16)) }
}
fn make_tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TFs { root_ino: ino }) }

fn mounted(p: &str) -> bool { common::mount_at_path_exact(p).is_some() }
fn mount_obj(p: &str) -> Arc<vfs::mount::Mount> {
    common::mount_at_path_exact(p).expect("mount exists")
}
fn busy(m: &Arc<vfs::mount::Mount>) -> bool {
    vfs::mount::propagate_mount_busy(m, vfs::mount::UMOUNT_SYSCALL_REFCNT)
}
/// Register `p` as an automounter's disposable submount (Linux
/// `do_add_mount(… | MNT_SHRINKABLE)` + the expire-list enqueue).
fn expirable(list: u64, p: &str) -> Arc<vfs::mount::Mount> {
    let m = mount_obj(p);
    vfs::mount::mnt_expire_add(list, &m);
    m
}

// --- shrink_submounts ------------------------------------------------------

// The headline: a mount whose only child is an expirable submount is NOT busy,
// because the submount is reaped first. Fails-before: EBUSY forever.
#[test]
fn an_autofs_parent_becomes_unmountable_once_its_submounts_are_shrunk() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/p1", fs(0xA1)).expect("p1");
    common::register("/p1/auto", fs(0xA2)).expect("p1/auto");
    let list = vfs::mount::expire_list_create();
    expirable(list, "/p1/auto");

    let p = mount_obj("/p1");
    assert!(busy(&p), "the submount holds the parent down until it is shrunk");
    assert_eq!(vfs::mount::shrink_submounts(&p), 1, "the expirable submount is reaped");
    assert!(!mounted("/p1/auto"), "reaped submount left the tree");
    assert!(!busy(&p), "parent is unmountable now that nothing is under it");
}

// An ORDINARY submount is not the automounter's to reap: it is left alone and
// the parent stays busy. The shrink must not become a general subtree unmount.
#[test]
fn an_ordinary_submount_is_never_shrunk() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/p2", fs(0xB1)).expect("p2");
    common::register("/p2/plain", fs(0xB2)).expect("p2/plain");

    let p = mount_obj("/p2");
    assert_eq!(vfs::mount::shrink_submounts(&p), 0, "nothing expirable under p2");
    assert!(mounted("/p2/plain"), "the ordinary submount survives");
    assert!(busy(&p), "and it still makes the parent busy");
}

// A pinned expirable submount is busy in its own right and is NOT reaped, so
// the parent stays busy too — the pass never yanks a submount in use.
#[test]
fn a_pinned_expirable_submount_is_not_shrunk() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/p3", fs(0xC1)).expect("p3");
    common::register("/p3/auto", fs(0xC2)).expect("p3/auto");
    let list = vfs::mount::expire_list_create();
    let auto = expirable(list, "/p3/auto");
    vfs::mount::mntget(&auto);

    let p = mount_obj("/p3");
    assert_eq!(vfs::mount::shrink_submounts(&p), 0, "a pinned submount is busy");
    assert!(mounted("/p3/auto"), "pinned submount survives the pass");
    assert!(busy(&p), "so the parent is still busy");

    // Once the pin drops, the same pass reaps it.
    vfs::mount::mntput(&auto);
    assert_eq!(vfs::mount::shrink_submounts(&p), 1, "reaped once the pin is gone");
    assert!(!busy(&p));
}

// Nested expirable submounts collapse: the inner one is reaped first, which is
// what makes the outer one childless and reapable on the next round. A
// single-pass implementation would stop after the inner one and still report
// the parent busy.
#[test]
fn nested_expirable_submounts_collapse_over_repeated_rounds() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/p4", fs(0xD1)).expect("p4");
    common::register("/p4/a", fs(0xD2)).expect("p4/a");
    common::register("/p4/a/b", fs(0xD3)).expect("p4/a/b");
    let list = vfs::mount::expire_list_create();
    expirable(list, "/p4/a");
    expirable(list, "/p4/a/b");

    let p = mount_obj("/p4");
    assert_eq!(vfs::mount::shrink_submounts(&p), 2, "both levels collapse");
    assert!(!mounted("/p4/a/b"));
    assert!(!mounted("/p4/a"));
    assert!(!busy(&p));
}

// The search stops at a non-shrinkable mount: an expirable submount reachable
// only THROUGH an ordinary one is not the automounter's to reap here.
#[test]
fn the_search_does_not_cross_an_ordinary_submount() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/p5", fs(0xE1)).expect("p5");
    common::register("/p5/plain", fs(0xE2)).expect("p5/plain");
    common::register("/p5/plain/auto", fs(0xE3)).expect("p5/plain/auto");
    let list = vfs::mount::expire_list_create();
    expirable(list, "/p5/plain/auto");

    let p = mount_obj("/p5");
    assert_eq!(vfs::mount::shrink_submounts(&p), 0, "the ordinary mount ends the search");
    assert!(mounted("/p5/plain/auto"), "the buried expirable submount survives");
}

// Every reap goes through the shared detach path, so a mount-namespace watcher
// is told — a shrink that bypassed the choke point would silently desync every
// watcher's view of the tree.
#[test]
fn a_shrunk_submount_is_reported_to_mount_namespace_watchers() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/p6", fs(0xF1)).expect("p6");
    common::register("/p6/auto", fs(0xF2)).expect("p6/auto");
    let list = vfs::mount::expire_list_create();
    let auto = expirable(list, "/p6/auto");
    let auto_id = auto.mnt_id;
    let ns = auto.namespace_id();

    let p = mount_obj("/p6");
    clear_notifications();
    assert_eq!(vfs::mount::shrink_submounts(&p), 1);
    assert!(notifications().iter().any(|&(n, id, mask)| {
        n == ns && id == auto_id && mask == vfs::mount::FS_MNT_DETACH
    }), "the shrink reported the submount leaving the namespace: {:?}", notifications());
}

// A reaped mount leaves the expire list with it: the automounter's next sweep
// must not walk an id that no longer names anything.
#[test]
fn a_shrunk_submount_leaves_its_expire_list() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/p7", fs(0x1F1)).expect("p7");
    common::register("/p7/auto", fs(0x1F2)).expect("p7/auto");
    let list = vfs::mount::expire_list_create();
    expirable(list, "/p7/auto");

    assert_eq!(vfs::mount::shrink_submounts(&mount_obj("/p7")), 1);
    // A fresh mount at the same position must not be reaped by that stale entry.
    common::register("/p7/auto", fs(0x1F3)).expect("re-mount");
    assert_eq!(vfs::mount::mark_mounts_for_expiry(list), 0, "no stale members remain");
    assert_eq!(vfs::mount::mark_mounts_for_expiry(list), 0, "and none on the next sweep");
    assert!(mounted("/p7/auto"), "the re-mount is untouched by the drained list");
}

// --- the propagation half of propagate_mount_busy --------------------------

// A pinned PEER copy refuses the unmount of a mount that is itself perfectly
// idle: unmounting it would remove the pinned mirror too. This is the half that
// did not exist.
#[test]
fn a_pinned_peer_mirror_makes_an_idle_mount_busy() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/s1", fs(0x2A1)).expect("s1");
    common::set_propagation("/s1", Propagation::Shared).expect("share s1");
    let group = common::peer_group_of("/s1");
    assert!(group != 0, "s1 has a peer group");
    common::register("/s2", fs(0x2A2)).expect("s2");
    common::join_peer_group("/s2", group);

    common::register("/s1/x", fs(0x2A3)).expect("s1/x");
    assert_eq!(common::propagate_mount("/s1/x"), 1, "the mount propagated to the peer");
    let x = mount_obj("/s1/x");
    let mirror = mount_obj("/s2/x");
    assert!(mirror.mnt_id != x.mnt_id, "the mirror is a distinct mount");

    assert!(!busy(&x), "both copies idle ⇒ unmountable");
    vfs::mount::mntget(&mirror);
    assert!(busy(&x), "a pinned mirror refuses the unmount of the idle original");
    vfs::mount::mntput(&mirror);
    assert!(!busy(&x), "and releases it again when the pin drops");
}

// A mirror carrying submounts of its own is not the copy this unmount would
// pull out, so it is skipped — a pin on it is irrelevant. Without the skip, a
// busy mirror would wrongly refuse every unmount in the peer group.
#[test]
fn a_mirror_with_its_own_submounts_is_skipped_by_the_busy_test() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/t1", fs(0x3A1)).expect("t1");
    common::set_propagation("/t1", Propagation::Shared).expect("share t1");
    let group = common::peer_group_of("/t1");
    common::register("/t2", fs(0x3A2)).expect("t2");
    common::join_peer_group("/t2", group);

    common::register("/t1/y", fs(0x3A3)).expect("t1/y");
    assert_eq!(common::propagate_mount("/t1/y"), 1);
    let y = mount_obj("/t1/y");
    let mirror = mount_obj("/t2/y");

    // Give the mirror a submount AND a pin: both are now irrelevant to `y`.
    common::register("/t2/y/deep", fs(0x3A4)).expect("t2/y/deep");
    vfs::mount::mntget(&mirror);
    assert!(!busy(&y), "a mirror with submounts of its own does not hold the original");
    vfs::mount::mntput(&mirror);
}

// The local half still decides first: a pin on the mount the caller named is
// busy regardless of what the mirrors look like.
#[test]
fn a_pin_on_the_named_mount_is_busy_whatever_the_mirrors_say() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/u1", fs(0x4A1)).expect("u1");
    common::set_propagation("/u1", Propagation::Shared).expect("share u1");
    let group = common::peer_group_of("/u1");
    common::register("/u2", fs(0x4A2)).expect("u2");
    common::join_peer_group("/u2", group);
    common::register("/u1/z", fs(0x4A3)).expect("u1/z");
    assert_eq!(common::propagate_mount("/u1/z"), 1);

    let z = mount_obj("/u1/z");
    assert!(!busy(&z));
    vfs::mount::mntget(&z);
    assert!(busy(&z), "a pin on the named mount is busy on its own");
    vfs::mount::mntput(&z);
}

// A private mount has no mirrors at all, so the propagation half never fires
// and an idle private mount stays unmountable.
#[test]
fn a_private_mount_has_no_mirrors_to_consult() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/v1", fs(0x5A1)).expect("v1");
    common::register("/v1/w", fs(0x5A2)).expect("v1/w");
    assert_eq!(common::propagate_mount("/v1/w"), 0, "a private parent originates nothing");
    assert!(!busy(&mount_obj("/v1/w")), "idle mount under a private parent is unmountable");
}
