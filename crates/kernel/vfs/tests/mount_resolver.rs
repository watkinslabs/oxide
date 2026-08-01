//! K2V V5–V7: the unified mount tree. `mount_root_at(abs)` returns the
//! root inode of whatever filesystem is mounted exactly at `abs` — what
//! `path_lookup` switches to when it crosses into a mount. Also covers
//! MS_MOVE, bind-as-clone, MS_REC, peer groups, and per-ns scoping.
//! Verified over the real (global) mount table, no QEMU.
//!
//! These tests share one process-global table + ns provider, so every
//! test serializes on `SERIAL` and resets the ns provider to 0 on entry
//! (so a panicking ns-test can't leak a non-zero ns into the next).

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

/// Serialize + reset the ns provider to 0. Poison-tolerant so one failing
/// test doesn't cascade. Also installs the hosted DentryResolver fixture
/// so the engine resolves parent/child/exact-mount by dentry identity
/// (the real-kernel path), not the table's rendered string column.
fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(vfs::mntns::initial);
    common::install();
    g
}

struct TDirOps;
impl vfs::InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Ok(tdir(0xD00)) }
}
fn tdir(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755),
        Arc::new(TDirOps), vfs::default_file_ops()).build()
}

struct TestFs { root_ino: u64 }
impl FileSystem for TestFs {
    fn name(&self) -> &str { "testfs" }
    fn root(&self) -> Option<InodeRef> { Some(tdir(self.root_ino)) }
}

#[test]
fn resolver_returns_mount_root() {
    let _g = guard();
    let fs = Arc::new(TestFs { root_ino: 0x1234 });
    common::register("/x", fs).expect("register");
    let r = common::mount_root_at("/x").expect("cross into /x");
    assert_eq!(r.ino(), 0x1234, "crossing returns the mounted fs root");
    assert_eq!(r.file_type(), FileType::Directory);
}

#[test]
fn resolver_skips_root_and_missing() {
    let _g = guard();
    // `/` is the walk start — never a crossing target.
    assert!(common::mount_root_at("/").is_none());
    // Nothing mounted at /nope.
    assert!(common::mount_root_at("/nope-xyz").is_none());
}

// WP2: there is NO whole-path `FileSystem::lookup` fallback. Every mounted
// fs publishes its root inode via `FileSystem::root()` or, for bind/tmpfs,
// the per-mount `m.root` (`register_bind`). A fs exposing neither has no
// crossable root — `mount_root_at` returns `None`.
struct NoRootFs;
impl FileSystem for NoRootFs {
    fn name(&self) -> &str { "norootfs" }
}

#[test]
fn resolver_without_root_has_no_crossable_inode() {
    let _g = guard();
    common::register("/y", Arc::new(NoRootFs)).expect("register");
    assert!(common::mount_root_at("/y").is_none(),
        "no root() and no m.root → nothing to cross into (no whole-path fallback)");
}

// K2V V7: MS_MOVE relocates a mount's mount_point in place, preserving
// mnt_id + propagation; the new parent_id falls out of the prefix
// recompute. Verified over the real mount table, no QEMU.
#[test]
fn move_mount_relocates_preserving_mnt_id() {
    let _g = guard();
    common::register("/mv-src", Arc::new(TestFs { root_ino: 0xABCD })).expect("register");
    let before = vfs::mount::snapshot();
    let id = before.iter().find(|m| m.mount_point_str() == "/mv-src").expect("present").mnt_id;
    common::move_mount("/mv-src", "/mv-dst").expect("move");
    assert!(common::mount_root_at("/mv-src").is_none(), "old point cleared");
    let r = common::mount_root_at("/mv-dst").expect("cross into new point");
    assert_eq!(r.ino(), 0xABCD, "same fs root after move");
    let after = vfs::mount::snapshot();
    let m = after.iter().find(|m| m.mount_point_str() == "/mv-dst").expect("moved present");
    assert_eq!(m.mnt_id, id, "mnt_id stable across MS_MOVE");
    assert!(matches!(common::move_mount("/nope-mv", "/x2"), Err(VfsError::Einval)));
    common::register("/occupied", Arc::new(TestFs { root_ino: 1 })).expect("register2");
    assert!(matches!(common::move_mount("/mv-dst", "/occupied"), Err(VfsError::Ebusy)));
}

// K2V V7-b: bind-as-clone. register_bind mounts an arbitrary source inode
// as the mount root; mount_root_at returns THAT inode (not fs.root()).
struct BindChildDirOps;
impl vfs::InodeOps for BindChildDirOps {
    fn lookup(&self, _inode: &Inode, n: &str) -> KResult<InodeRef> {
        if n == "kid" { Ok(tdir(0xC0DE)) } else { Err(VfsError::Enoent) }
    }
}
fn bind_child() -> InodeRef {
    vfs::InodeBuilder::new(0xB14D, vfs::mk_mode(FileType::Directory, 0o755),
        Arc::new(BindChildDirOps), vfs::default_file_ops()).build()
}

#[test]
fn bind_as_clone_roots_at_source_inode() {
    let _g = guard();
    let bindfs = Arc::new(TestFs { root_ino: 0x9999 }); // fs.root() must NOT win
    let src_root: InodeRef = bind_child();
    common::register_bind("/bnd", bindfs, src_root).expect("register_bind");
    let r = common::mount_root_at("/bnd").expect("cross into bind");
    assert_eq!(r.ino(), 0xB14D, "bind root is the source inode, not fs.root()");
    let kid = r.lookup("kid").expect("child via source subtree");
    assert_eq!(kid.ino(), 0xC0DE);
}

// K2V V7-c: MS_REC recursive bind clones every submount of src to the
// matching path under tgt as a bind-as-clone.
#[test]
fn ms_rec_clones_submounts() {
    let _g = guard();
    vfs::mount::set_current_ns_provider(common::current_namespace);
    common::register("/", Arc::new(TestFs { root_ino: 0x0100 })).expect("root");
    common::register("/rsrc", Arc::new(TestFs { root_ino: 0x100 })).expect("src");
    common::register("/rsrc/sub", Arc::new(TestFs { root_ino: 0x200 })).expect("submount");
    let r = common::mount_root_at("/rsrc").expect("src root");
    common::register_bind("/rtgt", Arc::new(TestFs { root_ino: 0xDEAD }), r).expect("bind top");
    let n = common::bind_submounts_rec("/rsrc", "/rtgt");
    assert_eq!(n, 1, "one submount cloned");
    let sub = common::mount_root_at("/rtgt/sub").expect("cloned submount present");
    assert_eq!(sub.ino(), 0x200, "cloned submount keeps the source fs root");
}

#[test]
fn ms_rec_from_root_clones_absolute_submounts() {
    let _g = guard();
    vfs::mount::set_current_ns_provider(common::current_namespace);
    common::register("/", Arc::new(TestFs { root_ino: 0x100 })).expect("root");
    common::register("/proc", Arc::new(TestFs { root_ino: 0x200 })).expect("proc");
    common::register("/sys/fs/cgroup", Arc::new(TestFs { root_ino: 0x300 })).expect("cgroup");
    let r = common::mount_root_at("/proc").expect("proc root");
    common::register_bind("/stage", Arc::new(TestFs { root_ino: 0xDEAD }), r).expect("bind top");
    let n = common::bind_submounts_rec("/", "/stage");
    assert_eq!(n, 2, "root recursive bind clones every non-root mount");
    let proc = common::mount_root_at("/stage/proc").expect("cloned /proc");
    let cgroup = common::mount_root_at("/stage/sys/fs/cgroup").expect("cloned /sys/fs/cgroup");
    assert_eq!(proc.ino(), 0x200);
    assert_eq!(cgroup.ino(), 0x300);
}

#[test]
fn ms_rec_from_subdir_clones_only_submounts_below_source_dentry() {
    let _g = guard();
    vfs::mount::set_current_ns_provider(common::current_namespace);
    let ns = common::current_namespace().id();
    common::register("/", Arc::new(TestFs { root_ino: 0x7100 })).expect("root");
    let src_d = common::dentry("/rsub-src");
    let tgt_d = common::dentry("/rsub-tgt");
    common::register("/rsub-src/sub", Arc::new(TestFs { root_ino: 0x7200 })).expect("inside");
    common::register("/rsub-outside", Arc::new(TestFs { root_ino: 0x7300 })).expect("outside");
    let source_mnt = vfs::mount::root_mount_id(ns).expect("source root id");
    let target_parent = vfs::mount::containing_mount_id(ns, &tgt_d);
    vfs::mount::register_bind_clone_under(target_parent, tgt_d.clone(), source_mnt, src_d.clone()).expect("top bind");
    let n = vfs::mount::bind_submounts_rec_at(Some(source_mnt), &src_d, &tgt_d, Some(target_parent));
    assert_eq!(n, 1, "recursive bind clones only submounts under the source dentry");
    let snap = vfs::mount::snapshot_all();
    let sub = snap.iter().find(|m| m.namespace_id() == ns && m.mount_point_str() == "/rsub-tgt/sub")
        .expect("inside submount cloned");
    assert_eq!(sub.mnt_root().and_then(|d| d.inode()).map(|i| i.ino()), Some(0x7200));
    assert!(snap.iter().all(|m| m.namespace_id() != ns || m.mount_point_str() != "/rsub-tgt/rsub-outside"),
        "outside sibling mount must not be cloned under the target");
}

// K2V V7-d: propagation peer-group ids.
#[test]
fn ms_shared_assigns_distinct_peer_groups() {
    let _g = guard();
    use std::sync::atomic::Ordering;
    use vfs::mount::Propagation;
    common::register("/pg-a", Arc::new(TestFs { root_ino: 1 })).expect("a");
    common::register("/pg-b", Arc::new(TestFs { root_ino: 2 })).expect("b");
    common::set_propagation("/pg-a", Propagation::Shared).expect("share a");
    common::set_propagation("/pg-b", Propagation::Shared).expect("share b");
    let snap = vfs::mount::snapshot();
    let ga = snap.iter().find(|m| m.mount_point_str() == "/pg-a").unwrap().peer_group.load(Ordering::Acquire);
    let gb = snap.iter().find(|m| m.mount_point_str() == "/pg-b").unwrap().peer_group.load(Ordering::Acquire);
    assert!(ga != 0 && gb != 0, "shared mounts get a peer group");
    assert!(ga != gb, "distinct shared mounts get distinct peer groups");
    common::set_propagation("/pg-a", Propagation::Shared).expect("reshare a");
    let ga2 = vfs::mount::snapshot().iter().find(|m| m.mount_point_str() == "/pg-a").unwrap().peer_group.load(Ordering::Acquire);
    assert_eq!(ga, ga2, "re-MS_SHARED keeps the peer group");
    common::set_propagation("/pg-a", Propagation::Private).expect("priv a");
    let ga3 = vfs::mount::snapshot().iter().find(|m| m.mount_point_str() == "/pg-a").unwrap().peer_group.load(Ordering::Acquire);
    assert_eq!(ga3, 0, "MS_PRIVATE clears the peer group");
}

// K2V V7/U2-a: mounts are stamped with the creating task's mount-ns via
// the installed provider. No provider ⇒ ns 0.
#[test]
fn register_stamps_mount_ns_from_provider() {
    let _g = guard();
    common::register("/ns-default", Arc::new(TestFs { root_ino: 1 })).expect("a");
    let m0 = vfs::mount::snapshot_all();
    let m0 = m0.iter().find(|m| m.mount_point_str() == "/ns-default").unwrap();
    assert_eq!(m0.namespace_id(), 0, "no provider ⇒ ns 0");
    vfs::mount::set_current_ns_provider(common::current_namespace);
    common::register("/ns-42", Arc::new(TestFs { root_ino: 2 })).expect("b");
    let m1 = vfs::mount::snapshot_all();
    let m1 = m1.iter().find(|m| m.mount_point_str() == "/ns-42").unwrap();
    assert_eq!(m1.namespace_id(), common::current_namespace().id(),
        "provider owner stamped onto the new mount");
}

// K2V V7/U2-b: per-ns resolution + copy-on-unshare. A mount in ns 0 is
// invisible from ns 7 until snapshot_ns copies it; the copy is a fresh
// independent mount (new mnt_id).
#[test]
fn per_ns_isolation_and_copy_on_unshare() {
    let _g = guard();
    // Register a base mount in ns 0.
    common::register("/u2b-base", Arc::new(TestFs { root_ino: 0x7001 })).expect("base");
    let base_id = vfs::mount::snapshot_all().iter()
        .find(|m| m.mount_point_str() == "/u2b-base").unwrap().mnt_id;
    // From ns 7 (before any copy) the base mount is INVISIBLE.
    vfs::mount::set_current_ns_provider(common::current_namespace);
    assert!(common::mount_root_at("/u2b-base").is_none(), "ns 7 can't see ns 0 mount");
    // unshare: copy ns 0 → ns 7. Now ns 7 sees its own copy.
    vfs::mount::set_current_ns_provider(vfs::mntns::initial);
    common::snapshot_ns(0, 7).unwrap();
    common::set_current_namespace(common::namespace_for_key(7));
    vfs::mount::set_current_ns_provider(common::current_namespace);
    let r = common::mount_root_at("/u2b-base").expect("ns 7 sees its copy");
    assert_eq!(r.ino(), 0x7001, "copy preserves the fs root");
    // The copy is an independent mount (fresh mnt_id).
    let copy = vfs::mount::snapshot_all().iter()
        .find(|m| m.mount_point_str() == "/u2b-base"
            && m.namespace_id() == common::namespace_id(7)).map(|m| m.mnt_id).unwrap();
    assert_ne!(copy, base_id, "copy-on-unshare assigns a fresh mnt_id");
    // Divergence: a new mount in ns 7 is invisible to ns 0.
    common::register("/u2b-only7", Arc::new(TestFs { root_ino: 0x7002 })).expect("only7");
    vfs::mount::set_current_ns_provider(vfs::mntns::initial);
    assert!(common::mount_root_at("/u2b-only7").is_none(), "ns 0 can't see ns 7's new mount");
}

#[test]
fn mountinfo_view_uses_the_mounting_task_namespace() {
    let _g = guard();
    const INIT_KEY: u64 = 0x7800_0001;
    const CHILD_NS: u64 = 0x7800_0002;
    common::set_current_namespace(common::namespace_for_key(INIT_KEY));
    vfs::mount::set_current_ns_provider(common::current_namespace);
    common::register("/", Arc::new(TestFs { root_ino: 0x7800 })).expect("root");
    common::register("/tmp-systemd-visible", Arc::new(TestFs { root_ino: 0x7801 })).expect("tmp");

    let init_rows = vfs::mount::snapshot_ns_view(common::namespace_id(INIT_KEY));
    assert!(init_rows.iter().any(|m| m.mount_point_str() == "/tmp-systemd-visible"),
        "mount(2) success in a task's namespace must be visible to that namespace's mountinfo reader");
    let foreign_rows = vfs::mount::snapshot_ns_view(common::namespace_id(CHILD_NS));
    assert!(foreign_rows.iter().all(|m| m.mount_point_str() != "/tmp-systemd-visible"),
        "mountinfo must not recover missing rows by scanning foreign namespaces");

    common::snapshot_ns_map(INIT_KEY, CHILD_NS).unwrap();
    common::set_current_namespace(common::namespace_for_key(CHILD_NS));
    vfs::mount::set_current_ns_provider(common::current_namespace);
    common::register("/tmp-child-only", Arc::new(TestFs { root_ino: 0x7802 })).expect("child");

    let child_rows = vfs::mount::snapshot_ns_view(common::namespace_id(CHILD_NS));
    assert!(child_rows.iter().any(|m| m.mount_point_str() == "/tmp-systemd-visible"),
        "copy-on-unshare preserves parent mounts in the child's mountinfo view");
    assert!(child_rows.iter().any(|m| m.mount_point_str() == "/tmp-child-only"),
        "new mounts after unshare appear in the child's mountinfo view");
    let init_rows_after = vfs::mount::snapshot_ns_view(common::namespace_id(INIT_KEY));
    assert!(init_rows_after.iter().all(|m| m.mount_point_str() != "/tmp-child-only"),
        "new mounts after unshare do not leak back to the parent namespace");
}

// K2V V7/U3-a: unregister detaches a TABLE mount (e.g. a bind) in the
// caller's ns — before this, umount of a bind mount was a no-op.
#[test]
fn unregister_detaches_table_mount() {
    let _g = guard();
    let src: InodeRef = tdir(0xD00D);
    common::register_bind("/umnt", Arc::new(TestFs { root_ino: 1 }), src).expect("bind");
    assert!(common::mount_root_at("/umnt").is_some(), "bound");
    let n = common::unregister("/umnt");
    assert_eq!(n, 1, "one mount detached");
    assert!(common::mount_root_at("/umnt").is_none(), "gone after umount");
    // Unmounting a non-mount removes nothing.
    assert_eq!(common::unregister("/umnt"), 0, "second umount is a no-op");
}

// K2V V7/U4: MS_MOVE relocates the whole subtree — submounts under `from`
// move to the mirrored path under `to`, preserving their mnt_id.
#[test]
fn move_mount_relocates_subtree() {
    let _g = guard();
    common::register("/sm-src", Arc::new(TestFs { root_ino: 0x10 })).expect("src");
    common::register("/sm-src/inner", Arc::new(TestFs { root_ino: 0x20 })).expect("sub");
    let sub_id = vfs::mount::snapshot().iter()
        .find(|m| m.mount_point_str() == "/sm-src/inner").unwrap().mnt_id;
    common::move_mount("/sm-src", "/sm-dst").expect("move subtree");
    // Both the root and the submount relocated.
    assert!(common::mount_root_at("/sm-src").is_none(), "old root gone");
    assert!(common::mount_root_at("/sm-src/inner").is_none(), "old submount gone");
    let r = common::mount_root_at("/sm-dst").expect("new root");
    assert_eq!(r.ino(), 0x10);
    let s = common::mount_root_at("/sm-dst/inner").expect("submount relocated");
    assert_eq!(s.ino(), 0x20, "submount keeps its fs root");
    let new_sub_id = vfs::mount::snapshot().iter()
        .find(|m| m.mount_point_str() == "/sm-dst/inner").unwrap().mnt_id;
    assert_eq!(new_sub_id, sub_id, "submount mnt_id preserved across move");
}

// K2V V7/U4-b: peer-group inheritance. join_peer_group makes a mount a
// peer (same shared:<pg>) of a shared source — the basis for propagation.
#[test]
fn join_peer_group_shares_group() {
    let _g = guard();
    use std::sync::atomic::Ordering;
    use vfs::mount::Propagation;
    common::register("/pi-src", Arc::new(TestFs { root_ino: 1 })).expect("src");
    common::set_propagation("/pi-src", Propagation::Shared).expect("share");
    let pg = common::peer_group_of("/pi-src");
    assert!(pg != 0, "shared source has a peer group");
    // A new mount joins that group → same shared:<pg>.
    common::register("/pi-dst", Arc::new(TestFs { root_ino: 2 })).expect("dst");
    assert_eq!(common::peer_group_of("/pi-dst"), 0, "fresh mount has no group");
    common::join_peer_group("/pi-dst", pg);
    assert_eq!(common::peer_group_of("/pi-dst"), pg, "joined the source's peer group");
    // And it's now Shared.
    let snap = vfs::mount::snapshot();
    let m = snap.iter().find(|m| m.mount_point_str() == "/pi-dst").unwrap();
    assert_eq!(Propagation::from_u8(m.propagation.load(Ordering::Acquire)), Propagation::Shared);
    // peer_group_of a non-mount is 0.
    assert_eq!(common::peer_group_of("/pi-nope"), 0);
}

// K2V V7/U4-c: propagation event delivery. A mount established under a
// SHARED parent propagates to every peer of that parent at the mirrored
// relative path. End-to-end over the real mount table.
#[test]
fn propagate_mount_reaches_peers() {
    let _g = guard();
    use vfs::mount::Propagation;
    vfs::mount::set_current_ns_provider(common::current_namespace);
    common::register("/", Arc::new(TestFs { root_ino: 0xA000 })).expect("root");
    // /pp-a shared (peer group P); /pp-b joins P (a peer of /pp-a).
    common::register("/pp-a", Arc::new(TestFs { root_ino: 0xA })).expect("a");
    common::set_propagation("/pp-a", Propagation::Shared).expect("share a");
    let pg = common::peer_group_of("/pp-a");
    common::register("/pp-b", Arc::new(TestFs { root_ino: 0xB })).expect("b");
    common::join_peer_group("/pp-b", pg);
    // Establish a mount UNDER /pp-a, then propagate it.
    common::register("/pp-a/x", Arc::new(TestFs { root_ino: 0x11 })).expect("under a");
    let n = common::propagate_mount("/pp-a/x");
    assert_eq!(n, 1, "propagated to the one peer");
    // The peer /pp-b now has the mount at the mirrored path /pp-b/x.
    let r = common::mount_root_at("/pp-b/x").expect("propagated to peer");
    assert_eq!(r.ino(), 0x11, "peer mount has the source fs root");
    // A non-shared parent does NOT propagate.
    common::register("/pp-priv", Arc::new(TestFs { root_ino: 0xC })).expect("priv");
    common::register("/pp-priv/y", Arc::new(TestFs { root_ino: 0x22 })).expect("under priv");
    assert_eq!(common::propagate_mount("/pp-priv/y"), 0, "private parent: no propagation");
}

// K2V V7/U4-d: pivot_root makes new_root the ns root and relocates the old
// tree under put_old. Verified over the real mount table.
#[test]
fn pivot_root_swaps_namespace_root() {
    let _g = guard();
    // Isolate in a dedicated ns so pivot_root's whole-table rewrite doesn't
    // touch mounts left by other tests (it scopes to current_ns()).
    vfs::mount::set_current_ns_provider(common::current_namespace);
    common::register("/", Arc::new(TestFs { root_ino: 0xA })).expect("root");
    common::register("/nr", Arc::new(TestFs { root_ino: 0xB })).expect("newroot");
    common::register("/nr/sub", Arc::new(TestFs { root_ino: 0xC })).expect("newsub");
    common::register("/etc", Arc::new(TestFs { root_ino: 0xD })).expect("oldtree");
    common::pivot_root("/nr", "/nr/old").expect("pivot");
    let snap = vfs::mount::snapshot();
    let ino_at = |mp: &str| snap.iter().find(|m| m.mount_point_str() == mp)
        .and_then(|m| m.sb().s_root_inode()).map(|i| i.ino());
    assert_eq!(ino_at("/"), Some(0xB), "new_root is now /");
    assert_eq!(ino_at("/sub"), Some(0xC), "new_root submount rebased to /sub");
    assert_eq!(ino_at("/old"), Some(0xA), "old root relocated under put_old");
    assert_eq!(ino_at("/old/etc"), Some(0xD), "old tree relocated under put_old");
    assert!(ino_at("/nr").is_none(), "old new_root path gone");
    // Errors (fresh ns): new_root not a mount → Einval; put_old not under
    // new_root → Einval.
    vfs::mount::set_current_ns_provider(common::current_namespace);
    assert!(matches!(common::pivot_root("/nope", "/nope/old"), Err(VfsError::Einval)));
    common::register("/e-nr", Arc::new(TestFs { root_ino: 1 })).expect("e-nr");
    assert!(matches!(common::pivot_root("/e-nr", "/other"), Err(VfsError::Einval)));
    // put_old already covered by a mount is NOT refused: `put_old` resolution
    // descends through it (Linux `where_to_mount`) and the old root stacks on
    // that mount's root, exactly as `pivot_root(".", ".")` stacks on new_root.
    common::register("/e-nr/m", Arc::new(TestFs { root_ino: 2 })).expect("e-m");
    common::pivot_root("/e-nr", "/e-nr/m").expect("put_old under an overmount stacks");
}
