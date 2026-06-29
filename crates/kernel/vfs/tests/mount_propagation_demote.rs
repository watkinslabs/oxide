//! B243: `change_mnt_propagation` / `do_make_slave` COMPLETENESS (Linux
//! `fs/pnode.c`). Demoting a SHARED mount that owns slaves to SLAVE/PRIVATE/
//! UNBINDABLE must RE-HOME those slaves onto the inheriting master (a surviving
//! peer), not leave them pointing at a mount that has stopped originating
//! propagation. Pre-fix `set_propagation` cleared the demoted mount's master
//! link but left both its `mnt_slave_list` and every slave's `mnt_master`
//! stale, so a later event under a peer never reached the orphaned slave.
//! Exercises the real global mount engine via the hosted dentry-identity
//! fixture (`common`), no QEMU. Serializes on `SERIAL`.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::mount::Propagation;
use vfs::{FileType, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, default_file_ops, mk_mode};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0xD3);
    common::install();
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

fn prop_of(p: &str) -> Propagation {
    let snap = vfs::mount::snapshot();
    let m = snap.iter().find(|m| m.mount_point_str() == p).expect("mount exists");
    Propagation::from_u8(m.propagation.load(Ordering::Acquire))
}

// do_make_slave: demoting the master `A` of a slave `C` to PRIVATE must hand
// `C` to a surviving peer `B` of `A`'s group, so a later event under `B`
// reaches `C`. Pre-fix `C` stayed slaved to the now-private `A` (which never
// originates), so the event was lost.
#[test]
fn demote_master_to_private_rehomes_slaves_to_peer() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    // A shared (its own group g); B a peer of g; C a slave of g (master = A,
    // the first shared peer found in ascending mnt_id order).
    common::register("/a", fs(0xA)).expect("a");
    common::set_propagation("/a", Propagation::Shared).expect("share a");
    let g = common::peer_group_of("/a");
    assert!(g != 0);
    common::register("/b", fs(0xB)).expect("b");
    common::join_peer_group("/b", g);
    common::register("/c", fs(0xC)).expect("c");
    common::join_peer_group("/c", g);
    common::set_propagation("/c", Propagation::Slave).expect("slave c"); // master = A

    // Sanity: an event under A reaches its slave C (and peer B).
    common::register("/a/x", fs(0x11)).expect("under a");
    assert_eq!(common::propagate_mount("/a/x"), 2, "A originates to peer B + slave C");
    assert!(common::mount_root_at("/c/x").is_some(), "slave C got A's event");

    // Demote A to PRIVATE. do_make_slave(A): A is shared-with-peer (B), so the
    // peer B inherits A's slaves; C is re-homed to B; then A is detached from
    // B and made private.
    common::set_propagation("/a", Propagation::Private).expect("private a");
    assert_eq!(prop_of("/a"), Propagation::Private, "A is now private");
    assert_eq!(common::peer_group_of("/a"), 0, "A left the peer group");

    // A no longer originates anything.
    common::register("/a/z", fs(0x33)).expect("under private a");
    assert_eq!(common::propagate_mount("/a/z"), 0, "private A originates nothing");

    // The re-homing is the fix: an event under the surviving peer B now reaches
    // C (C's master is B). Pre-fix B had no slaves and C was orphaned under the
    // private A, so this returned 0 and /c/y never appeared.
    common::register("/b/y", fs(0x22)).expect("under b");
    assert_eq!(common::propagate_mount("/b/y"), 1, "peer B originates to re-homed slave C");
    assert_eq!(common::mount_root_at("/c/y").map(|i| i.ino()), Some(0x22),
               "re-homed slave C received B's event");
}

// Demoting the SOLE shared mount of a group (no surviving peer) to PRIVATE has
// no master to inherit, so its slaves are ORPHANED (left masterless) — they
// must NOT keep receiving events through the now-private former master.
#[test]
fn demote_lone_shared_to_private_orphans_slaves() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/m", fs(0xA)).expect("m");
    common::set_propagation("/m", Propagation::Shared).expect("share m");
    let g = common::peer_group_of("/m");
    common::register("/s", fs(0xB)).expect("s");
    common::join_peer_group("/s", g);
    common::set_propagation("/s", Propagation::Slave).expect("slave s"); // master = M

    // Before demotion M reaches its slave S.
    common::register("/m/x", fs(0x11)).expect("under m");
    assert_eq!(common::propagate_mount("/m/x"), 1, "M originates to slave S");
    assert!(common::mount_root_at("/s/x").is_some());

    // M is the only shared mount in g; demote to PRIVATE → S orphaned.
    common::set_propagation("/m", Propagation::Private).expect("private m");
    assert_eq!(prop_of("/m"), Propagation::Private);
    common::register("/m/y", fs(0x22)).expect("under private m");
    assert_eq!(common::propagate_mount("/m/y"), 0, "orphaned: private M originates nothing");
    assert!(common::mount_root_at("/s/y").is_none(), "orphaned slave S receives nothing");
}
