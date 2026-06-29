//! B214: `propagate_mnt`-on-mount peer-group SPREAD (Linux `propagate_one`
//! `CL_MAKE_SHARED`/`CL_SLAVE`). A mount established under a SHARED parent and
//! its propagated copies form ONE new peer group, so a later mount under any
//! peer propagates back; a copy landing on a SLAVE becomes a slave of the
//! source and never originates. Exercises the real global mount engine via the
//! hosted dentry-identity fixture (`common`), no QEMU. Serializes on `SERIAL`
//! and resets the ns provider on entry like `mount_tree.rs`.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::mount::Propagation;
use vfs::{FileType, InodeRef, KResult, VfsError};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0xD0);
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

fn prop_of(p: &str) -> Propagation {
    let snap = vfs::mount::snapshot();
    let m = snap.iter().find(|m| m.mount_point_str() == p).expect("mount exists");
    Propagation::from_u8(m.propagation.load(Ordering::Acquire))
}

// CL_MAKE_SHARED: the source new mount + every PEER copy join ONE NEW peer
// group (distinct from the parent group), and a later mount under a PEER copy
// propagates BACK to the source. Pre-fix the copies were PRIVATE, so this
// second propagation returned 0 — the regression this test pins.
#[test]
fn peer_copies_share_a_new_group_and_propagate_back() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/pa", fs(0xA)).expect("pa");
    common::set_propagation("/pa", Propagation::Shared).expect("share pa");
    let parent_pg = common::peer_group_of("/pa");
    assert!(parent_pg != 0, "shared parent has a group");
    common::register("/pb", fs(0xB)).expect("pb");
    common::join_peer_group("/pb", parent_pg);            // peer of pa

    // Mount under the shared parent, then propagate.
    common::register("/pa/x", fs(0x11)).expect("under pa");
    assert_eq!(common::propagate_mount("/pa/x"), 1, "spread to the one peer");
    assert_eq!(common::mount_root_at("/pb/x").map(|i| i.ino()), Some(0x11), "peer copy present");

    // Source + peer copy are now SHARED in a single NEW group (≠ parent group).
    assert_eq!(prop_of("/pa/x"), Propagation::Shared, "source made shared");
    assert_eq!(prop_of("/pb/x"), Propagation::Shared, "peer copy made shared");
    let g_src = common::peer_group_of("/pa/x");
    let g_peer = common::peer_group_of("/pb/x");
    assert!(g_src != 0, "source joined a group");
    assert_eq!(g_src, g_peer, "source and peer copy share ONE group");
    assert_ne!(g_src, parent_pg, "new tree forms its own group, not the parent's");

    // A later mount under the PEER copy propagates BACK to the source copy.
    common::register("/pb/x/sub", fs(0x22)).expect("under peer copy");
    assert_eq!(common::propagate_mount("/pb/x/sub"), 1, "peer copy originates back to source");
    assert_eq!(common::mount_root_at("/pa/x/sub").map(|i| i.ino()), Some(0x22), "source got the back-propagated mount");
}

// CL_SLAVE: a copy landing on a SLAVE of the group becomes a SLAVE of the
// source — it receives the master event but does NOT originate propagation.
#[test]
fn slave_copy_is_a_slave_and_does_not_originate() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/qa", fs(0xA)).expect("qa");
    common::set_propagation("/qa", Propagation::Shared).expect("share qa");
    let pg = common::peer_group_of("/qa");
    common::register("/qs", fs(0xB)).expect("qs");
    common::join_peer_group("/qs", pg);
    common::set_propagation("/qs", Propagation::Slave).expect("slave qs"); // slave of group

    common::register("/qa/x", fs(0x11)).expect("under qa");
    assert_eq!(common::propagate_mount("/qa/x"), 1, "reaches the slave");
    assert_eq!(common::mount_root_at("/qs/x").map(|i| i.ino()), Some(0x11), "slave got the copy");
    // The copy on the slave is itself a SLAVE (CL_SLAVE), never a peer.
    assert_eq!(prop_of("/qs/x"), Propagation::Slave, "slave copy is a slave");
    assert_eq!(common::peer_group_of("/qs/x"), 0, "slave copy has no peer group of its own");

    // A mount under the slave copy does NOT propagate up to the source.
    common::register("/qs/x/y", fs(0x22)).expect("under slave copy");
    assert_eq!(common::propagate_mount("/qs/x/y"), 0, "slave copy does not originate");
    assert!(common::mount_root_at("/qa/x/y").is_none(), "source unaffected by slave event");
}
