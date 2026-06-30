//! copy_tree / clone_mnt / commit_tree (BIG REWRITE #3, Linux `fs/namespace.c`
//! `copy_tree`/`clone_mnt`/`commit_tree`). Exercises the real global mount
//! engine through its two public entry points — `bind_submounts_rec` (MS_REC)
//! and `propagate_mount` (peer/slave fan-out) — over the hosted dentry-identity
//! fixture (`common`), no QEMU. Pins: recursive subtree clone, shared-peer group
//! join, slave no-back-propagation, unbindable exclusion, and the `struct
//! mountpoint` (D_MOUNTED) + `s_active` refcount balance across clone/detach.
//! Serializes on `SERIAL`; resets the ns provider on entry like `mount_tree.rs`.

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
    vfs::mount::set_current_ns_provider(|| 0xC07);
    common::install();
    g
}

struct TFs { root_ino: u64 }
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
    fn root(&self) -> Option<InodeRef> { Some(tdir(self.root_ino)) }
}
struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TFs { root_ino: ino }) }

// Factory-dir backend: any name resolves to a fresh child dir, so a clone's fs
// can resolve a deeper nested submount slot crossed into via `descend`.
static FAC_INO: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0x5000);
struct FacOps;
impl InodeOps for FacOps {
    fn lookup(&self, _i: &Inode, _n: &str) -> KResult<InodeRef> {
        Ok(facdir(FAC_INO.fetch_add(1, Ordering::Relaxed)))
    }
}
fn facdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(FacOps), default_file_ops()).build()
}
struct FacFs { root_ino: u64 }
impl FileSystem for FacFs {
    fn name(&self) -> &str { "facfs" }
    fn root(&self) -> Option<InodeRef> { Some(facdir(self.root_ino)) }
}
fn facfs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(FacFs { root_ino: ino }) }

fn mounted(p: &str) -> bool { common::mount_at_path_exact(p).is_some() }
fn prop_of(p: &str) -> Propagation {
    let m = common::mount_at_path_exact(p).expect("mount exists");
    Propagation::from_u8(m.propagation.load(Ordering::Acquire))
}

// copy_tree recursion: an MS_REC bind clones the WHOLE submount subtree (Linux
// `copy_tree` recurses `mnt_mounts` depth-first), not just the direct children.
// Factory backends let the nested slot resolve through the parent clone crossed
// into by `commit_tree`'s `descend` (mirrors in-fs submount nesting at boot).
#[test]
fn copy_tree_recursive_bind() {
    let _g = guard();
    common::register("/", facfs(0x1)).expect("root");
    common::register("/src", facfs(0xA)).expect("src");
    common::register("/src/a", facfs(0xA1)).expect("a");
    common::register("/src/a/b", facfs(0xA2)).expect("b");

    let n = common::bind_submounts_rec("/src", "/dst");
    assert_eq!(n, 2, "BOTH the direct submount AND the nested sub-submount are cloned (depth-first)");
    assert!(mounted("/dst/a"), "direct submount cloned and committed");
}

// CL_MAKE_SHARED: a mount under a SHARED parent + its propagated peer copy join
// ONE NEW peer group (distinct from the parent group), and the copy is SHARED.
#[test]
fn copy_tree_shared_peers() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/pa", fs(0xA)).expect("pa");
    common::set_propagation("/pa", Propagation::Shared).expect("share pa");
    let parent_pg = common::peer_group_of("/pa");
    assert!(parent_pg != 0, "shared parent has a group");
    common::register("/pb", fs(0xB)).expect("pb");
    common::join_peer_group("/pb", parent_pg);            // peer of pa

    common::register("/pa/x", fs(0x11)).expect("under pa");
    assert_eq!(common::propagate_mount("/pa/x"), 1, "spread to the one peer");
    assert!(mounted("/pb/x"), "peer copy present");
    assert_eq!(prop_of("/pa/x"), Propagation::Shared, "source made shared");
    assert_eq!(prop_of("/pb/x"), Propagation::Shared, "peer copy shared");

    let g_src = common::peer_group_of("/pa/x");
    let g_peer = common::peer_group_of("/pb/x");
    assert!(g_src != 0 && g_src == g_peer, "source + peer copy share ONE new group");
    assert_ne!(g_src, parent_pg, "new tree forms its own group, not the parent's");
}

// CL_SLAVE: a copy landing on a SLAVE of the group becomes a SLAVE of the
// source — receives master events but NEVER originates back-propagation.
#[test]
fn copy_tree_slave_no_backprop() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/qa", fs(0xA)).expect("qa");
    common::set_propagation("/qa", Propagation::Shared).expect("share qa");
    let pg = common::peer_group_of("/qa");
    common::register("/qs", fs(0xB)).expect("qs");
    common::join_peer_group("/qs", pg);
    common::set_propagation("/qs", Propagation::Slave).expect("slave qs");

    common::register("/qa/x", fs(0x11)).expect("under qa");
    assert_eq!(common::propagate_mount("/qa/x"), 1, "reaches the slave");
    assert_eq!(prop_of("/qs/x"), Propagation::Slave, "slave copy is a slave");
    assert_eq!(common::peer_group_of("/qs/x"), 0, "slave copy has no group of its own");

    // A mount under the slave copy does NOT propagate up to the source.
    common::register("/qs/x/y", fs(0x22)).expect("under slave copy");
    assert_eq!(common::propagate_mount("/qs/x/y"), 0, "slave copy does not originate");
    assert!(!mounted("/qa/x/y"), "source unaffected by slave event");
}

// D15: copy_tree drops UNBINDABLE submounts (Linux `IS_MNT_UNBINDABLE`).
#[test]
fn copy_tree_unbindable_excluded() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/usrc", fs(0xA)).expect("usrc");
    common::register("/usrc/keep", fs(0xA1)).expect("keep");
    common::register("/usrc/skip", fs(0xA2)).expect("skip");
    common::set_propagation("/usrc/skip", Propagation::Unbindable).expect("unbindable");

    let n = common::bind_submounts_rec("/usrc", "/udst");
    assert_eq!(n, 1, "only the bindable submount is cloned");
    assert!(mounted("/udst/keep"), "bindable submount cloned");
    assert!(!mounted("/udst/skip"), "unbindable submount excluded");
}

// commit_tree refcount balance: a clone takes ONE `struct mountpoint`
// (D_MOUNTED) hold on its crossing dentry (`get_mountpoint`), held while mounted
// and released on detach (`put_mountpoint`). The clone gets a fresh anon SB
// (distinct `s_root`, `s_active == 1`); the SOURCE submount's SB is untouched.
#[test]
fn copy_tree_dmounted_refcount() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/rsrc", fs(0xA)).expect("rsrc");
    common::register("/rsrc/a", fs(0xA1)).expect("a");

    let src_active = common::mount_at_path_exact("/rsrc/a").expect("a mount").sb().s_active();
    let n = common::bind_submounts_rec("/rsrc", "/rdst");
    assert_eq!(n, 1, "one submount cloned");
    // D_MOUNTED hold taken on the clone's crossing dentry.
    assert!(common::dentry("/rdst/a").is_mounted(), "D_MOUNTED set on the clone crossing");
    // Source SB active count is NOT perturbed (distinct per-clone anon SB).
    assert_eq!(common::mount_at_path_exact("/rsrc/a").expect("a mount").sb().s_active(), src_active,
        "source submount SB active count unchanged by the clone");
    assert_eq!(common::mount_at_path_exact("/rdst/a").expect("clone").sb().s_active(), 1,
        "clone has its own fresh anon SB (one active ref)");

    common::unregister("/rdst/a");
    assert!(!common::dentry("/rdst/a").is_mounted(), "D_MOUNTED released on detach (put_mountpoint)");
    assert_eq!(common::mount_at_path_exact("/rsrc/a").expect("a mount").sb().s_active(), src_active,
        "source SB still balanced after the clone is detached");
}
