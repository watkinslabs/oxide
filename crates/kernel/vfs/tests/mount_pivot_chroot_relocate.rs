//! `pivot_root(2)` operates on the CALLER's root, not on the mount-namespace
//! root (Linux `path_pivot_root()` starts from `get_fs_root(current->fs)` and
//! never reassigns `mnt_ns->root`). A caller that chrooted into some mount other
//! than the namespace root therefore relocates THAT mount: `new_root` takes over
//! the slot it occupied under its parent, the old root is re-attached under
//! `put_old`, and the namespace root — plus every task rooted there — is left
//! alone.
//!
//! Also covered here, because they are only observable once the surgery runs:
//! MNT_LOCKED travelling with the root slot, `put_old` overmount stacking, the
//! shared-propagation rungs that need a real `root_parent`, both reachability
//! rungs, and the post-pivot parent/rendered-path topology `/proc/self/
//! mountinfo` is generated from.
//!
//! Exercises the real global mount engine via the hosted fixture, no QEMU.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::mount::{Propagation, PivotRoot};
use vfs::{Dentry, FileType, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, default_file_ops, mk_mode};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());
static NEXT_NS: AtomicU64 = AtomicU64::new(0x9100);

/// Fresh mount namespace per test so one test's tree cannot be read as another's.
fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(common::current_namespace);
    common::install();
    common::set_current_namespace(common::namespace_for_key(NEXT_NS.fetch_add(1, Ordering::Relaxed)));
    g
}

struct TFs { root_ino: u64 }
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
    fn root(&self) -> Option<InodeRef> { Some(make_tdir(self.root_ino)) }
}
struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Ok(make_tdir(0xD70)) }
}
fn make_tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TFs { root_ino: ino }) }

fn ns() -> u64 { vfs::mount::current_ns() }
fn id(p: &str) -> u64 { common::mount_at_path_exact(p).expect("mount exists").mnt_id }
fn rendered(mnt: u64) -> String { vfs::mount::mount_by_id(mnt).unwrap().mount_point_str() }
fn parent_of(mnt: u64) -> u64 { vfs::mount::parent_mnt_id(&vfs::mount::mount_by_id(mnt).unwrap()) }
fn mnt_root(mnt: u64) -> Arc<Dentry> { vfs::mount::mount_by_id(mnt).unwrap().mnt_root().unwrap() }

/// The tree every chrooted-caller test starts from: namespace root `/`, the
/// caller's chroot mount `/chr`, and the pivot target `/chr/nr` inside it.
fn chroot_tree() -> (u64, u64, u64) {
    common::register("/", fs(0xA)).expect("ns root");
    common::register("/chr", fs(0xB)).expect("chroot mount");
    common::register("/chr/nr", fs(0xC)).expect("new root");
    (id("/"), id("/chr"), id("/chr/nr"))
}

fn pivot_as(root_mnt: u64, new_root: &Arc<Dentry>, put_old: &Arc<Dentry>) -> KResult<()> {
    vfs::mount::pivot_root_from(new_root, put_old, PivotRoot { mnt_id: root_mnt, path_mounted: true })
}

// A caller chrooted into a mount OTHER than the namespace root relocates that
// mount only: the namespace root is untouched.
#[test]
fn chrooted_pivot_does_not_reroot_the_namespace() {
    let _g = guard();
    let (root_id, chr, nr) = chroot_tree();
    let chr_d = common::dentry("/chr");
    let nr_d = common::dentry("/chr/nr");
    let po_d = common::dentry("/chr/nr/old");

    pivot_as(chr, &nr_d, &po_d).expect("chrooted pivot");

    assert_eq!(vfs::mount::root_mount_id(ns()), Some(root_id),
        "pivot_root by a chrooted caller must leave the mount-namespace root alone");
    assert_eq!(rendered(root_id), "/", "the namespace root keeps its position");
    // new_root took over the slot the caller's root occupied.
    assert_eq!(parent_of(nr), root_id, "new_root inherits the old root's parent");
    assert_eq!(rendered(nr), "/chr", "new_root inherits the old root's position");
    assert!(Arc::ptr_eq(&vfs::mount::mount_by_id(nr).unwrap().mountpoint().unwrap(), &chr_d),
        "new_root is attached on the dentry the old root was attached on");
    // the displaced old root now hangs under put_old.
    assert_eq!(parent_of(chr), nr, "the old root is re-attached under put_old's mount");
    assert_eq!(rendered(chr), "/chr/old", "the old root renders at put_old");
}

// Relocation re-renders both moved subtrees: a mount inside the new root moves
// up with it, and a mount inside the old root follows it down under put_old.
#[test]
fn chrooted_pivot_rerenders_both_subtrees() {
    let _g = guard();
    let (_root_id, chr, nr) = chroot_tree();
    common::register("/chr/nr/sub", fs(0xD)).expect("mount inside the new root");
    common::register("/chr/other", fs(0xE)).expect("mount inside the old root");
    let sub = id("/chr/nr/sub");
    let other = id("/chr/other");
    let nr_d = common::dentry("/chr/nr");
    let po_d = common::dentry("/chr/nr/old");

    pivot_as(chr, &nr_d, &po_d).expect("chrooted pivot");

    assert_eq!(parent_of(sub), nr, "an in-new-root mount keeps its parent");
    assert_eq!(rendered(sub), "/chr/sub", "an in-new-root mount rises with the new root");
    assert_eq!(parent_of(other), chr, "an in-old-root mount keeps its parent");
    assert_eq!(rendered(other), "/chr/old/other", "an in-old-root mount descends under put_old");
}

// `chroot_fs_refs(&root, new)` fires with the OLD root mount and the NEW one, so
// only tasks whose root/cwd was exactly the old root are re-pointed.
#[test]
fn chrooted_pivot_fires_chroot_refs_for_the_callers_root() {
    let _g = guard();
    static SEEN: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());
    fn record(old: u64, new: u64) { SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((old, new)); }
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    vfs::mount::set_chroot_refs_hook(record);

    let (_root_id, chr, nr) = chroot_tree();
    let nr_d = common::dentry("/chr/nr");
    let po_d = common::dentry("/chr/nr/old");
    pivot_as(chr, &nr_d, &po_d).expect("chrooted pivot");

    assert_eq!(*SEEN.lock().unwrap_or_else(|e| e.into_inner()), vec![(chr, nr)],
        "chroot_fs_refs must name the caller's own root mount, not the namespace root");
}

// MNT_LOCKED belongs to the ROOT SLOT: new_root inherits it and the displaced
// old root loses it, so an unprivileged user namespace cannot use pivot_root to
// leave a pinned mount behind, and the old root stays umountable under put_old.
#[test]
fn chrooted_pivot_transfers_mnt_locked_to_the_new_root() {
    let _g = guard();
    let (_root_id, chr, nr) = chroot_tree();
    vfs::mount::mount_by_id(chr).unwrap().set_internal_flag(vfs::mount::MNT_LOCKED);
    let nr_d = common::dentry("/chr/nr");
    let po_d = common::dentry("/chr/nr/old");

    pivot_as(chr, &nr_d, &po_d).expect("chrooted pivot");

    assert!(vfs::mount::mount_by_id(nr).unwrap().is_locked(),
        "new_root must inherit the old root's MNT_LOCKED");
    assert!(!vfs::mount::mount_by_id(chr).unwrap().is_locked(),
        "the displaced old root must lose MNT_LOCKED");
}

// Linux resolves put_old THROUGH anything mounted there (`where_to_mount`), so
// the old root stacks on the overmount instead of being refused.
#[test]
fn put_old_covered_by_a_mount_stacks_instead_of_ebusy() {
    let _g = guard();
    let (_root_id, chr, _nr) = chroot_tree();
    common::register("/chr/nr/old", fs(0xF)).expect("mount covering put_old");
    let cover = id("/chr/nr/old");
    let nr_d = common::dentry("/chr/nr");
    let po_d = common::dentry("/chr/nr/old");

    pivot_as(chr, &nr_d, &po_d).expect("put_old under an overmount is not EBUSY");

    assert_eq!(parent_of(chr), cover, "the old root stacks on the mount covering put_old");
    assert!(Arc::ptr_eq(&vfs::mount::mount_by_id(chr).unwrap().mountpoint().unwrap(), &mnt_root(cover)),
        "the old root is attached on the covering mount's root dentry");
    assert_eq!(rendered(chr), "/chr/old", "the stacked old root renders at put_old");
}

// `IS_MNT_SHARED(root_parent)` — only reachable once the caller's root HAS a
// parent, i.e. exactly the chrooted case.
#[test]
fn chrooted_pivot_with_a_shared_root_parent_is_einval() {
    let _g = guard();
    let (root_id, chr, _nr) = chroot_tree();
    common::set_propagation("/", Propagation::Shared).expect("share the root parent");
    let nr_d = common::dentry("/chr/nr");
    let po_d = common::dentry("/chr/nr/old");

    assert_eq!(pivot_as(chr, &nr_d, &po_d), Err(VfsError::Einval),
        "a shared root_parent must be rejected before any mutation");
    assert_eq!(vfs::mount::root_mount_id(ns()), Some(root_id), "a rejected pivot mutates nothing");
    assert_eq!(rendered(chr), "/chr", "a rejected pivot mutates nothing");
}

// `is_path_reachable(new_mnt, new->dentry, &root)`: new_root must lie under the
// CALLER's root, not merely somewhere in the namespace.
#[test]
fn new_root_outside_the_callers_root_is_einval() {
    let _g = guard();
    let (_root_id, chr, _nr) = chroot_tree();
    common::register("/out", fs(0x11)).expect("mount outside the chroot");
    let out_d = common::dentry("/out");
    let po_d = common::dentry("/out/old");

    assert_eq!(pivot_as(chr, &out_d, &po_d), Err(VfsError::Einval),
        "new_root outside the caller's root must be EINVAL");
    assert_eq!(rendered(chr), "/chr", "a rejected pivot mutates nothing");
}

// `is_path_reachable(old_mnt, old_mp->m_dentry, new)`: put_old must lie under
// new_root. A put_old on the caller's OWN root mount is the earlier EBUSY rung
// (`old_mnt == root_mnt`), so this needs a third mount to reach the EINVAL.
#[test]
fn put_old_outside_the_new_root_is_einval() {
    let _g = guard();
    let (_root_id, chr, _nr) = chroot_tree();
    common::register("/chr/side", fs(0x12)).expect("sibling mount inside the chroot");
    let nr_d = common::dentry("/chr/nr");
    let po_d = common::dentry("/chr/side/x");

    assert_eq!(pivot_as(chr, &nr_d, &po_d), Err(VfsError::Einval),
        "put_old outside new_root must be EINVAL");
}

// `old_mnt == root_mnt` is EBUSY, and it outranks the put_old reachability
// EINVAL: a put_old left on the caller's own root filesystem is a loop.
#[test]
fn put_old_on_the_callers_own_root_mount_is_ebusy() {
    let _g = guard();
    let (_root_id, chr, _nr) = chroot_tree();
    let nr_d = common::dentry("/chr/nr");
    let po_d = common::dentry("/chr/elsewhere");

    assert_eq!(pivot_as(chr, &nr_d, &po_d), Err(VfsError::Ebusy),
        "put_old on the caller's own root mount is a loop");
}

// The container / systemd shape — `chdir(new_root); pivot_root(".", ".")`, where
// put_old resolves (LOOKUP_FOLLOW) to the new root's own root dentry so the old
// root stacks directly on it. Caller root == namespace root, so the namespace
// IS re-rooted here.
#[test]
fn pivot_root_dot_dot_reroots_the_namespace() {
    let _g = guard();
    common::register("/", fs(0xA)).expect("ns root");
    common::register("/nr", fs(0xB)).expect("new root");
    let root_id = id("/");
    let nr = id("/nr");
    let nr_d = common::dentry("/nr");

    vfs::mount::pivot_root(&nr_d, &mnt_root(nr)).expect("pivot_root(\".\", \".\")");

    assert_eq!(vfs::mount::root_mount_id(ns()), Some(nr),
        "a caller rooted at the namespace root re-roots the namespace");
    assert_eq!(rendered(nr), "/");
    assert!(vfs::mount::mount_by_id(root_id).is_some(), "the old root survives for the umount(\".\")");
}
