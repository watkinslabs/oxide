//! `pivot_root(2)` when the caller's root IS the mount-namespace root — the
//! initramfs / container shape. Linux makes exactly TWO `attach_mnt()` calls:
//! `new_root` takes the old root's slot, and the old root is re-attached at the
//! mountpoint object `put_old` resolved to. Every other mount keeps BOTH its
//! mountpoint dentry and its parent, because those dentries live inside
//! filesystems that travelled with the pivot.
//!
//! The regressions pinned here:
//!
//! * a `put_old` that is itself COVERED by another mount must land the old root
//!   on the covering mount's ROOT dentry with the covering mount as parent —
//!   re-deriving the position from the rendered destination string cannot name
//!   that dentry, and lands the old root on the underlay instead;
//! * a mount that is neither root keeps its recorded parent, so a bind/clone
//!   sharing an `s_root` with another mount cannot be re-parented onto its twin;
//! * both relocated mounts fire an `FS_MNT_MOVE` mount-namespace notification,
//!   which `pivot_root` must emit explicitly because it re-seats mounts in
//!   place instead of going through the publish/unpublish choke points.
//!
//! Exercises the real global mount engine via the hosted fixture, no QEMU.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{Dentry, FileType, InodeBuilder, InodeOps, InodeRef, KResult, mk_mode, default_file_ops};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());
static NEXT_NS: AtomicU64 = AtomicU64::new(0x9400);

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
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Ok(make_tdir(0xD80)) }
}
fn make_tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TFs { root_ino: ino }) }

fn ns() -> u64 { vfs::mount::current_ns() }
fn id(p: &str) -> u64 { common::mount_at_path_exact(p).expect("mount exists").mnt_id }
fn parent_of(m: u64) -> u64 { vfs::mount::parent_mnt_id(&vfs::mount::mount_by_id(m).unwrap()) }
fn mnt_root(m: u64) -> Arc<Dentry> { vfs::mount::mount_by_id(m).unwrap().mnt_root().unwrap() }
fn mountpoint(m: u64) -> Arc<Dentry> { vfs::mount::mount_by_id(m).unwrap().mountpoint().unwrap() }

/// `/` (namespace root, also the caller's root), `/nr` (new root), and a mount
/// COVERING the `put_old` directory `/nr/old`.
fn covered_put_old_tree() -> (u64, u64, u64) {
    common::register("/", fs(0xA1)).expect("ns root");
    common::register("/nr", fs(0xB1)).expect("new root");
    common::register("/nr/old", fs(0xC1)).expect("mount covering put_old");
    (id("/"), id("/nr"), id("/nr/old"))
}

// A covered `put_old` in the re-root branch must attach the displaced old root
// on the COVERING mount's root dentry, with the covering mount as its parent.
#[test]
fn a_covered_put_old_attaches_the_old_root_on_the_covering_mounts_root() {
    let _g = guard();
    let (old_root, nr, cover) = covered_put_old_tree();
    let po_d = common::dentry("/nr/old");

    vfs::mount::pivot_root(&common::dentry("/nr"), &po_d).expect("pivot onto /nr, put_old /nr/old");

    assert_eq!(vfs::mount::root_mount_id(ns()), Some(nr), "new_root becomes the namespace root");
    assert_eq!(parent_of(old_root), cover,
        "the old root must hang off the mount covering put_old, not off the underlay");
    assert!(Arc::ptr_eq(&mountpoint(old_root), &mnt_root(cover)),
        "the old root must attach on the covering mount's ROOT dentry");
}

// Everything that is not one of the two mounts named by the call keeps its
// mountpoint dentry AND its recorded parent: Linux re-parents exactly two.
#[test]
fn only_the_two_named_mounts_change_attachment() {
    let _g = guard();
    let (_old_root, nr, _cover) = covered_put_old_tree();
    common::register("/nr/sub", fs(0xD1)).expect("mount inside the new root");
    let sub = id("/nr/sub");
    let sub_mp = mountpoint(sub);

    vfs::mount::pivot_root(&common::dentry("/nr"), &common::dentry("/nr/old"))
        .expect("pivot onto /nr");

    assert_eq!(parent_of(sub), nr, "an in-new-root mount keeps its recorded parent");
    assert!(Arc::ptr_eq(&mountpoint(sub), &sub_mp),
        "an in-new-root mount keeps its mountpoint dentry — it travelled with the filesystem");
}

// `pivot_root` re-seats mounts in place instead of going through the publish /
// unpublish choke points, so it has to fire the mount-namespace notification
// itself. One FS_MNT_MOVE record per relocated mount, and no others.
#[test]
fn the_reroot_fires_one_mount_move_notification_per_relocated_mount() {
    let _g = guard();
    static SEEN: Mutex<Vec<(u64, u64, u32)>> = Mutex::new(Vec::new());
    fn record(ns_id: u64, mnt_id: u64, mask: u32) {
        SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((ns_id, mnt_id, mask));
    }
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();

    let (old_root, nr, _cover) = covered_put_old_tree();
    vfs::mount::set_mnt_notify_hook(record);
    let this_ns = ns();

    vfs::mount::pivot_root(&common::dentry("/nr"), &common::dentry("/nr/old"))
        .expect("pivot onto /nr");

    let seen = SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(seen, vec![
        (this_ns, old_root, vfs::mount::FS_MNT_MOVE),
        (this_ns, nr, vfs::mount::FS_MNT_MOVE),
    ], "the displaced old root and the new root each report one move record");
}
