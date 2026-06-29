//! mount/D8 (hash-key) + D9 (overmount topology), FUNCTIONAL validation.
//!
//! The `(ns, parent_mnt_id, mountpoint_dentry_ptr) -> Vec<mnt_id>` hash
//! (Linux `__lookup_mnt`) stacks every mount attached at the SAME mountpoint
//! dentry; "top of stack = last attached" is the covering (visible) mount,
//! and an `umount` of the top REVEALS the underlay. The structural divergence
//! the ledger tracks (ns-in-key; an overmount's `parent_id` is the underlay's
//! parent, not the underlay mount; value is a Vec not a single covering mount)
//! is NOT a live functional bug: crossing always lands on the top, and the
//! stack pops to reveal the underlay in attach order. This test pins that
//! contract so a future hash refactor cannot silently break overmount
//! cover/reveal. Process-global table → SERIAL-guarded.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{FileType, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, default_file_ops, mk_mode};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0);
    common::install();
    g
}

struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn make_tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}
struct OvFs { ino: u64 }
impl FileSystem for OvFs {
    fn name(&self) -> &str { "ovfs" }
    fn root(&self) -> Option<InodeRef> { Some(make_tdir(self.ino)) }
}

/// Stack three mounts at the SAME mountpoint dentry; the crossing returns the
/// LAST attached (top), and each `umount` of the top reveals the next in
/// reverse-attach (LIFO) order — the overmount stack contract.
#[test]
fn overmount_top_wins_and_umount_reveals_underlay() {
    let _g = guard();
    // A under B under C, all at /ov (one underlay mountpoint dentry).
    common::register("/ov", Arc::new(OvFs { ino: 0xAA })).expect("mount A");
    common::register("/ov", Arc::new(OvFs { ino: 0xBB })).expect("mount B over A");
    common::register("/ov", Arc::new(OvFs { ino: 0xCC })).expect("mount C over B");

    // Crossing lands on the TOP of the stack (C).
    assert_eq!(common::mount_root_at("/ov").expect("cross").ino(), 0xCC,
        "top of the overmount stack = last attached");

    // umount pops C → reveals B.
    assert_eq!(common::unregister("/ov"), 1, "umount removes exactly the top");
    assert_eq!(common::mount_root_at("/ov").expect("cross").ino(), 0xBB,
        "umount of the top reveals the prior overmount (LIFO)");

    // umount pops B → reveals A.
    assert_eq!(common::unregister("/ov"), 1);
    assert_eq!(common::mount_root_at("/ov").expect("cross").ino(), 0xAA,
        "second umount reveals the base mount");

    // umount pops A → nothing left at /ov.
    assert_eq!(common::unregister("/ov"), 1);
    assert!(common::mount_root_at("/ov").is_none(),
        "stack empty → the underlay dentry is no longer a mountpoint");
}

/// Two DISTINCT mountpoint dentries hash to independent stacks: umounting one
/// position does not disturb the other (the (parent,dentry) key is per-position).
#[test]
fn distinct_mountpoints_are_independent_stacks() {
    let _g = guard();
    common::register("/p", Arc::new(OvFs { ino: 0x11 })).expect("mount /p");
    common::register("/q", Arc::new(OvFs { ino: 0x22 })).expect("mount /q");
    common::register("/q", Arc::new(OvFs { ino: 0x33 })).expect("overmount /q");

    assert_eq!(common::mount_root_at("/p").expect("p").ino(), 0x11);
    assert_eq!(common::mount_root_at("/q").expect("q top").ino(), 0x33);

    // Popping /q's top must not touch /p.
    assert_eq!(common::unregister("/q"), 1);
    assert_eq!(common::mount_root_at("/q").expect("q reveal").ino(), 0x22);
    assert_eq!(common::mount_root_at("/p").expect("p intact").ino(), 0x11,
        "an unrelated position's mount is untouched by a sibling umount");
}
