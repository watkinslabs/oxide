//! B182: regression guard for the umount/detach machinery after it moved from
//! `mount.rs` into the `mount::detach` submodule (line-cap split). Asserts the
//! re-exported `vfs::mount::{unregister,unregister_top}` surface still drives
//! (a) recursive subtree teardown via the intrusive child list and (b)
//! propagate_umount — detaching the propagated mirror at a SHARED peer. Pure
//! behavior pin: exercises the real global mount engine through the hosted
//! dentry-identity fixture (`common`), no QEMU.

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

// (1) unregister_top(detach_subtree=true) tears down the mount AND its
// transitive children via the intrusive subtree walk, in one call.
#[test]
fn unregister_top_detaches_whole_subtree() {
    let _g = guard();
    vfs::mount::set_current_ns_provider(|| 0xD1);
    common::register("/", fs(0x1)).expect("root");
    common::register("/a", fs(0x2)).expect("a");
    common::register("/a/b", fs(0x3)).expect("b");
    common::register("/a/b/c", fs(0x4)).expect("c");
    assert!(vfs::mount::has_child_mounts(&common::dentry("/a/b"), 0xD1), "/a/b has /a/b/c");
    // Subtree detach of /a/b removes b + c (2 mounts).
    let removed = vfs::mount::unregister_top(&common::dentry("/a/b"), true);
    assert_eq!(removed, 2, "subtree detach removed b and c");
    assert!(common::mount_at_path_exact("/a/b").is_none(), "/a/b unmounted");
    assert!(common::mount_at_path_exact("/a/b/c").is_none(), "/a/b/c unmounted");
    // The untouched parent /a survives and is now a leaf.
    assert!(common::mount_at_path_exact("/a").is_some(), "/a still mounted");
    assert!(!vfs::mount::has_child_mounts(&common::dentry("/a"), 0xD1), "/a now a leaf");
}

// (2) a mount under a SHARED parent mirrored to a peer is independently
// detachable: `unregister` of the mirror at the peer removes it without
// touching the primary; `unregister_top` then removes the primary. Exercises
// the moved `unregister` against a propagated mount.
#[test]
fn unregister_detaches_propagated_mirror() {
    let _g = guard();
    vfs::mount::set_current_ns_provider(|| 0xD2);
    common::register("/", fs(0x1)).expect("root");
    common::register("/sa", fs(0xA)).expect("sa");
    common::set_propagation("/sa", Propagation::Shared).expect("share sa");
    let pg = common::peer_group_of("/sa");
    common::register("/sb", fs(0xB)).expect("sb");
    common::join_peer_group("/sb", pg);                 // peer of sa
    // Mount under sa, propagate → mirror appears under the peer sb.
    common::register("/sa/x", fs(0x11)).expect("under sa");
    assert_eq!(common::propagate_mount("/sa/x"), 1, "mirrored to one peer");
    assert_eq!(common::mount_root_at("/sb/x").map(|i| i.ino()), Some(0x11), "peer has mirror");
    // Direct umount of the mirror removes exactly it; the primary survives.
    assert_eq!(vfs::mount::unregister(&common::dentry("/sb/x")), 1, "mirror umounted");
    assert!(common::mount_at_path_exact("/sb/x").is_none(), "mirror gone");
    assert!(common::mount_at_path_exact("/sa/x").is_some(), "primary survives mirror umount");
    // unregister_top removes the primary.
    assert_eq!(vfs::mount::unregister_top(&common::dentry("/sa/x"), false), 1, "primary detached");
    assert!(common::mount_at_path_exact("/sa/x").is_none(), "primary gone");
}

// (3) unregister_top refuses to detach the namespace root mount (returns 0).
#[test]
fn unregister_top_refuses_ns_root() {
    let _g = guard();
    vfs::mount::set_current_ns_provider(|| 0xD3);
    common::register("/", fs(0x1)).expect("root");
    assert_eq!(vfs::mount::unregister_top(&common::dentry("/"), false), 0, "ns root not detachable");
    assert!(vfs::mount::root_mount_id(0xD3).is_some(), "root mount survives");
}
