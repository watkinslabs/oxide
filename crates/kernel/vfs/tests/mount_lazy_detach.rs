//! B226: MNT_DETACH lazy umount — a busy mount is unlinked from the namespace
//! tree at once (no EBUSY), but its superblock teardown (`put_super`) is
//! DEFERRED until the last external reference (`mnt_count`, Linux `f_path.mnt`)
//! drops. Mirrors Linux `do_umount(MNT_DETACH)` → `umount_tree` +
//! `mntput_no_expire`: detach immediately, `deactivate_super` only on the final
//! `mntput`. Drives the real global mount engine through the hosted dentry-
//! identity fixture (`common`), no QEMU.
//!
//! Fails-before: `unregister_top` called `put_super_if_last` synchronously per
//! victim, so a still-referenced lazily-detached mount tore its SB down while a
//! pin was held (s_active 1 → 0 at detach). Passes-after: the pin defers the
//! teardown to `mntput`.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
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

// (1) Lazy detach of a BUSY mount (has a child) succeeds AND defers the SB
// teardown while an external `mnt_count` pin is held; the final `mntput`
// completes it.
#[test]
fn lazy_detach_of_busy_mount_defers_put_super() {
    let _g = guard();
    vfs::mount::set_current_ns_provider(|| 0xD5);
    common::register("/", fs(0x1)).expect("root");
    common::register("/a", fs(0x2)).expect("a");
    common::register("/a/b", fs(0x3)).expect("b");          // makes /a busy
    assert!(vfs::mount::has_child_mounts(&common::dentry("/a"), 0xD5), "/a busy via /a/b");

    // Hold an external reference on /a (Linux: an open file's `f_path.mnt`).
    let a = common::mount_at_path_exact("/a").expect("/a mounted");
    let b = common::mount_at_path_exact("/a/b").expect("/a/b mounted");
    vfs::mount::mntget(&a);
    assert_eq!(a.sb().s_active(), 1, "pinned /a SB starts with one active ref");
    assert_eq!(b.sb().s_active(), 1, "/a/b SB starts with one active ref");

    // Lazy (MNT_DETACH) umount of the busy subtree {a, b}.
    let removed = vfs::mount::unregister_top(&common::dentry("/a"), true);
    assert_eq!(removed, 2, "lazy detach removed a and b from the tree");
    assert!(common::mount_at_path_exact("/a").is_none(), "/a unlinked from tree at once");
    assert!(common::mount_at_path_exact("/a/b").is_none(), "/a/b unlinked from tree");
    assert!(a.is_detached(), "/a flagged MNT_DETACHED");

    // /a/b had no external pin → torn down immediately on detach.
    assert_eq!(b.sb().s_active(), 0, "unpinned child SB torn down at detach");
    // /a is pinned → its SB teardown is DEFERRED (this is the fails-before line).
    assert_eq!(a.sb().s_active(), 1, "pinned /a SB teardown deferred past detach");

    // Drop the last external reference → deferred `put_super` runs now.
    vfs::mount::mntput(&a);
    assert_eq!(a.sb().s_active(), 0, "final mntput completes the deferred teardown");
}

// (2) Lazy detach of an UNPINNED busy mount tears the SB down immediately —
// the deferral is keyed on a live `mnt_count`, not on the lazy flag alone.
#[test]
fn lazy_detach_without_pin_tears_down_now() {
    let _g = guard();
    vfs::mount::set_current_ns_provider(|| 0xD6);
    common::register("/", fs(0x1)).expect("root");
    common::register("/a", fs(0x2)).expect("a");
    common::register("/a/b", fs(0x3)).expect("b");

    let a = common::mount_at_path_exact("/a").expect("/a mounted");
    assert_eq!(a.mnt_count(), 0, "no external pin held");
    assert_eq!(a.sb().s_active(), 1, "/a SB active before umount");

    assert_eq!(vfs::mount::unregister_top(&common::dentry("/a"), true), 2, "subtree detached");
    assert!(a.is_detached(), "/a flagged MNT_DETACHED");
    assert_eq!(a.sb().s_active(), 0, "unpinned lazy detach tears the SB down at once");
}
