//! ACCEPTANCE: udevd private-sysfs sandbox (the captured pass-6 failure).
//! udevd does `mount("sysfs", "/tmp/ns/sysfs-XXXX")` at a fresh mkdtemp temp
//! path, then `mount(MS_MOVE, "/tmp/ns/sysfs-XXXX" -> "/sys")`. The MS_MOVE
//! source is a mount at a path that was NEVER a pre-known mount; the old
//! string/longest-prefix engine failed to find it (mount_exact_at re-resolved
//! the rendered path and missed) → EINVAL → systemd EXIT_NAMESPACE(226) →
//! udevd never starts. With attach-time (parent,mountpoint-dentry) recording
//! the move source is found by IDENTITY, so the move succeeds and the mount
//! ends up at /sys with the correct parent.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0);
    common::install_dentry_resolver();
    g
}

struct TDir { ino: u64 }
impl Inode for TDir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}

struct TestFs { root_ino: u64 }
impl FileSystem for TestFs {
    fn name(&self) -> &str { "sysfs" }
    fn root(&self) -> Option<InodeRef> { Some(Arc::new(TDir { ino: self.root_ino })) }
}

#[test]
fn udevd_sysfs_move_from_mkdtemp_temp_path() {
    let _g = guard();
    const NS: u64 = 0xDEAD_BEEF;
    vfs::mount::set_current_ns_provider(|| NS);
    let ns = NS;

    // Host tree. In the private mount-ns sandbox `/sys` is an empty
    // mountpoint dir (not yet a mount); udevd moves its private sysfs onto it.
    vfs::mount::register("/", Arc::new(TestFs { root_ino: 0x1 })).expect("root");
    vfs::mount::register("/tmp", Arc::new(TestFs { root_ino: 0x7 })).expect("tmp");

    // udevd: mount fresh sysfs at a mkdtemp temp path that was NEVER a
    // pre-known mount.
    let temp = "/tmp/ns/sysfs-Xa9f3";
    vfs::mount::register(temp, Arc::new(TestFs { root_ino: 0x55 })).expect("temp sysfs");

    // The temp mount MUST be findable as an exact mount by identity.
    assert!(vfs::mount::is_mount_in_ns(temp, ns), "temp sysfs is an exact mount");
    let temp_id = vfs::mount::snapshot().iter()
        .find(|m| m.mount_point_str() == temp).expect("temp present").mnt_id;

    // The move that used to EINVAL.
    let mv = vfs::mount::move_mount(temp, "/sys");
    assert!(mv.is_ok(), "MS_MOVE(temp -> /sys) must succeed, got {:?}", mv);

    // The moved mount is now resolvable at /sys (top of the stack), same id.
    let at_sys = vfs::mount::mount_at_path_exact("/sys").expect("mount at /sys");
    assert_eq!(at_sys.mnt_id, temp_id, "the moved sysfs is now the mount at /sys");
    assert_eq!(at_sys.fs.root().map(|i| i.ino()), Some(0x55), "moved sysfs root inode");

    // Parent of /sys is the mount owning '/' (root mount), by identity.
    let root_id = vfs::mount::root_mount_id(ns).expect("root id");
    assert_eq!(vfs::mount::parent_mnt_id(&at_sys), root_id, "/sys parent is the root mount");

    // The temp path is no longer a mount.
    assert!(!vfs::mount::is_mount_in_ns(temp, ns), "temp path cleared after move");

    // mountinfo render: no non-root line self-parents (the journald-SIGSEGV
    // / libmount cyclic-line guard).
    for m in vfs::mount::snapshot().iter() {
        if vfs::mount::root_mount_id(ns) == Some(m.mnt_id) { continue; }
        assert_ne!(vfs::mount::parent_mnt_id(&m), m.mnt_id,
            "non-root mount {} must not self-parent", m.mnt_id);
    }
}
