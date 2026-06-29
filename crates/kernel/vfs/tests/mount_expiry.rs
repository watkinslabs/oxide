//! B252 [D26]: mount expiry list (Linux `mark_mounts_for_expiry`). Entirely
//! absent pre-fix (grep mnt_expire/MNT_EXPIRE/mark_mounts empty). A member of an
//! expire list that has gone idle is auto-umounted on the SECOND sweep (two-pass
//! grace); a busy member (child mounts / external pin) is never reaped; a member
//! referenced via mntget between sweeps resets its grace. Exercises the real
//! global mount engine via the hosted dentry-identity fixture. Serializes on
//! `SERIAL`.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{FileType, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, default_file_ops, mk_mode};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0xE0E0);
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

fn mounted(p: &str) -> bool { common::mount_at_path_exact(p).is_some() }
fn mount_obj(p: &str) -> Arc<vfs::mount::Mount> {
    common::mount_at_path_exact(p).expect("mount exists")
}

// Two-pass grace: an idle expire-list member survives the FIRST sweep (it is
// only marked) and is umounted on the SECOND. Pre-fix there was no expiry
// machinery at all.
#[test]
fn idle_member_reaped_on_second_sweep() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/e1", fs(0xA)).expect("e1");
    let list = vfs::mount::expire_list_create();
    vfs::mount::mnt_expire_add(list, &mount_obj("/e1"));

    assert!(mounted("/e1"), "mounted before any sweep");
    assert_eq!(vfs::mount::mark_mounts_for_expiry(list), 0, "first sweep only marks");
    assert!(mounted("/e1"), "survives the first sweep (grace)");
    assert_eq!(vfs::mount::mark_mounts_for_expiry(list), 1, "second sweep reaps the idle mount");
    assert!(!mounted("/e1"), "e1 auto-umounted");
    // Sweep on the now-empty list is a no-op.
    assert_eq!(vfs::mount::mark_mounts_for_expiry(list), 0, "empty list");
}

// A busy member (has a child mount) is marked but NEVER reaped, no matter how
// many sweeps run (Linux `propagate_mount_busy`).
#[test]
fn busy_member_is_never_reaped() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/e2", fs(0xB)).expect("e2");
    common::register("/e2/sub", fs(0xB2)).expect("e2/sub"); // child ⇒ e2 busy
    let list = vfs::mount::expire_list_create();
    vfs::mount::mnt_expire_add(list, &mount_obj("/e2"));

    assert_eq!(vfs::mount::mark_mounts_for_expiry(list), 0);
    assert_eq!(vfs::mount::mark_mounts_for_expiry(list), 0, "busy: not reaped on 2nd sweep");
    assert!(mounted("/e2"), "busy mount survives");
    assert!(mounted("/e2/sub"), "child intact");
}

// A member referenced between sweeps (mntget clears the expiry mark) resets its
// grace, so it survives a sweep where it would otherwise have been reaped.
#[test]
fn use_between_sweeps_resets_grace() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/e3", fs(0xC)).expect("e3");
    let list = vfs::mount::expire_list_create();
    let m = mount_obj("/e3");
    vfs::mount::mnt_expire_add(list, &m);

    assert_eq!(vfs::mount::mark_mounts_for_expiry(list), 0, "1st sweep marks");
    // Use the mount (path walk pin), then release: the mark is cleared, pin gone.
    vfs::mount::mntget(&m);
    vfs::mount::mntput(&m);
    // Would have reaped here without the use; instead it is re-marked + survives.
    assert_eq!(vfs::mount::mark_mounts_for_expiry(list), 0, "use reset the grace");
    assert!(mounted("/e3"), "still mounted after the reset");
    // Now left idle: marked this pass, reaped the next.
    assert_eq!(vfs::mount::mark_mounts_for_expiry(list), 1, "reaped once truly idle");
    assert!(!mounted("/e3"));
}

// `mnt_expire_remove` revokes a member's expiry: it is no longer swept.
#[test]
fn removed_member_is_not_swept() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/e4", fs(0xD)).expect("e4");
    let list = vfs::mount::expire_list_create();
    let m = mount_obj("/e4");
    vfs::mount::mnt_expire_add(list, &m);
    assert_eq!(vfs::mount::mark_mounts_for_expiry(list), 0, "marked");
    vfs::mount::mnt_expire_remove(list, &m);
    assert_eq!(vfs::mount::mark_mounts_for_expiry(list), 0, "removed: not reaped");
    assert!(mounted("/e4"), "survives after removal from the list");
}
