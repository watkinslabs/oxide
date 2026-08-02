//! `fsmount(2)`'s mount exists before anyone says where it goes.
//!
//! The reference creates a real `vfsmount` and parks it in an ANONYMOUS mount
//! namespace: real id, real superblock, real root, in nobody's tree. What this
//! replaces carried `(sb, root)` on the fd and minted a mount only at
//! `move_mount` time, so between the two calls there was no mount at all —
//! nothing with an id, nothing `statmount` could answer about, and nothing to
//! tear down if the fd was simply closed.
//!
//! Driven against the real global mount engine through the hosted fixture, so
//! these run in `cargo test` — the syscall shims themselves are
//! `#![cfg(target_os = "oxide-kernel")]` and cannot be.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(common::current_namespace);
    common::install();
    g
}

struct TFs { root_ino: u64 }
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
    fn root(&self) -> Option<InodeRef> { Some(tdir(self.root_ino)) }
}
struct TDirOps;
impl vfs::InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Ok(tdir(0xB00)) }
}
fn tdir(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755),
        Arc::new(TDirOps), vfs::default_file_ops()).build()
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TFs { root_ino: ino }) }

/// A realized superblock, as `fsopen`+`fsconfig(CMD_CREATE)` produces before
/// `fsmount` is called.
fn realized_sb(ino: u64, dev: u64) -> Arc<vfs::SuperBlock> {
    let f = fs(ino);
    common::ensure_fs_type(&f);
    common::realize_sb(f, None, dev, String::from("anonfs"))
}

/// The property the old shape could not have: a mount, with an id, before
/// anybody has said where it goes.
#[test]
fn an_fsmounted_filesystem_is_a_real_mount_before_it_is_moved_anywhere() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");

    let m = vfs::mount::create_anon_mount(realized_sb(0xA1, 0x901), 0, 0, None)
        .expect("anonymous mount");

    assert!(m.mnt_id != 0, "a mount that exists has an id; the fd used to carry 0");
    assert!(vfs::mount::mount_by_id(m.mnt_id).is_some(),
        "it is in the mount arena, so statmount on its own fd can answer");
    assert!(vfs::mount::anon_ns_root(&m), "it is the root of its anonymous namespace");
    assert!(m.mnt_root().is_some(), "and it has a real root dentry to open as a dirfd");
}

/// ...and it is nobody's: not in the caller's namespace, so no path walk
/// reaches it and a `listmount` of the caller's namespace cannot see it. That
/// invisibility is the reference's behaviour, not a gap.
#[test]
fn an_anonymous_mount_is_not_in_the_callers_namespace() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    let caller_ns = vfs::mount::current_ns();

    let m = vfs::mount::create_anon_mount(realized_sb(0xA2, 0x902), 0, 0, None)
        .expect("anonymous mount");

    assert!(m.namespace_id() != caller_ns,
        "an anonymous mount lives in its own namespace");
    let root = vfs::mount::root_mount_id(caller_ns).expect("ns root");
    let visible = vfs::mount::listmount_ids(caller_ns, root, false, 0, false, usize::MAX);
    assert!(!visible.contains(&vfs::mount::unique_mnt_id(m.mnt_id)),
        "listmount of the caller's namespace must not show it");
}

/// Two anonymous mounts are two namespaces — one fsmount fd cannot see or
/// dissolve another's.
#[test]
fn each_anonymous_mount_gets_its_own_namespace() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    let a = vfs::mount::create_anon_mount(realized_sb(0xA3, 0x903), 0, 0, None).expect("a");
    let b = vfs::mount::create_anon_mount(realized_sb(0xA4, 0x904), 0, 0, None).expect("b");
    assert!(a.mnt_id != b.mnt_id);
    assert!(a.namespace_id() != b.namespace_id());
}

/// Closing the fd without moving it takes the mount with it (Linux
/// `dissolve_on_fput`). Without this the mount and its superblock would sit in
/// the arena forever, which is the leak the old shape could not even express.
#[test]
fn dropping_an_unmoved_anonymous_mount_dissolves_it() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    let m = vfs::mount::create_anon_mount(realized_sb(0xA5, 0x905), 0, 0, None).expect("anon");
    let id = m.mnt_id;
    assert!(vfs::mount::mount_by_id(id).is_some());

    vfs::mount::dissolve_anon(&m);

    assert!(vfs::mount::mount_by_id(id).is_none(), "the mount is gone from the arena");
    assert!(!vfs::mount::anon_ns_root(&m), "and is no longer any namespace's root");
}

/// Dissolving twice is what a close-after-close would do; it must not remove
/// anything a second time or panic.
#[test]
fn dissolving_twice_is_harmless() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    let m = vfs::mount::create_anon_mount(realized_sb(0xA6, 0x906), 0, 0, None).expect("anon");
    vfs::mount::dissolve_anon(&m);
    vfs::mount::dissolve_anon(&m);
    assert!(vfs::mount::mount_by_id(m.mnt_id).is_none());
}

/// The mount option word given at `fsmount` time rides on the mount itself, so
/// `MOUNT_ATTR_*` are not lost between `fsmount` and `move_mount`.
#[test]
fn the_mount_attrs_given_at_creation_are_carried_by_the_mount() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    let flags = vfs::mount::MNT_NOSUID | vfs::mount::MNT_NODEV;
    let m = vfs::mount::create_anon_mount(realized_sb(0xA7, 0x907), flags, 0, None).expect("anon");
    let live = m.flags.load(core::sync::atomic::Ordering::Acquire);
    assert!(live & vfs::mount::MNT_NOSUID != 0, "nosuid survived to the mount");
    assert!(live & vfs::mount::MNT_NODEV != 0, "nodev survived to the mount");
}

/// `move_mount(2)`: the SAME mount object joins the caller's tree. Same id
/// before and after, which is what makes the id worth reporting at all.
#[test]
fn moving_an_anonymous_mount_keeps_its_identity_and_joins_the_callers_namespace() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    let caller_ns = vfs::mount::current_ns();
    let m = vfs::mount::create_anon_mount(realized_sb(0xA8, 0x908), 0, 0, None).expect("anon");
    let id = m.mnt_id;

    let target = common::dentry("/mnt");
    let base = vfs::mount::root_mount_id(caller_ns).expect("ns root");
    vfs::mount::graft_anon_mount_at(&m, target, base).expect("graft");

    assert_eq!(m.mnt_id, id, "the move does not mint a new mount");
    assert_eq!(m.namespace_id(), caller_ns, "it is the caller's now");
    assert!(!vfs::mount::anon_ns_root(&m), "and no longer an anonymous root");
    assert!(vfs::mount::mount_by_id(id).is_some(), "still in the arena");
    // `listmount` reports UNIQUE ids, which is the id space `statmount`'s
    // request struct uses — not the raw `mnt_id`.
    let visible = vfs::mount::listmount_ids(caller_ns, base, false, 0, false, usize::MAX);
    assert!(visible.contains(&vfs::mount::unique_mnt_id(id)),
        "and now listmount of the caller's namespace shows it");
}

/// After a move, closing the fd must NOT tear the mount down — it belongs to
/// the tree now. This is the whole point of the reference re-checking
/// `anon_ns_root` inside `dissolve_on_fput` rather than trusting the flag it
/// set at open time.
#[test]
fn closing_the_fd_after_a_move_does_not_unmount_the_now_grafted_mount() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    let caller_ns = vfs::mount::current_ns();
    let m = vfs::mount::create_anon_mount(realized_sb(0xA9, 0x909), 0, 0, None).expect("anon");
    let base = vfs::mount::root_mount_id(caller_ns).expect("ns root");
    vfs::mount::graft_anon_mount_at(&m, common::dentry("/mnt2"), base).expect("graft");

    vfs::mount::dissolve_anon(&m);   // what the fd's teardown does unconditionally

    assert!(vfs::mount::mount_by_id(m.mnt_id).is_some(),
        "a grafted mount survives the fd that created it");
}

/// A mount can only be grafted out of an anonymous namespace once; the second
/// attempt is EINVAL rather than a second attach of one mount.
#[test]
fn an_anonymous_mount_can_only_be_moved_once() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    let base = vfs::mount::root_mount_id(vfs::mount::current_ns()).expect("ns root");
    let m = vfs::mount::create_anon_mount(realized_sb(0xAA, 0x90A), 0, 0, None).expect("anon");
    vfs::mount::graft_anon_mount_at(&m, common::dentry("/mnt3"), base).expect("first graft");
    assert_eq!(vfs::mount::graft_anon_mount_at(&m, common::dentry("/mnt4"), base),
        Err(vfs::VfsError::Einval), "the source is no longer an anonymous root");
}
