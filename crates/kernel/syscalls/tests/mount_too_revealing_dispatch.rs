// B1478: the SYSCALL-layer half of `mount_too_revealing`. Drives the extracted
// `mount_dispatch::dispatch_mount` (ungated pure fn,
// `src/fsmount_common/mount_dispatch.rs` — the body of `mount(2)`'s
// new-superblock arm) against the real `vfs` mount engine, hosted.
//
// The vfs-side decision is proven in `vfs/tests/mount_too_revealing.rs`; this
// file proves the WIRING: that `mount(2)` actually consults it, refuses with
// EPERM, grafts nothing on refusal, and installs the inherited MNT_LOCK_* bits
// on the mount it does graft. Linux `fs/namespace.c` `do_new_mount_fc`:
//
//     if (unlikely(mount_too_revealing(sb, &mnt_flags))) {
//             errorfcp(fc, "VFS", "Mount too revealing");
//             return -EPERM;
//     }
//
// It also proves `superblock_from_filesystem` stamps `s_iflags` from the
// backend — without that, EVERY user-namespace mount of a
// FS_USERNS_MOUNT_RESTRICTED type is refused by the `required_iflags` branch.
// This integration test compiles production modules directly via `#[path]` to
// assert their ABI shape, and exercises only the part of each module the shape
// under test needs. dead_code here measures the test's reach, not the kernel's
// -- the real signal lives in `xtask kernel`, which is dead_code-clean.
#![allow(dead_code)]
use std::sync::{Arc, Mutex, MutexGuard};

extern crate alloc;

use namespace_identity::{NamespaceKind, NamespaceRef};
use syscall::errno::Errno;
use vfs::fs::{FileSystem, FsFlags, FsType};
use mount_dispatch::MountCaps;
use vfs::inode::Inode;
use vfs::mount::{MNT_LOCK_ATIME, MNT_LOCK_READONLY, MNT_RDONLY, MNT_RELATIME, MS_RDONLY};
use vfs::superblock::SB_I_USERNS_REQUIRED;
use vfs::{FileType, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

#[path = "../../vfs/tests/common/mod.rs"]
mod common;

#[path = "../src/namei_common/errno.rs"]
mod namei_common;

// `mount_capable` is its own ungated module so the user-namespace rung is
// testable on its own; `mount_dispatch` names it through the crate root, which
// here is this test binary.
#[path = "../src/mount_capable.rs"]
mod mount_capable;
#[path = "../src/fsmount_common/mount_dispatch.rs"]
mod mount_dispatch;

static SERIAL: Mutex<()> = Mutex::new(());
static CUR_NS: Mutex<Option<vfs::mntns::MntNamespaceRef>> = Mutex::new(None);

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// An unprivileged user-namespace holder: full capability set INSIDE its own
/// userns (so `may_mount()` and `mount_capable` both pass for a
/// `FS_USERNS_MOUNT` type), none in the initial one. `mount_too_revealing` is
/// the ONLY thing left standing between it and a pristine procfs.
const USERNS_CAPS: MountCaps = MountCaps { init_user_ns: false, mnt_user_ns: true };
const ROOT_CAPS: MountCaps = MountCaps { init_user_ns: true, mnt_user_ns: true };

fn cur_ns() -> vfs::mntns::MntNamespaceRef {
    CUR_NS.lock().unwrap_or_else(|e| e.into_inner()).as_ref().expect("current namespace owner").clone()
}

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    common::install();
    vfs::mount::set_current_ns_provider(cur_ns);
    g
}

struct RootDirOps;
impl InodeOps for RootDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Ok(plain_dir(0xD670_0100)) }
}
fn plain_dir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755), Arc::new(RootDirOps), vfs::default_file_ops()).build()
}
struct RootFs { tag: &'static str }
impl FileSystem for RootFs {
    fn name(&self) -> &str { self.tag }
    fn root(&self) -> Option<InodeRef> { Some(plain_dir(1)) }
}

/// A fresh mount namespace owned by a fresh CHILD user namespace — the shape
/// `unshare(CLONE_NEWUSER|CLONE_NEWNS)` produces, and the only one in which
/// Linux applies this check.
fn unprivileged_ns(tag: &'static str) {
    let parent_user: NamespaceRef = namespace_identity::initial(NamespaceKind::User);
    let child_user = namespace_identity::allocate(NamespaceKind::User, parent_user.clone(),
        Some(parent_user)).expect("child user namespace");
    let namespace = vfs::mntns::allocate(child_user).expect("mount ns under the child user ns");
    *CUR_NS.lock().unwrap_or_else(|e| e.into_inner()) = Some(namespace);
    common::register("/", Arc::new(RootFs { tag })).expect("root mount");
}

// --- the procfs stand-in: FS_USERNS_MOUNT | FS_USERNS_MOUNT_RESTRICTED, and
// `s_iflags = SB_I_NOEXEC | SB_I_NODEV` as `proc_fill_super` stamps them. ---
const REVEAL_ROOT_INO: u64 = 0xDEAD_0001;
struct RevealRootOps;
impl InodeOps for RevealRootOps {
    fn lookup(&self, _inode: &Inode, n: &str) -> KResult<InodeRef> {
        if n == "kcore" { Ok(plain_dir(0xDEAD_0002)) } else { Err(VfsError::Enoent) }
    }
}
struct RevealFs;
impl FileSystem for RevealFs {
    fn name(&self) -> &str { "revealproc" }
    fn s_iflags(&self) -> u64 { SB_I_USERNS_REQUIRED }
    fn root(&self) -> Option<InodeRef> {
        Some(InodeBuilder::new(REVEAL_ROOT_INO, vfs::mk_mode(FileType::Directory, 0o755),
            Arc::new(RevealRootOps), vfs::default_file_ops()).build())
    }
}
fn register_revealproc() {
    let _ = vfs::fs::register_fs(FsType::new("revealproc", 0x9fa0,
        FsFlags::FS_USERNS_MOUNT | FsFlags::FS_USERNS_MOUNT_RESTRICTED,
        Box::new(|ty, _s, _t, _d, _, _: &[vfs::fs::FsParameter]| {
            let fs: Arc<dyn FileSystem> = Arc::new(RevealFs);
            vfs::fs::superblock_from_filesystem(ty, fs, None, "revealproc".into(), 0)
        })));
}

/// Graft an instance of `revealproc` straight through the engine — the
/// already-visible mount a real namespace inherits from its parent via
/// `copy_mnt_ns`, not through the syscall under test.
fn graft_visible(at: &str, mnt_flags: u64) -> Arc<vfs::mount::Mount> {
    let ty = vfs::fs::get_fs("revealproc").expect("registered");
    let sb = ty.construct(None, at, "").expect("superblock");
    assert_eq!(sb.s_iflags(), SB_I_USERNS_REQUIRED,
        "superblock_from_filesystem stamps FileSystem::s_iflags (fill_super)");
    vfs::mount::attach_sb_with_flags_at(Some(common::dentry(at)), sb, mnt_flags, None)
        .expect("graft the inherited instance");
    vfs::mount::mount_at_path_exact(&common::dentry(at)).expect("visible mount")
}

#[test]
fn a_userns_caller_cannot_mount_a_revealing_procfs() {
    let _g = guard();
    register_revealproc();
    unprivileged_ns("reveal-a");
    let target_d = common::dentry("/mnt/point");

    // THE ESCAPE. `mount_capable` says yes (FS_USERNS_MOUNT), `may_mount` says
    // yes (CAP_SYS_ADMIN inside the userns) — and before this fix nothing else
    // was consulted, so the caller got a pristine instance showing everything
    // its own namespace's procfs had covered.
    let rv = mount_dispatch::dispatch_mount(None, "revealproc", "/mnt/point", &target_d, None, "",
        0, USERNS_CAPS);
    assert_eq!(rv, eno(Errno::Eperm), "no already-visible instance ⇒ EPERM");
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_none(), "a refused mount grafts nothing");
}

#[test]
fn the_same_mount_succeeds_once_an_instance_is_already_visible() {
    let _g = guard();
    register_revealproc();
    unprivileged_ns("reveal-b");
    graft_visible("/proc", MNT_RELATIME);
    let target_d = common::dentry("/mnt/point");

    // The NON-refusal half: `unshare -Urm --mount-proc` must keep working, so a
    // "refuse every userns mount" implementation cannot read as a pass here.
    assert_eq!(mount_dispatch::dispatch_mount(None, "revealproc", "/mnt/point", &target_d, None, "",
        0, USERNS_CAPS), 0);
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_some(), "and it really grafted");
}

#[test]
fn the_initial_user_namespace_is_unaffected() {
    let _g = guard();
    register_revealproc();
    // A namespace owned by the INITIAL user ns, with nothing of the type mounted.
    let init = vfs::mntns::initial();
    let namespace = vfs::mntns::allocate(init.owner_user_namespace()).expect("ns");
    *CUR_NS.lock().unwrap_or_else(|e| e.into_inner()) = Some(namespace);
    common::register("/", Arc::new(RootFs { tag: "reveal-c" })).expect("root mount");
    let target_d = common::dentry("/mnt/point");

    assert_eq!(mount_dispatch::dispatch_mount(None, "revealproc", "/mnt/point", &target_d, None, "",
        0, ROOT_CAPS), 0, "`ns->user_ns == &init_user_ns` ⇒ never too revealing");
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_some());
}

#[test]
fn the_visible_instances_locks_are_forced_onto_and_installed_on_the_new_mount() {
    let _g = guard();
    register_revealproc();
    unprivileged_ns("reveal-d");
    let vis = graft_visible("/proc", MNT_RELATIME | MNT_RDONLY);
    vis.set_internal_flag(MNT_LOCK_READONLY | MNT_LOCK_ATIME);
    let target_d = common::dentry("/mnt/point");

    // A read-WRITE instance would launder away the read-only lock.
    assert_eq!(mount_dispatch::dispatch_mount(None, "revealproc", "/mnt/point", &target_d, None, "",
        0, USERNS_CAPS), eno(Errno::Eperm), "mount -t revealproc (rw) against a locked-ro instance");
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_none(), "nothing grafted");

    // `mount -o ro` reproduces the lock, so it is admitted — and the mount that
    // lands carries the inherited MNT_LOCK_* bits, not just the option bits.
    assert_eq!(mount_dispatch::dispatch_mount(None, "revealproc", "/mnt/point", &target_d, None, "",
        MS_RDONLY, USERNS_CAPS), 0);
    let m = vfs::mount::mount_at_path_exact(&target_d).expect("grafted");
    assert_eq!(m.internal_flags() & (MNT_LOCK_READONLY | MNT_LOCK_ATIME),
        MNT_LOCK_READONLY | MNT_LOCK_ATIME,
        "\"preserve the locked attributes\" survived the dispatch onto the mount");
    // And they bite: the new mount cannot be remounted read-write either.
    assert_eq!(vfs::mount::remount_flags_by_id(m.mnt_id, vfs::mount::MS_RELATIME),
        Err(VfsError::Eperm));
}

#[test]
fn a_locked_child_on_the_visible_instance_re_arms_the_refusal() {
    let _g = guard();
    register_revealproc();
    unprivileged_ns("reveal-e");
    graft_visible("/proc", MNT_RELATIME);
    let target_d = common::dentry("/mnt/point");
    assert_eq!(mount_dispatch::dispatch_mount(None, "revealproc", "/mnt/point", &target_d, None, "",
        0, USERNS_CAPS), 0, "fully visible ⇒ allowed");
    vfs::mount::unregister(&target_d);

    // Now mask /proc/kcore with a locked mount — the container shape. The
    // visible instance stops being FULLY visible, and a fresh instance would
    // uncover the masked path.
    let mask_d = common::dentry("/proc/kcore");
    common::register("/proc/kcore", Arc::new(RootFs { tag: "mask" })).expect("mask mount");
    vfs::mount::mount_at_path_exact(&mask_d).expect("the mask").set_internal_flag(
        vfs::mount::MNT_LOCKED);

    assert_eq!(mount_dispatch::dispatch_mount(None, "revealproc", "/mnt/point", &target_d, None, "",
        0, USERNS_CAPS), eno(Errno::Eperm), "a locked child vetoes the vouch");
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_none());
}
