// B1413: `mount(2)` with `fstype="cgroup"` (legacy v1) used to hit
// `"devpts" | "cgroup" => 0` in `fsmount_common/mount_ops.rs` — success with
// NOTHING mounted. Drives the extracted `mount_dispatch::dispatch_mount`
// (ungated pure fn, `src/fsmount_common/mount_dispatch.rs`) directly against
// the real `vfs` mount engine, hosted — no boot required.
//
// Proves:
//  - `fstype="cgroup"` returns the honest ENODEV and grafts nothing, for two
//    different controller-option strings (the "different hierarchy" case) —
//    both fail identically; no controller is EVER attached, so there is no
//    partial state to observe (the honest analogue of Linux's real EBUSY,
//    which only applies once *some* hierarchy can be attached at all).
//  - a REAL registered fstype (modelled on `devpts`, which the same match arm
//    used to shadow as dead code) still succeeds AND grafts real, reachable
//    content — the mountpoint is provably non-empty afterward, not just
//    "attached to nothing."
use std::sync::{Arc, Mutex, MutexGuard};

extern crate alloc;

use syscall::errno::Errno;
use vfs::fs::{FileSystem, FsFlags, FsType};
use mount_dispatch::MountCaps;
use vfs::inode::Inode;
use vfs::{Dentry, FileType, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

#[path = "../../vfs/tests/common/mod.rs"]
mod common;

// `mount_dispatch.rs` calls `crate::namei_common::errno_from_vfs` — reuse the
// SAME canonical VfsError->errno table (`src/namei_common/errno.rs`) via
// `#[path]`, not a reimplementation, so the honest-errno path is proven
// against the real mapping.
#[path = "../src/namei_common/errno.rs"]
mod namei_common;

#[path = "../src/fsmount_common/mount_dispatch.rs"]
mod mount_dispatch;

static SERIAL: Mutex<()> = Mutex::new(());
static CUR_NS: Mutex<Option<vfs::mntns::MntNamespaceRef>> = Mutex::new(None);

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// A caller privileged in the initial user namespace — `capable(CAP_SYS_ADMIN)`
/// and `may_mount()` both true, so `mount_capable` never refuses.
const ROOT_CAPS: MountCaps = MountCaps { init_user_ns: true, mnt_user_ns: true };
/// An unprivileged user-namespace holder: it holds a full capability set INSIDE
/// its own userns (so `may_mount()` passes) but not in the initial one.
const USERNS_CAPS: MountCaps = MountCaps { init_user_ns: false, mnt_user_ns: true };

fn cur_ns() -> vfs::mntns::MntNamespaceRef {
    CUR_NS.lock().unwrap_or_else(|e| e.into_inner()).as_ref().expect("current namespace owner").clone()
}

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    common::install();
    vfs::mount::set_current_ns_provider(cur_ns);
    g
}

fn new_ns() {
    let init = vfs::mntns::initial();
    let namespace = vfs::mntns::allocate(init.owner_user_namespace()).expect("allocate mount namespace");
    *CUR_NS.lock().unwrap_or_else(|e| e.into_inner()) = Some(namespace);
}

struct RootDirOps;
impl InodeOps for RootDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Ok(plain_dir(0xC670_0100)) }
}
fn plain_dir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755), std::sync::Arc::new(RootDirOps), vfs::default_file_ops()).build()
}
struct RootFs { tag: &'static str }
impl FileSystem for RootFs {
    fn name(&self) -> &str { self.tag }
    fn root(&self) -> Option<InodeRef> { Some(plain_dir(1)) }
}

fn mount_tree(tag: &'static str) -> Arc<Dentry> {
    new_ns();
    common::register("/", Arc::new(RootFs { tag })).expect("root mount");
    common::dentry("/mnt/point")
}

// --- fake real fstype (models `devpts`: registered via `vfs::fs::register_fs`,
// hence reachable through `dispatch_mount`'s `Some(ty)` arm, same as the real
// devpts crate is via `registry.rs`). Its root has ONE named child, so a
// successful graft is provably non-empty (readdir-shaped: known name resolves,
// unknown name ENOENT), not just an attach-to-nothing.
const FAKE_ROOT_INO: u64 = 0xFEED_0001;
const FAKE_CHILD_INO: u64 = 0xFEED_0002;
struct FakeDevptsRootOps;
impl InodeOps for FakeDevptsRootOps {
    fn lookup(&self, _inode: &Inode, n: &str) -> KResult<InodeRef> {
        if n == "0" { Ok(fake_child()) } else { Err(VfsError::Enoent) }
    }
}
fn fake_child() -> InodeRef {
    InodeBuilder::new(FAKE_CHILD_INO, vfs::mk_mode(FileType::CharDev, 0o620), vfs::default_inode_ops(), vfs::default_file_ops()).build()
}
fn fake_devpts_root() -> InodeRef {
    InodeBuilder::new(FAKE_ROOT_INO, vfs::mk_mode(FileType::Directory, 0o755), std::sync::Arc::new(FakeDevptsRootOps), vfs::default_file_ops()).build()
}
struct FakeDevptsFs;
impl FileSystem for FakeDevptsFs {
    fn name(&self) -> &str { "devpts" }
    fn root(&self) -> Option<InodeRef> { Some(fake_devpts_root()) }
}
fn register_fake_devpts() {
    let _ = vfs::fs::register_fs(FsType::new("devpts", 0, FsFlags::empty(), Box::new(|ty, _s, _t, _d| {
        let fs: std::sync::Arc<dyn FileSystem> = std::sync::Arc::new(FakeDevptsFs);
        vfs::fs::superblock_from_filesystem(ty, fs, None, "devpts".into())
    })));
}

#[test]
fn cgroup_v1_mount_is_honest_enodev_not_a_silent_success() {
    let _g = guard();
    let target_d = mount_tree("cgv1-a");

    // First "hierarchy": cpu+cpuset controllers.
    let rv1 = mount_dispatch::dispatch_mount(None, "cgroup", "/mnt/point", &target_d, None, "cpu,cpuset", 0, ROOT_CAPS);
    assert_eq!(rv1, eno(Errno::Enodev), "cgroup v1 mount must fail honestly, never silently succeed");
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_none(), "nothing may be grafted on honest failure");

    // Second "hierarchy" at the SAME target: memory+pids controllers. Real
    // Linux would EBUSY here only because the FIRST attach could have
    // succeeded; since no v1 hierarchy is ever attachable in this kernel, the
    // honest behaviour is BOTH attempts failing identically — never a
    // silent flip to success on retry, never partial/inconsistent state.
    let rv2 = mount_dispatch::dispatch_mount(None, "cgroup", "/mnt/point", &target_d, None, "memory,pids", 0, ROOT_CAPS);
    assert_eq!(rv2, eno(Errno::Enodev), "a second cgroup v1 attempt must fail the same honest way");
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_none(), "still nothing grafted after the second attempt");
}

#[test]
fn cgroup_v1_named_hierarchy_option_also_fails_honestly() {
    let _g = guard();
    let target_d = mount_tree("cgv1-b");

    // `-o none,name=systemd` (systemd's hybrid-mode process-tracking
    // hierarchy) — still unimplemented, still honest ENODEV, not `0`.
    let rv = mount_dispatch::dispatch_mount(None, "cgroup", "/mnt/point", &target_d, None, "none,name=systemd", 0, ROOT_CAPS);
    assert_eq!(rv, eno(Errno::Enodev));
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_none());
}

#[test]
fn devpts_style_fstype_still_mounts_and_target_becomes_non_empty() {
    let _g = guard();
    register_fake_devpts();
    let target_d = mount_tree("devpts-a");

    let rv = mount_dispatch::dispatch_mount(None, "devpts", "/mnt/point", &target_d, None, "", 0, ROOT_CAPS);
    assert_eq!(rv, 0, "a genuinely registered fstype must still mount successfully");

    let m = vfs::mount::mount_at_path_exact(&target_d).expect("devpts-style mount grafted");
    let root_inode = m.mnt_root().and_then(|d| d.inode()).expect("mounted root has an inode");
    assert_eq!(root_inode.ino(), FAKE_ROOT_INO, "grafted root is the real fs root, not a default/placeholder");

    // Non-empty: a name the fs actually serves resolves; an unknown name
    // still ENOENTs (proves this is real dispatch, not "anything resolves").
    let known = root_inode.lookup("0").expect("known child resolves through the grafted fs");
    assert_eq!(known.ino(), FAKE_CHILD_INO);
    assert!(matches!(root_inode.lookup("nope"), Err(VfsError::Enoent)));
}

// B1478: the `mount(2)` MS_* option word must SURVIVE the dispatch and land on
// the mount `dispatch_mount` grafts. Linux `path_mount` derives `mnt_flags` and
// `do_new_mount` -> `do_add_mount` stamps it (`newmnt->mnt.mnt_flags =
// mnt_flags`); this shim passed a hard-coded 0 to `attach_sb_with_flags_at`, so
// `mount -t devpts -o ro,nosuid,nodev,noexec` produced an unrestricted mount.
#[test]
fn mount_options_reach_the_grafted_mount() {
    let _g = guard();
    register_fake_devpts();
    let target_d = mount_tree("devpts-flags");

    let ms = vfs::mount::MS_RDONLY | vfs::mount::MS_NOSUID | vfs::mount::MS_NODEV
        | vfs::mount::MS_NOEXEC | vfs::mount::MS_NOATIME;
    let rv = mount_dispatch::dispatch_mount(None, "devpts", "/mnt/point", &target_d, None, "", ms, ROOT_CAPS);
    assert_eq!(rv, 0, "the mount itself still succeeds");

    let m = vfs::mount::mount_at_path_exact(&target_d).expect("grafted");
    // FAILS-BEFORE: every one of these read false — the request was dropped.
    assert!(m.is_readonly(), "MS_RDONLY survived the dispatch");
    assert!(m.is_nosuid(),   "MS_NOSUID survived the dispatch");
    assert!(m.is_nodev(),    "MS_NODEV survived the dispatch");
    assert!(m.is_noexec(),   "MS_NOEXEC survived the dispatch");
    assert_eq!(m.atime_policy(), vfs::mount::AtimePolicy::Noatime);

    // And the restriction actually REFUSES something.
    assert_eq!(vfs::mount::mnt_want_write(&m), Err(VfsError::Erofs),
        "the read-only mount refuses a writer");
    assert!(!m.may_suid(), "the nosuid mount suppresses setuid + file caps at execve");
}

// A request naming NO option still gets Linux's relatime default, not an empty
// flag word (`path_mount`: "Default to relatime unless overriden").
#[test]
fn a_flagless_mount_still_gets_the_relatime_default() {
    let _g = guard();
    register_fake_devpts();
    let target_d = mount_tree("devpts-default");
    assert_eq!(mount_dispatch::dispatch_mount(None, "devpts", "/mnt/point", &target_d, None, "", 0, ROOT_CAPS), 0);
    let m = vfs::mount::mount_at_path_exact(&target_d).expect("grafted");
    assert!(m.is_relatime(), "MNT_RELATIME is stamped by default");
    assert!(!m.is_readonly() && !m.is_nosuid() && !m.is_nodev() && !m.is_noexec());
}

// B1478 (Linux `fs/super.c` `mount_capable`): `FS_USERNS_MOUNT` existed in
// `vfs::fs::FsFlags` and was set on procfs/sysfs, but NOTHING read it. An
// unprivileged user-namespace holder passes `may_mount()` by construction (it
// has CAP_SYS_ADMIN inside its own userns), so it could mount ext4, tmpfs,
// devtmpfs, devpts — every filesystem Linux reserves for the initial user ns.
#[test]
fn a_userns_caller_cannot_mount_a_non_userns_filesystem() {
    let _g = guard();
    register_fake_devpts();          // registered WITHOUT FS_USERNS_MOUNT
    let target_d = mount_tree("devpts-userns");

    let rv = mount_dispatch::dispatch_mount(None, "devpts", "/mnt/point", &target_d, None, "", 0,
        USERNS_CAPS);
    assert_eq!(rv, eno(Errno::Eperm),
        "a filesystem without FS_USERNS_MOUNT needs privilege in the INITIAL user ns");
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_none(),
        "a refused mount grafts nothing");

    // The same caller, same target, same filesystem — but privileged in the
    // initial user namespace: allowed.
    assert_eq!(mount_dispatch::dispatch_mount(None, "devpts", "/mnt/point", &target_d, None, "", 0,
        ROOT_CAPS), 0);
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_some());
}

// The mirror case: a filesystem that DOES carry FS_USERNS_MOUNT (procfs/sysfs in
// the real registry) is mountable by the userns caller.
#[test]
fn a_userns_caller_may_mount_a_userns_filesystem() {
    let _g = guard();
    let _ = vfs::fs::register_fs(FsType::new("usernsfs", 0, FsFlags::FS_USERNS_MOUNT,
        Box::new(|ty, _s, _t, _d| {
            let fs: std::sync::Arc<dyn FileSystem> = std::sync::Arc::new(FakeDevptsFs);
            vfs::fs::superblock_from_filesystem(ty, fs, None, "usernsfs".into())
        })));
    let target_d = mount_tree("usernsfs-a");
    assert_eq!(mount_dispatch::dispatch_mount(None, "usernsfs", "/mnt/point", &target_d, None, "", 0,
        USERNS_CAPS), 0, "FS_USERNS_MOUNT settles for privilege in the mount ns owner");
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_some());
}

// The decision table itself, exhaustively (Linux `mount_capable`).
#[test]
fn mount_capable_table() {
    let cases = [
        //  fs_flags                    init  mntns  allowed
        (FsFlags::empty(),              false, true,  false),
        (FsFlags::empty(),              true,  false, true ),
        (FsFlags::FS_USERNS_MOUNT,      false, true,  true ),
        (FsFlags::FS_USERNS_MOUNT,      false, false, false),
        (FsFlags::FS_USERNS_MOUNT,      true,  false, false),
    ];
    for (fl, init, mntns, want) in cases {
        let caps = MountCaps { init_user_ns: init, mnt_user_ns: mntns };
        assert_eq!(mount_dispatch::mount_capable(fl, caps), want, "{fl:?} init={init} mntns={mntns}");
    }
}
