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
    let rv1 = mount_dispatch::dispatch_mount(None, "cgroup", "/mnt/point", &target_d, None, "cpu,cpuset");
    assert_eq!(rv1, eno(Errno::Enodev), "cgroup v1 mount must fail honestly, never silently succeed");
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_none(), "nothing may be grafted on honest failure");

    // Second "hierarchy" at the SAME target: memory+pids controllers. Real
    // Linux would EBUSY here only because the FIRST attach could have
    // succeeded; since no v1 hierarchy is ever attachable in this kernel, the
    // honest behaviour is BOTH attempts failing identically — never a
    // silent flip to success on retry, never partial/inconsistent state.
    let rv2 = mount_dispatch::dispatch_mount(None, "cgroup", "/mnt/point", &target_d, None, "memory,pids");
    assert_eq!(rv2, eno(Errno::Enodev), "a second cgroup v1 attempt must fail the same honest way");
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_none(), "still nothing grafted after the second attempt");
}

#[test]
fn cgroup_v1_named_hierarchy_option_also_fails_honestly() {
    let _g = guard();
    let target_d = mount_tree("cgv1-b");

    // `-o none,name=systemd` (systemd's hybrid-mode process-tracking
    // hierarchy) — still unimplemented, still honest ENODEV, not `0`.
    let rv = mount_dispatch::dispatch_mount(None, "cgroup", "/mnt/point", &target_d, None, "none,name=systemd");
    assert_eq!(rv, eno(Errno::Enodev));
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_none());
}

#[test]
fn devpts_style_fstype_still_mounts_and_target_becomes_non_empty() {
    let _g = guard();
    register_fake_devpts();
    let target_d = mount_tree("devpts-a");

    let rv = mount_dispatch::dispatch_mount(None, "devpts", "/mnt/point", &target_d, None, "");
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
