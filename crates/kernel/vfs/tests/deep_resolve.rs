//! Deep-path resolution regression guard (`docs/16§3`). Exercises the
//! `walk_to_mount → resolve_abs` chain — the owning-mount
//! identification walk used by rename/link/truncate/inotify/xattr/… — for a
//! path of >=3 components resolving (a) wholly inside the ROOT filesystem and
//! (b) across a mount into a WHOLE-PATH (procfs-style) filesystem.
//!
//! Why this guard exists: the prior hosted suite installed only the dentry
//! resolver, leaving `root_dentry()` un-set, so `walk_to_mount` short-circuited
//! to the `root_mount_id` fallback and its per-component DESCENT + mount
//! CROSSING were never driven. This test installs the real boot wiring (root
//! dentry provider + dentry resolver sharing ONE canonical tree) so the walk
//! descends, crosses at `/proc` by dentry identity, and `resolve_abs` completes
//! the deep resolution with no mount-wrapper re-entry. Routing stays
//! dentry/hash identity; any absolute text is resolver input, not a mount-tree
//! string decision.

mod common;

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{Dentry, FileType, InodeOps, InodeRef, KResult, VfsError};

static SERIAL: Mutex<()> = Mutex::new(());

// --- tree-backed inodes (per-component lookup works, like ext4) ------------

/// Per-inode dir state (the old `Dir.kids`), stored in `i_private`.
struct DirData { kids: &'static [(&'static str, u64)] }

/// Tree-backed directory `i_op`: per-component `lookup` reads the child table
/// off `i_private` and materialises the child via `node` (like ext4).
struct DirOps;
impl InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, n: &str) -> KResult<InodeRef> {
        let d = inode.private::<DirData>().ok_or(VfsError::Einval)?;
        for (name, ino) in d.kids {
            if *name == n { return Ok(node(*ino)); }
        }
        Err(VfsError::Enoent)
    }
}

fn dir(ino: u64, kids: &'static [(&'static str, u64)]) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755), Arc::new(DirOps), vfs::default_file_ops())
        .private(Arc::new(DirData { kids })).build()
}
fn reg(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Regular, 0o644), vfs::default_inode_ops(), vfs::default_file_ops()).build()
}

const ROOT_INO: u64 = 2;
const DIR_A: u64 = 10;
const DIR_B: u64 = 11;
const FILE_C: u64 = 0xABC;     // /a/b/c
const PROC_UNDERLAY: u64 = 60; // empty /proc dir on the root fs
const PROC_ROOT: u64 = 70;     // procfs mount root (per-component)
const PROC_PID1: u64 = 71;     // /proc/1
const PROC_STAT: u64 = 0x501;  // /proc/1/stat

/// Materialise an inode by ino — the shared backing the root tree + fs lookups
/// agree on, so identity is stable.
fn node(ino: u64) -> InodeRef {
    match ino {
        ROOT_INO => dir(ROOT_INO, &[("a", DIR_A), ("proc", PROC_UNDERLAY)]),
        DIR_A => dir(DIR_A, &[("b", DIR_B)]),
        DIR_B => dir(DIR_B, &[("c", FILE_C)]),
        FILE_C => reg(FILE_C),
        PROC_UNDERLAY => dir(PROC_UNDERLAY, &[]),
        // procfs mount root resolves per-component: /proc → 1 → stat.
        PROC_ROOT => dir(PROC_ROOT, &[("1", PROC_PID1)]),
        PROC_PID1 => dir(PROC_PID1, &[("stat", PROC_STAT)]),
        other => reg(other),
    }
}

// --- one canonical root dentry, shared by both providers -------------------

static ROOT: OnceLock<Arc<Dentry>> = OnceLock::new();
fn root() -> Arc<Dentry> { ROOT.get_or_init(|| Dentry::new_root(node(ROOT_INO))).clone() }

/// Root-dentry provider (`walk_to_mount`'s start). # fn pointer, no capture.
fn root_provider() -> Option<Arc<Dentry>> { Some(root()) }

/// Resolve an absolute path to its canonical dentry by the SAME walk the
/// real syscall handler does (the namei walk the caller hands the mount
/// engine), so the dentry `register` attaches on is identity-equal to the
/// one `walk_to_mount` later crosses.
fn dentry(p: &str) -> Arc<Dentry> {
    let r = root();
    vfs::path_lookup(r.clone(), r, p, vfs::LookupFlags::default()).ok().map(|(_, d)| d).unwrap()
}

// --- filesystems -----------------------------------------------------------

struct RootFs;
impl FileSystem for RootFs {
    fn name(&self) -> &str { "rootfs" }
    fn root(&self) -> Option<InodeRef> { Some(node(ROOT_INO)) }
}

struct ProcFs;
impl FileSystem for ProcFs {
    fn name(&self) -> &str { "procfs" }
    fn root(&self) -> Option<InodeRef> { Some(node(PROC_ROOT)) }
}

fn register(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>) -> KResult<()> {
    let ty: Arc<dyn vfs::FileSystemType> = vfs::fs::FsType::new(
        fs.name(), fs.magic(), fs.fs_flags(), Box::new(|_, _, _, _, _, _| unreachable!()));
    vfs::mount::register_typed(ty, mp, fs)
}

/// Install the real boot wiring (providers + a `/` and `/proc` mount), once.
fn setup() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(common::current_namespace);
    vfs::set_root_dentry_provider(root_provider);
    static MOUNTED: OnceLock<()> = OnceLock::new();
    MOUNTED.get_or_init(|| {
        register(None, Arc::new(RootFs)).expect("mount root fs");
        register(Some(dentry("/proc")), Arc::new(ProcFs)).expect("mount procfs");
    });
    g
}

// --- the guard -------------------------------------------------------------

#[test]
fn deep_path_into_root_fs_resolves_to_inode() {
    let _g = setup();
    let id = vfs::namei::walk_to_mount("/a/b/c").expect("owning mount");
    let m = vfs::mount::mount_by_id(id).expect("mount by id");
    assert_eq!(m.mount_point_str(), "/", "deep root path is owned by the / mount");
    // The mount's own lookup completes the deep resolution in one pass.
    let i = vfs::resolve_abs("/a/b/c").expect("deep lookup in root fs");
    assert_eq!(i.ino(), FILE_C, "resolved /a/b/c to its inode, not ENOENT");
}

#[test]
fn deep_path_into_mounted_fs_crosses_and_resolves() {
    let _g = setup();
    // walk_to_mount crosses at /proc by DENTRY IDENTITY (the dentry register
    // marked), then per-component lookup (proc_root→1→stat) completes the path
    // — NO whole-path delegate; resolution is `d_lookup → i_op->lookup`.
    let id = vfs::namei::walk_to_mount("/proc/1/stat").expect("owning mount");
    let m = vfs::mount::mount_by_id(id).expect("mount by id");
    assert_eq!(m.mount_point_str(), "/proc", "deep proc path is owned by the /proc mount");
    let i = vfs::resolve_abs("/proc/1/stat").expect("per-component lookup across mount");
    assert_eq!(i.ino(), PROC_STAT, "crossed /proc and resolved /proc/1/stat per-component");
}

#[test]
fn missing_deep_leaf_is_enoent_not_misrouted() {
    let _g = setup();
    // A genuinely-missing deep leaf still routes to the owning (root) mount,
    // whose fs.lookup misses → Enoent (the error stands, no silent success).
    let id = vfs::namei::walk_to_mount("/a/b/nope").expect("owning mount of missing leaf");
    let m = vfs::mount::mount_by_id(id).expect("mount by id");
    assert_eq!(m.mount_point_str(), "/", "missing leaf owned by deepest existing parent's mount");
    assert!(vfs::resolve_abs("/a/b/nope").is_err(), "missing deep leaf is ENOENT");
}
