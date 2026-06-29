//! [D24] Stage-0: a fresh-filesystem mount OVER an existing mount whose target
//! resolves to a SINGLETON `s_root` (parentless, empty-name — like procfs/sysfs)
//! must GRAFT as a proper overmount, NOT self-root and HIJACK the ns root.
//!
//! Root cause (capture-proven at real boot): the self-root filter at `attach` /
//! `graft_realized` used the STRUCTURAL `is_global_root(d)` (`parent().is_none()
//! && name().is_empty()`), which matches EVERY superblock root dentry. A second
//! `mount(proc,/proc)` over an existing proc mount resolves its target THROUGH
//! the underlay to the procfs `s_root` (parentless, empty-name); the structural
//! filter wrongly nulled that mountpoint → the new mount took the self-root
//! branch (`parent=self`, `mp=NULL`) AND `ns_set_root` HIJACKED the ns root, so
//! `__lookup_mnt(parent,/proc)` missed (the 9885 boot GAP). The fix swaps that
//! filter to `is_ns_root_dentry` (IDENTITY vs the true `global_root()`), so only
//! the genuine ns-root dentry self-roots; a procfs `s_root` grafts.
//!
//! This pins: (1) the overmount grafts under the underlay (`__lookup_mnt(procA,
//! procfs_root) == procB`), (2) the underlay's own dir-level mount is NOT
//! clobbered (`__lookup_mnt(rootfs_root, /proc_dir) == procA` still), (3) NO ns
//! root hijack (`ns_root_id` unchanged across the procB mount). Process-global
//! table → SERIAL-guarded.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{default_file_ops, mk_mode, FileType, InodeBuilder, InodeOps, InodeRef,
          KResult, LookupFlags};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0);
    common::install();
    g
}

/// Directory-factory ops: any name resolves to a fresh child directory — the
/// rootfs side, so `/proc` materialises as a normal (parented, named) dir
/// dentry that procA grafts onto.
struct FacDirOps;
impl InodeOps for FacDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Ok(facdir(0x9000)) }
}
fn facdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(FacDirOps), default_file_ops()).build()
}

/// The rootfs backing the ns-root mount; its directory-factory root resolves
/// `/proc` to a normal (parented, named) dentry.
struct RootFs;
impl FileSystem for RootFs {
    fn name(&self) -> &str { "ext4" }
    fn root(&self) -> Option<InodeRef> { Some(facdir(2)) }
}

/// Singleton-root pseudo-fs (procfs/sysfs shape): its `root()` inode becomes the
/// SB's `s_root` via `d_make_root` — a parentless, empty-name dentry that the
/// pre-fix structural filter wrongly treated as the global root.
struct PseudoFs { ino: u64 }
impl FileSystem for PseudoFs {
    fn name(&self) -> &str { "proc" }
    fn root(&self) -> Option<InodeRef> { Some(facdir(self.ino)) }
}

#[test]
fn fresh_fs_over_existing_mount_grafts_no_hijack() {
    let _g = guard();
    let ns = 0u64;

    // The ns-root mount (rootfs); `root_mount_id(ns)` becomes Some after this.
    common::register("/", Arc::new(RootFs)).expect("root mount");

    // Resolve the rootfs `/proc` directory dentry (parented, name="proc").
    let root = common::dentry("/");
    let (_, proc_dir) = vfs::path_lookup(root.clone(), root.clone(), "/proc", LookupFlags::default())
        .expect("/proc dir");

    let rootfs_root_id = vfs::mount::root_mount_id(ns).expect("ns root mount");

    // procA: the underlay proc mount, grafted on the /proc DIRECTORY dentry.
    vfs::mount::register(Some(proc_dir.clone()), Arc::new(PseudoFs { ino: 0xA001 }))
        .expect("mount procA at /proc");

    // The dir-level mount is recorded under (rootfs_root, /proc_dir).
    let procA = vfs::mount::__lookup_mnt(rootfs_root_id, &proc_dir)
        .expect("procA at (rootfs_root, /proc_dir)");
    let procA_id = procA.mnt_id;
    assert_ne!(procA_id, rootfs_root_id, "procA is a distinct mount, not the ns root");

    // Resolve /proc AGAIN: now it follows the mount DOWN to procA's singleton
    // s_root (parentless, empty-name) — the dentry the pre-fix filter nulled.
    let (_, procfs_root) = vfs::path_lookup(root.clone(), root.clone(), "/proc", LookupFlags::default())
        .expect("/proc -> procA s_root");
    assert!(procfs_root.parent().is_none() && procfs_root.name().is_empty(),
        "resolved target is the procfs SINGLETON s_root (structural global-root shape)");

    // Snapshot the ns root id BEFORE the overmount — the hijack would change it.
    let ns_root_before = vfs::mount::root_mount_id(ns);

    // procB: a FRESH-fs mount OVER the existing procA mount. Its target resolves
    // to procA's s_root; pre-fix this self-rooted + hijacked the ns root.
    vfs::mount::register(Some(procfs_root.clone()), Arc::new(PseudoFs { ino: 0xB001 }))
        .expect("mount procB over /proc");

    // (1) procB grafted as a proper overmount UNDER procA: keyed
    // (procA_id, procfs_root), NOT self-rooted.
    let procB = vfs::mount::__lookup_mnt(procA_id, &procfs_root)
        .expect("procB grafted at (procA, procfs_root) — NOT self-rooted");
    let procB_id = procB.mnt_id;
    assert_ne!(procB_id, procA_id, "procB is a distinct mount");
    assert_ne!(procB_id, rootfs_root_id, "procB did not hijack the ns root id");

    // (2) the original dir-level mount is NOT clobbered.
    let still_procA = vfs::mount::__lookup_mnt(rootfs_root_id, &proc_dir)
        .expect("(rootfs_root, /proc_dir) still maps to a mount");
    assert_eq!(still_procA.mnt_id, procA_id, "procA entry intact after the overmount");

    // (3) NO ns-root hijack: the ns root mount id is unchanged.
    assert_eq!(vfs::mount::root_mount_id(ns), ns_root_before,
        "fresh-fs overmount must NOT call ns_set_root (no root hijack)");
    assert_eq!(vfs::mount::root_mount_id(ns), Some(rootfs_root_id),
        "ns root still the rootfs mount");

    // Cleanup so a sibling test starts clean.
    let _ = vfs::mount::unregister(&procfs_root);
    let _ = vfs::mount::unregister(&proc_dir);
}
