//! D24 Stage 1a — recursive `open_tree(OPEN_TREE_CLONE[, AT_RECURSIVE])` +
//! HASH-ONLY `move_mount` commit. Drives the real global mount engine through
//! the new public wiring ([`vfs::mount::clone_mount_tree`] /
//! [`commit_tree_hashonly`] / [`release_clone_tree`]) over a DEV-BACKED rootfs
//! fixture + api-mounts, no QEMU.
//!
//! Pins the whole point of Stage 1a:
//!   * a cloned `/proc` is reachable in the STRICT hash under the NEW root id
//!     (`__lookup_mnt(clone_root, /proc) == clone`), AND
//!   * the ORIGINAL `(ns_root, /proc)` hash entry is NOT clobbered, AND
//!   * the legacy `dentry.mounted_mounts` walk oracle is untouched (no
//!     `wire_crossing`), AND
//!   * an uncommitted clone tree (`release_clone_tree`) balances `s_active`.
//!
//! The dev-backed rootfs is what exposes the global `/proc` dentry to the clone:
//! the clone root SHARES the rootfs SB via `sget`, so its `mnt_root` is the
//! GLOBAL `s_root` and `/proc` under it is the SAME mountpoint dentry as the
//! original — confirming the live-gnome `dev_id() == Some` premise.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::{FileSystem, FsFlags};
use vfs::inode::{Inode, InodeBuilder};
use vfs::{default_file_ops, mk_mode, Cred, Dentry, FileType, InodeOps, InodeRef, KResult, LookupFlags, VfsError};

static SERIAL: Mutex<()> = Mutex::new(());

// Per-test ns/dev counters (global mount state persists across tests in one
// binary, so each test uses a FRESH ns + backing dev to avoid collision).
static NEXT_DEV: AtomicU64 = AtomicU64::new(0xD24_1000);

// The current test's rootfs s_root, installed as the root-dentry provider so the
// engine's `descend`/`global_root` resolve through the SAME dcache `child()`
// uses — exactly the boot wiring where the ns-root mount's s_root IS the walk
// root. Serialized by `SERIAL`, so the single global provider always names the
// running test's s_root.
static CUR_SROOT: Mutex<Option<Arc<Dentry>>> = Mutex::new(None);
fn root_provider() -> Option<Arc<Dentry>> { CUR_SROOT.lock().unwrap_or_else(|e| e.into_inner()).clone() }

static NEXT_INO: AtomicU64 = AtomicU64::new(0x1000);

// Factory-dir backend: every name resolves to a fresh child directory, so any
// mountpoint position (`/proc`, `/staging`) materialises through the dcache.
struct FacOps;
impl InodeOps for FacOps {
    fn lookup(&self, _i: &Inode, _n: &str) -> KResult<InodeRef> {
        Ok(facdir(NEXT_INO.fetch_add(1, Ordering::Relaxed)))
    }
}
fn facdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(FacOps), default_file_ops()).build()
}

/// Dev-backed rootfs (`dev_id() == Some` → SB shared via `sget`).
struct RootFs { dev: u64, root_ino: u64 }
impl FileSystem for RootFs {
    fn name(&self) -> &str { "rootfs_test" }
    fn magic(&self) -> u64 { 0xEF53 }
    fn dev_id(&self) -> Option<u64> { Some(self.dev) }
    fn root(&self) -> Option<InodeRef> { Some(facdir(self.root_ino)) }
    fn fs_flags(&self) -> FsFlags { FsFlags::FS_ALLOW_IDMAP }
}

/// Anon api-fs (`dev_id() == None` → fresh per-mount SB), e.g. procfs/sysfs.
struct ApiFs { root_ino: u64 }
impl FileSystem for ApiFs {
    fn name(&self) -> &str { "apifs_test" }
    fn root(&self) -> Option<InodeRef> { Some(facdir(self.root_ino)) }
}

fn register(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>) -> KResult<()> {
    let ty: Arc<dyn vfs::FileSystemType> = vfs::fs::FsType::new(
        fs.name(), fs.magic(), fs.fs_flags(), Box::new(|_, _, _, _| unreachable!()));
    vfs::mount::register_typed(ty, mp, fs)
}

/// Resolve `name` under `parent` through the shared dcache (d_lookup → lookup →
/// d_add) — the per-component walk the engine's `descend` also uses.
fn child(parent: &Arc<Dentry>, name: &str) -> Arc<Dentry> {
    match vfs::d_lookup(parent, name) {
        Some(d) if !d.is_negative() => d,
        _ => {
            let ci = parent.inode().unwrap().lookup(name).unwrap();
            vfs::d_add(parent, name, ci)
        }
    }
}

/// Build the dev-backed rootfs + a `/proc` api-mount, install the provider, and
/// return (ns, root_mnt_id, proc_mnt_id, s_root, proc_dentry).
fn setup() -> (u64, u64, u64, u64, Arc<Dentry>, Arc<Dentry>) {
    let init = vfs::mntns::initial();
    let namespace = vfs::mntns::allocate(init.owner_user_namespace()).unwrap();
    let ns = namespace.id();
    *CUR_NS.lock().unwrap_or_else(|e| e.into_inner()) = Some(namespace);
    vfs::mount::set_current_ns_provider(current_namespace);
    *CUR_SROOT.lock().unwrap_or_else(|e| e.into_inner()) = None;
    // ns-root mount over the dev-backed rootfs.
    let dev = NEXT_DEV.fetch_add(1, Ordering::Relaxed);
    register(None, Arc::new(RootFs { dev, root_ino: NEXT_INO.fetch_add(1, Ordering::Relaxed) }))
        .expect("root mount");
    let root_id = vfs::mount::root_mount_id(ns).expect("root id");
    let s_root = vfs::mount::mount_by_id(root_id).unwrap().sb().s_root().expect("rootfs s_root");
    // Install the s_root as the global root-dentry provider (boot wiring).
    *CUR_SROOT.lock().unwrap_or_else(|e| e.into_inner()) = Some(s_root.clone());
    vfs::set_root_dentry_provider(root_provider);
    // /proc api-mount (anon procfs) on the /proc dentry under s_root.
    let proc_d = child(&s_root, "proc");
    register(Some(proc_d.clone()), Arc::new(ApiFs { root_ino: NEXT_INO.fetch_add(1, Ordering::Relaxed) }))
        .expect("proc mount");
    let proc_id = vfs::mount::__lookup_mnt(root_id, &proc_d).expect("proc in hash").mnt_id;
    (ns, root_id, proc_id, dev, s_root, proc_d)
}

static CUR_NS: Mutex<Option<vfs::mntns::MntNamespaceRef>> = Mutex::new(None);

fn current_namespace() -> vfs::mntns::MntNamespaceRef {
    CUR_NS.lock().unwrap_or_else(|e| e.into_inner()).as_ref().cloned()
        .unwrap_or_else(vfs::mntns::initial)
}

fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

// The whole point of Stage 1a: a recursive open_tree clone, committed hash-only,
// makes (clone_root, /proc) resolvable WITHOUT clobbering the original
// (ns_root, /proc) — proving the new strict-hash entry coexists.
#[test]
fn recursive_clone_hashonly_no_clobber() {
    let _g = guard();
    let (_ns, root_id, proc_id, dev, _s_root, proc_d) = setup();

    // Premise: rootfs is dev-backed (the global-dentry-exposure precondition).
    assert_eq!(vfs::mount::mount_by_id(root_id).unwrap().sb().s_dev, dev,
        "rootfs is dev-backed (live-gnome premise: clone shares the SB → global /proc dentry)");
    // Baseline: original (ns_root, /proc) resolves to the original proc mount.
    assert_eq!(vfs::mount::__lookup_mnt(root_id, &proc_d).map(|m| m.mnt_id), Some(proc_id),
        "baseline: original /proc in the strict hash");

    // open_tree(OPEN_TREE_CLONE | AT_RECURSIVE): clone the whole subtree.
    let nodes = vfs::mount::clone_mount_tree(&vfs::mount::mount_by_id(root_id).unwrap(), true);
    assert!(nodes.len() >= 2, "root clone + proc clone replicated (got {})", nodes.len());
    let clone_root_id = nodes.iter().find(|n| n.rel.is_empty()).expect("root clone").m.mnt_id;
    let proc_clone_id = nodes.iter().find(|n| n.rel == "/proc").expect("proc clone").m.mnt_id;
    // The clone root SHARES the rootfs SB (sget) → its mnt_root is the GLOBAL s_root.
    let clone_root_mnt = nodes.iter().find(|n| n.rel.is_empty()).unwrap().m.clone();
    assert!(Arc::ptr_eq(clone_root_mnt.sb(), vfs::mount::mount_by_id(root_id).unwrap().sb()),
        "dev-backed clone root SHARES the rootfs SuperBlock (global s_root exposure)");

    // move_mount: commit hash-only under a staging dentry.
    let staging = child(&_s_root, "staging");
    let n = vfs::mount::commit_tree_hashonly(nodes, &staging);
    assert!(n >= 2, "both root + proc clones committed (got {})", n);

    // NEW: (clone_root, /proc) is now resolvable in the strict hash.
    assert_eq!(vfs::mount::__lookup_mnt(clone_root_id, &proc_d).map(|m| m.mnt_id), Some(proc_clone_id),
        "__lookup_mnt(clone_root, /proc) resolves to the CLONE (the D24 fix)");
    // NOT CLOBBERED: original (ns_root, /proc) still resolves to the original.
    assert_eq!(vfs::mount::__lookup_mnt(root_id, &proc_d).map(|m| m.mnt_id), Some(proc_id),
        "__lookup_mnt(ns_root, /proc) STILL the original (no hash clobber)");
}

// Leak balance: an open_tree clone tree released without a move_mount (fd closed)
// balances the shared SB active count (release_clone_tree).
#[test]
fn uncommitted_clone_tree_balances_s_active() {
    let _g = guard();
    let (_ns, root_id, _proc_id, _dev, _s_root, _proc_d) = setup();
    let root_mnt = vfs::mount::mount_by_id(root_id).unwrap();
    let before = root_mnt.sb().s_active();

    let nodes = vfs::mount::clone_mount_tree(&root_mnt, true);
    assert!(root_mnt.sb().s_active() > before, "clone root shares the SB → s_active bumped");
    vfs::mount::release_clone_tree(&nodes);
    assert_eq!(root_mnt.sb().s_active(), before,
        "release_clone_tree drops the clones' active refs → s_active balanced");
}

#[test]
fn empty_path_clone_uses_dirfd_mount() {
    let _g = guard();
    let (_ns, root_id, proc_id, _dev, s_root, _proc_d) = setup();

    let proc_vp = vfs::path_lookup_at_root_cred(
        s_root.clone(), root_id, s_root.clone(), root_id, "/proc",
        LookupFlags::default(), Cred::root(),
    ).expect("walk /proc through mounted procfs");
    assert_eq!(proc_vp.mnt_id, proc_id, "/proc walk crosses into the proc mount");

    let empty_vp = vfs::path_lookup_at_root_cred(
        proc_vp.dentry.clone(), proc_vp.mnt_id, s_root.clone(), root_id, "",
        LookupFlags { empty: true, ..Default::default() }, Cred::root(),
    ).expect("open_tree(dirfd, \"\", AT_EMPTY_PATH) resolves the dirfd path");
    assert_eq!(empty_vp.mnt_id, proc_id,
        "AT_EMPTY_PATH must operate on the dirfd mount, not return ENOENT or the namespace root");

    let nodes = vfs::mount::clone_mount_tree(&vfs::mount::mount_by_id(empty_vp.mnt_id).unwrap(), true);
    assert_eq!(nodes.iter().filter(|n| n.rel.is_empty()).count(), 1,
        "open_tree empty-path clone has exactly one clone root");
    assert_eq!(nodes.iter().find(|n| n.rel.is_empty()).unwrap().m.sb().s_type.name(), "apifs_test",
        "empty-path clone source is the fd's proc/api mount, not the rootfs");
    vfs::mount::release_clone_tree(&nodes);
}

#[test]
fn detached_clone_commit_under_bind_stage_uses_walked_parent_mount() {
    let _g = guard();
    let (_ns, root_id, _proc_id, _dev, s_root, _proc_d) = setup();
    let dev_d = child(&s_root, "dev");
    register(Some(dev_d.clone()), Arc::new(ApiFs { root_ino: NEXT_INO.fetch_add(1, Ordering::Relaxed) }))
        .expect("dev mount");
    let dev_id = vfs::mount::__lookup_mnt(root_id, &dev_d).expect("original dev").mnt_id;

    let stage = child(&s_root, "stage");
    let root_nodes = vfs::mount::clone_mount_tree(&vfs::mount::mount_by_id(root_id).unwrap(), true);
    let n = vfs::mount::commit_tree_hashonly_at(root_nodes, &stage, root_id);
    assert!(n >= 2, "stage receives root clone and submount clones");
    let stage_id = vfs::mount::__lookup_mnt(root_id, &stage).expect("stage root clone").mnt_id;

    // The staged /dev slot is the same dentry as the original /dev slot because
    // the cloned root shares the dev-backed rootfs s_root. A detached mount
    // committed here must therefore use the walked parent mount id (stage_id);
    // deriving by dentry ancestry alone picks root_id.
    let dev_nodes = vfs::mount::clone_mount_tree(&vfs::mount::mount_by_id(dev_id).unwrap(), true);
    let n = vfs::mount::commit_tree_hashonly_at(dev_nodes, &dev_d, stage_id);
    assert_eq!(n, 1, "root-only /dev detached clone committed");
    let staged_dev = vfs::mount::__lookup_mnt(stage_id, &dev_d)
        .expect("detached /dev clone must be attached under staged root");
    assert_ne!(staged_dev.mnt_id, dev_id, "staged /dev clone is distinct from original /dev");
    assert_eq!(staged_dev.parent_id.load(Ordering::Acquire), stage_id,
        "staged /dev clone parent must be the walked stage root, not original root");
    assert_eq!(vfs::mount::__lookup_mnt(root_id, &dev_d).map(|m| m.mnt_id), Some(dev_id),
        "original /dev crossing remains intact");
}

#[test]
fn idmap_recursive_prepare_is_atomic_across_mixed_filesystems() {
    let _g = guard();
    let (_ns, root_id, _proc_id, _dev, _s_root, _proc_d) = setup();
    let source = vfs::mount::mount_by_id(root_id).unwrap();
    let tree = vfs::mount::clone_mount_tree(&source, true);
    let root = tree.iter().find(|n| n.rel.is_empty()).expect("root clone").m.clone();
    let proc = tree.iter().find(|n| n.rel == "/proc").expect("proc clone").m.clone();
    let map = Arc::new(vfs::idmap::Idmap::uniform(100_000, 0, 65_536));

    assert_eq!(
        vfs::mount::mnt_setattr_detached_tree(
            &tree, vfs::mount::MNT_RDONLY, 0, Some(map), true, None, true,
        ),
        Err(VfsError::Einval),
        "recursive prepare must reject the procfs-like child without partial commit",
    );
    assert!(!root.is_readonly(), "root options stay unchanged after failed prepare");
    assert!(root.idmap().is_identity(), "root idmap stays unchanged after failed prepare");
    assert!(!proc.is_readonly(), "child options stay unchanged after failed prepare");
    assert!(proc.idmap().is_identity(), "child idmap stays unchanged after failed prepare");
    assert!(source.idmap().is_identity(), "detached transaction never mutates its source");
    vfs::mount::release_clone_tree(&tree);
}

#[test]
fn idmap_nonrecursive_changes_only_clone_root_and_cannot_be_replaced() {
    let _g = guard();
    let (_ns, root_id, _proc_id, _dev, _s_root, _proc_d) = setup();
    let source = vfs::mount::mount_by_id(root_id).unwrap();
    let tree = vfs::mount::clone_mount_tree(&source, true);
    let root = tree.iter().find(|n| n.rel.is_empty()).expect("root clone").m.clone();
    let proc = tree.iter().find(|n| n.rel == "/proc").expect("proc clone").m.clone();
    let map = Arc::new(vfs::idmap::Idmap::uniform(100_000, 0, 65_536));

    vfs::mount::mnt_setattr_detached_tree(
        &tree, vfs::mount::MNT_RDONLY, 0, Some(map.clone()), true, None, false,
    ).expect("nonrecursive idmap on supported clone root");
    assert!(root.is_readonly(), "root option committed with its idmap");
    assert_eq!(root.idmap().map_out_uid(100_000), 0, "root exposes mapped uid");
    assert!(proc.idmap().is_identity(), "nonrecursive request leaves child map alone");
    assert!(!proc.is_readonly(), "nonrecursive request leaves child options alone");
    assert!(source.idmap().is_identity(), "source remains non-idmapped");
    assert_eq!(
        vfs::mount::mnt_setattr_detached_tree(&tree, 0, 0, Some(map), true, None, false),
        Err(VfsError::Eperm),
        "Linux permits only the first idmap installation",
    );
    vfs::mount::release_clone_tree(&tree);
}

#[allow(dead_code)]
fn _unused(_: VfsError) {}
