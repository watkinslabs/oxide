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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::{Inode, InodeBuilder};
use vfs::{default_file_ops, mk_mode, Dentry, FileType, InodeOps, InodeRef, KResult, VfsError};

static SERIAL: Mutex<()> = Mutex::new(());

// Per-test ns/dev counters (global mount state persists across tests in one
// binary, so each test uses a FRESH ns + backing dev to avoid collision).
static NEXT_NS: AtomicU64 = AtomicU64::new(0xD24_0000);
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
}

/// Anon api-fs (`dev_id() == None` → fresh per-mount SB), e.g. procfs/sysfs.
struct ApiFs { root_ino: u64 }
impl FileSystem for ApiFs {
    fn name(&self) -> &str { "apifs_test" }
    fn root(&self) -> Option<InodeRef> { Some(facdir(self.root_ino)) }
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
fn setup() -> (u64, u64, u64, Arc<Dentry>, Arc<Dentry>) {
    let ns = NEXT_NS.fetch_add(1, Ordering::Relaxed);
    // A `fn()` ns-provider cannot capture `ns`; stash it in a global the provider
    // reads. Serialized by SERIAL.
    *CUR_NS.lock().unwrap_or_else(|e| e.into_inner()) = ns;
    vfs::mount::set_current_ns_provider(|| *CUR_NS.lock().unwrap_or_else(|e| e.into_inner()));
    // ns-root mount over the dev-backed rootfs.
    let dev = NEXT_DEV.fetch_add(1, Ordering::Relaxed);
    vfs::mount::register(None, Arc::new(RootFs { dev, root_ino: NEXT_INO.fetch_add(1, Ordering::Relaxed) }))
        .expect("root mount");
    let root_id = vfs::mount::root_mount_id(ns).expect("root id");
    let s_root = vfs::mount::mount_by_id(root_id).unwrap().sb().s_root().expect("rootfs s_root");
    // Install the s_root as the global root-dentry provider (boot wiring).
    *CUR_SROOT.lock().unwrap_or_else(|e| e.into_inner()) = Some(s_root.clone());
    vfs::set_root_dentry_provider(root_provider);
    // /proc api-mount (anon procfs) on the /proc dentry under s_root.
    let proc_d = child(&s_root, "proc");
    vfs::mount::register(Some(proc_d.clone()), Arc::new(ApiFs { root_ino: NEXT_INO.fetch_add(1, Ordering::Relaxed) }))
        .expect("proc mount");
    let proc_id = vfs::mount::__lookup_mnt(root_id, &proc_d).expect("proc in hash").mnt_id;
    (ns, root_id, proc_id, s_root, proc_d)
}

static CUR_NS: Mutex<u64> = Mutex::new(0);

fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

// The whole point of Stage 1a: a recursive open_tree clone, committed hash-only,
// makes (clone_root, /proc) resolvable WITHOUT clobbering the original
// (ns_root, /proc) — proving the new strict-hash entry coexists.
#[test]
fn recursive_clone_hashonly_no_clobber() {
    let _g = guard();
    let (ns, root_id, proc_id, _s_root, proc_d) = setup();

    // Premise: rootfs is dev-backed (the global-dentry-exposure precondition).
    assert!(vfs::mount::mount_by_id(root_id).unwrap().fs().dev_id().is_some(),
        "rootfs dev_id() == Some (live-gnome premise: clone shares the SB → global /proc dentry)");
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
    // Walk oracle UNTOUCHED: the legacy per-ns map at /proc still names the
    // original proc mount, not the clone (no wire_crossing in hash-only commit).
    assert_eq!(proc_d.mounted_mount(ns), Some(proc_id),
        "legacy dentry.mounted_mounts map (walk oracle) NOT clobbered by hash-only commit");
}

// Leak balance: an open_tree clone tree released without a move_mount (fd closed)
// balances the shared SB active count (release_clone_tree).
#[test]
fn uncommitted_clone_tree_balances_s_active() {
    let _g = guard();
    let (_ns, root_id, _proc_id, _s_root, _proc_d) = setup();
    let root_mnt = vfs::mount::mount_by_id(root_id).unwrap();
    let before = root_mnt.sb().s_active();

    let nodes = vfs::mount::clone_mount_tree(&root_mnt, true);
    assert!(root_mnt.sb().s_active() > before, "clone root shares the SB → s_active bumped");
    vfs::mount::release_clone_tree(&nodes);
    assert_eq!(root_mnt.sb().s_active(), before,
        "release_clone_tree drops the clones' active refs → s_active balanced");
}

#[allow(dead_code)]
fn _unused(_: VfsError) {}
