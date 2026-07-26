//! Hosted-test mount-engine fixture (`docs/16§3`). After WP4 the mount
//! engine NEVER resolves a mount-point path STRING to a dentry — every
//! caller hands it the `Arc<Dentry>` its namei walk produced, and the
//! engine's internal `descend` materialises SYNTHESIZED positions
//! (propagation mirrors / move-pivot relocations) from a dentry it already
//! holds. This fixture mirrors the real boot wiring: it installs a global
//! ROOT-DENTRY PROVIDER over a directory-factory inode tree, so both
//! `common::dentry(path)` (the caller's walk) and the engine's `descend`
//! resolve through ONE shared dcache (`parent.children`), giving stable
//! dentry identity by (parent,name) — exactly what the dentry-identity
//! engine needs to be exercised in `cargo test`.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use vfs::fs::FileSystem;
use vfs::inode::{Inode, InodeBuilder};
use vfs::mount::Propagation;
use vfs::{default_file_ops, mk_mode, Dentry, FileSystemType, FileType, InodeOps, InodeRef, KResult, SimpleSuperOps, SuperBlock, SuperOps, VfsError};

static NEXT_INO: AtomicU64 = AtomicU64::new(0x1000);

static CURRENT_NAMESPACE: OnceLock<Mutex<vfs::mntns::MntNamespaceRef>> = OnceLock::new();
static NAMESPACES: OnceLock<Mutex<BTreeMap<u64, vfs::mntns::MntNamespaceRef>>> = OnceLock::new();

fn new_namespace() -> vfs::mntns::MntNamespaceRef {
    let init = vfs::mntns::initial();
    vfs::mntns::allocate(init.owner_user_namespace()).unwrap()
}

pub fn current_namespace() -> vfs::mntns::MntNamespaceRef {
    CURRENT_NAMESPACE.get_or_init(|| Mutex::new(new_namespace()))
        .lock().unwrap_or_else(|e| e.into_inner()).clone()
}

pub fn set_current_namespace(namespace: vfs::mntns::MntNamespaceRef) {
    *CURRENT_NAMESPACE.get_or_init(|| Mutex::new(new_namespace()))
        .lock().unwrap_or_else(|e| e.into_inner()) = namespace;
}

pub fn namespace_for_key(key: u64) -> vfs::mntns::MntNamespaceRef {
    let mut namespaces = NAMESPACES.get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock().unwrap_or_else(|e| e.into_inner());
    namespaces.entry(key).or_insert_with(|| {
        if key == 0 { vfs::mntns::initial() } else { new_namespace() }
    }).clone()
}

pub fn namespace_id(key: u64) -> u64 { namespace_for_key(key).id() }

pub fn copy_mnt_ns(from: u64, to: u64) -> KResult<()> {
    let from = namespace_for_key(from);
    let to = namespace_for_key(to);
    vfs::mount::copy_mnt_ns(&from, &to)
}

pub fn snapshot_ns(from: u64, to: u64) -> KResult<()> {
    let from = namespace_for_key(from);
    let to = namespace_for_key(to);
    vfs::mount::snapshot_ns(&from, &to)
}

pub fn snapshot_ns_map(from: u64, to: u64) -> KResult<Vec<(u64, u64)>> {
    let from = namespace_for_key(from);
    let to = namespace_for_key(to);
    vfs::mount::snapshot_ns_map(&from, &to)
}

/// Directory-factory inode: every name resolves to a fresh child directory,
/// so the engine's `descend` / `path_lookup` can materialise ANY mountpoint
/// position. Mount routing keys on dentry identity (not inode identity), and
/// the dcache (`parent.children`) dedups the dentry, so a fresh inode per
/// lookup is fine.
struct FixDirOps;
impl InodeOps for FixDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> {
        Ok(make_fixdir(NEXT_INO.fetch_add(1, Ordering::Relaxed)))
    }
}
fn make_fixdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(FixDirOps), default_file_ops()).build()
}

/// One process-global root dentry, shared by `dentry()` and the engine's
/// `descend` via the root-dentry provider.
static ROOT: OnceLock<Arc<Dentry>> = OnceLock::new();
fn root() -> Arc<Dentry> {
    ROOT.get_or_init(|| Dentry::new_root(make_fixdir(2))).clone()
}
fn root_provider() -> Option<Arc<Dentry>> { Some(root()) }

fn fs_type_for(fs: &Arc<dyn FileSystem>) -> Arc<dyn FileSystemType> {
    vfs::fs::FsType::new(fs.name(), fs.magic(), fs.fs_flags(), Box::new(|_, _, _, _| unreachable!("test fs type is mounted explicitly")))
}

/// Canonical dentry for absolute `path`, built by descending from the root
/// via the dcache (`d_lookup → i_op->lookup → d_add`) — the SAME per-
/// component walk the engine's `descend` uses, so identity is shared.
fn raw_dentry(path: &str) -> Arc<Dentry> {
    let mut cur = root();
    for comp in path.split('/').filter(|c| !c.is_empty()) {
        cur = match vfs::d_lookup(&cur, comp) {
            Some(d) if !d.is_negative() => d,
            _ => {
                let ci = cur.inode().unwrap().lookup(comp).unwrap();
                vfs::d_add(&cur, comp, ci)
            }
        };
    }
    cur
}

pub fn dentry(path: &str) -> Arc<Dentry> {
    if path == "/" { return root(); }
    if vfs::mount::root_mount_id(vfs::mount::current_ns()).is_some() {
        return mount_target(path).mountpoint;
    }
    raw_dentry(path)
}

fn mount_target(p: &str) -> vfs::MountTarget {
    let r = root();
    let ns = vfs::mount::current_ns();
    let root_mnt = vfs::mount::root_mount_id(ns).expect("root mount exists");
    vfs::mountpoint_lookup_at_root_cred(r.clone(), root_mnt, r, root_mnt, p, vfs::Cred::root())
        .expect("mount target resolves")
}

/// Install the root-dentry provider so the engine's internal walks resolve
/// against this fixture tree. Idempotent (last wins).
pub fn install() {
    vfs::set_root_dentry_provider(root_provider);
}

/// Build a test superblock through the same Linux-shaped fields the mount
/// engine installs: `s_type`, `s_op`, `s_root`, and `s_fs_info`.
pub fn realize_sb(fs: Arc<dyn FileSystem>, root: Option<InodeRef>, dev: u64, s_id: String) -> Arc<SuperBlock> {
    let root = root.or_else(|| fs.root());
    let s_op: Arc<dyn SuperOps> = fs.super_ops().unwrap_or_else(|| {
        Arc::new(SimpleSuperOps {
            magic: fs.magic(),
            block_size: fs.block_size(),
            options: fs.show_options(),
        })
    });
    let ty: Arc<dyn vfs::FileSystemType> =
        vfs::fs::FsType::new(fs.name(), fs.magic(), fs.fs_flags(), Box::new(|_, _, _, _| unreachable!("test fs type is not mounted through ->mount")));
    let sb = SuperBlock::from_ops(ty, s_op, root, fs.magic(), dev, fs.block_size(), s_id, Arc::new(()));
    fs.set_sb(Arc::downgrade(&sb)).expect("test fs set_sb");
    sb
}

// --- thin string→dentry test wrappers over the dentry-form mount API. These
// live in the FIXTURE (a caller), never in the engine: each does the single
// namei-equivalent walk (`dentry`) the real syscall handler does, then calls
// the dentry-form engine fn. ----------------------------------------------

/// Register `fs`'s name into the real global `FileSystemType` registry
/// (`vfs::fs::register_filesystem`), idempotently. Needed before any call to
/// the `_path_at` mount entry points (`register_bind_path_at`, `register_at`),
/// which resolve their filesystem type by NAME through `get_fs_type` — unlike
/// `common::register`/`register_bind`, which build and pass an explicit
/// `FileSystemType` directly, bypassing the registry entirely.
#[allow(dead_code)]
pub fn ensure_fs_type(fs: &Arc<dyn FileSystem>) {
    if vfs::fs::get_fs_type(fs.name()).is_some() { return; }
    let _ = vfs::fs::register_filesystem(fs_type_for(fs));
}
#[allow(dead_code)]
pub fn register(p: &str, fs: Arc<dyn FileSystem>) -> KResult<()> {
    let ty = fs_type_for(&fs);
    if p == "/" { return vfs::mount::register_typed(ty, None, fs); }
    if vfs::mount::root_mount_id(vfs::mount::current_ns()).is_none() {
        return vfs::mount::register_typed(ty, Some(raw_dentry(p)), fs);
    }
    let target = mount_target(p);
    vfs::mount::register_typed_at(ty, Some(target.mountpoint), fs, Some(target.parent.mnt_id))
}
#[allow(dead_code)]
pub fn register_bind(p: &str, fs: Arc<dyn FileSystem>, root: InodeRef) -> KResult<()> {
    let ty = fs_type_for(&fs);
    if p == "/" { return vfs::mount::register_bind_typed(ty, None, fs, root); }
    if vfs::mount::root_mount_id(vfs::mount::current_ns()).is_none() {
        return vfs::mount::register_bind_typed(ty, Some(raw_dentry(p)), fs, root);
    }
    let target = mount_target(p);
    vfs::mount::register_bind_typed_at(ty, Some(target.mountpoint), fs, root, Some(target.parent.mnt_id))
}
#[allow(dead_code)]
pub fn unregister(p: &str) -> usize { vfs::mount::unregister(&dentry(p)) }
#[allow(dead_code)]
pub fn move_mount(from: &str, to: &str) -> KResult<()> {
    if vfs::mount::root_mount_id(vfs::mount::current_ns()).is_none() {
        return vfs::mount::move_mount(&raw_dentry(from), &raw_dentry(to));
    }
    vfs::mount::move_mount(&mount_target(from).mountpoint, &mount_target(to).mountpoint)
}
#[allow(dead_code)]
pub fn pivot_root(nr: &str, po: &str) -> KResult<()> {
    vfs::mount::pivot_root(&dentry(nr), &dentry(po))
}
#[allow(dead_code)]
pub fn bind_submounts_rec(src: &str, tgt: &str) -> usize {
    if vfs::mount::root_mount_id(vfs::mount::current_ns()).is_none() {
        return vfs::mount::bind_submounts_rec(&raw_dentry(src), &raw_dentry(tgt));
    }
    let r = root();
    let source = vfs::path_lookup_path(r.clone(), r, src, vfs::LookupFlags::default())
        .expect("recursive bind source resolves");
    let target = mount_target(tgt);
    let target_d = target.mountpoint.clone();
    let target_parent = target.parent.mnt_id;
    if vfs::mount::mount_at_path_exact(&target_d).is_none() {
        vfs::mount::register_bind_clone_under(target_parent, target_d.clone(), source.mnt_id, source.dentry.clone())
            .expect("recursive bind top clone");
    }
    vfs::mount::bind_submounts_rec_at(Some(source.mnt_id), &source.dentry, &target_d, Some(target_parent))
}
#[allow(dead_code)]
pub fn set_propagation(p: &str, kind: Propagation) -> KResult<()> {
    if vfs::mount::root_mount_id(vfs::mount::current_ns()).is_none() {
        return vfs::mount::set_propagation(&raw_dentry(p), kind);
    }
    vfs::mount::set_propagation(&mount_target(p).mountpoint, kind)
}
#[allow(dead_code)]
pub fn peer_group_of(p: &str) -> u64 {
    if vfs::mount::root_mount_id(vfs::mount::current_ns()).is_none() {
        return vfs::mount::peer_group_of(&raw_dentry(p));
    }
    vfs::mount::peer_group_of(&mount_target(p).mountpoint)
}
#[allow(dead_code)]
pub fn join_peer_group(p: &str, pg: u64) {
    if vfs::mount::root_mount_id(vfs::mount::current_ns()).is_none() {
        return vfs::mount::join_peer_group(&raw_dentry(p), pg);
    }
    vfs::mount::join_peer_group(&mount_target(p).mountpoint, pg)
}
#[allow(dead_code)]
pub fn propagate_mount(p: &str) -> usize {
    if vfs::mount::root_mount_id(vfs::mount::current_ns()).is_none() {
        return vfs::mount::propagate_mount(&raw_dentry(p));
    }
    vfs::mount::propagate_mount(&mount_target(p).mountpoint)
}
#[allow(dead_code)]
pub fn is_mount_in_ns(p: &str, ns: u64) -> bool {
    if vfs::mount::root_mount_id(vfs::mount::current_ns()).is_none() {
        return vfs::mount::is_mount_in_ns(&raw_dentry(p), ns);
    }
    vfs::mount::is_mount_in_ns(&mount_target(p).mountpoint, ns)
}
#[allow(dead_code)]
pub fn mount_root_at(p: &str) -> Option<InodeRef> {
    if vfs::mount::root_mount_id(vfs::mount::current_ns()).is_none() {
        return vfs::mount::mount_root_at(&raw_dentry(p));
    }
    mount_at_path_exact(p).and_then(|m| m.mnt_root()).and_then(|d| d.inode())
}
#[allow(dead_code)]
pub fn mount_at_path_exact(p: &str) -> Option<Arc<vfs::mount::Mount>> {
    if p == "/" {
        return vfs::mount::root_mount_id(vfs::mount::current_ns()).and_then(vfs::mount::mount_by_id);
    }
    if vfs::mount::root_mount_id(vfs::mount::current_ns()).is_none() {
        return vfs::mount::mount_at_path_exact(&raw_dentry(p));
    }
    let target = mount_target(p);
    vfs::mount::mount_at_path_exact_under(target.parent.mnt_id, &target.mountpoint)
}

// Silence unused-import warnings in test binaries that pull in `common` but
// exercise only a subset of the wrappers.
#[allow(dead_code)]
fn _unused(_: VfsError) {}
