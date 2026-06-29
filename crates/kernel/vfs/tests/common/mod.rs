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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use vfs::fs::FileSystem;
use vfs::inode::{Inode, InodeBuilder};
use vfs::mount::Propagation;
use vfs::{default_file_ops, mk_mode, Dentry, FileType, InodeOps, InodeRef, KResult, VfsError};

static NEXT_INO: AtomicU64 = AtomicU64::new(0x1000);

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

/// Canonical dentry for absolute `path`, built by descending from the root
/// via the dcache (`d_lookup → i_op->lookup → d_add`) — the SAME per-
/// component walk the engine's `descend` uses, so identity is shared.
pub fn dentry(path: &str) -> Arc<Dentry> {
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

/// `None` for the root path "/", else `Some(dentry(p))` — the
/// `Option<Arc<Dentry>>` an attach/register caller hands the engine.
fn opt(p: &str) -> Option<Arc<Dentry>> {
    if p == "/" { None } else { Some(dentry(p)) }
}

/// Install the root-dentry provider so the engine's internal walks resolve
/// against this fixture tree. Idempotent (last wins).
pub fn install() {
    vfs::set_root_dentry_provider(root_provider);
}

// --- thin string→dentry test wrappers over the dentry-form mount API. These
// live in the FIXTURE (a caller), never in the engine: each does the single
// namei-equivalent walk (`dentry`) the real syscall handler does, then calls
// the dentry-form engine fn. ----------------------------------------------

#[allow(dead_code)]
pub fn register(p: &str, fs: Arc<dyn FileSystem>) -> KResult<()> {
    vfs::mount::register(opt(p), fs)
}
#[allow(dead_code)]
pub fn register_bind(p: &str, fs: Arc<dyn FileSystem>, root: InodeRef) -> KResult<()> {
    vfs::mount::register_bind(opt(p), fs, root)
}
#[allow(dead_code)]
pub fn unregister(p: &str) -> usize { vfs::mount::unregister(&dentry(p)) }
#[allow(dead_code)]
pub fn move_mount(from: &str, to: &str) -> KResult<()> {
    vfs::mount::move_mount(&dentry(from), &dentry(to))
}
#[allow(dead_code)]
pub fn pivot_root(nr: &str, po: &str) -> KResult<()> {
    vfs::mount::pivot_root(&dentry(nr), &dentry(po))
}
#[allow(dead_code)]
pub fn bind_submounts_rec(src: &str, tgt: &str) -> usize {
    vfs::mount::bind_submounts_rec(&dentry(src), &dentry(tgt))
}
#[allow(dead_code)]
pub fn set_propagation(p: &str, kind: Propagation) -> KResult<()> {
    vfs::mount::set_propagation(&dentry(p), kind)
}
#[allow(dead_code)]
pub fn peer_group_of(p: &str) -> u64 { vfs::mount::peer_group_of(&dentry(p)) }
#[allow(dead_code)]
pub fn join_peer_group(p: &str, pg: u64) { vfs::mount::join_peer_group(&dentry(p), pg) }
#[allow(dead_code)]
pub fn propagate_mount(p: &str) -> usize { vfs::mount::propagate_mount(&dentry(p)) }
#[allow(dead_code)]
pub fn is_mount_in_ns(p: &str, ns: u64) -> bool { vfs::mount::is_mount_in_ns(&dentry(p), ns) }
#[allow(dead_code)]
pub fn mount_root_at(p: &str) -> Option<InodeRef> { vfs::mount::mount_root_at(&dentry(p)) }
#[allow(dead_code)]
pub fn mount_at_path_exact(p: &str) -> Option<Arc<vfs::mount::Mount>> {
    vfs::mount::mount_at_path_exact(&dentry(p))
}

// Silence unused-import warnings in test binaries that pull in `common` but
// exercise only a subset of the wrappers.
#[allow(dead_code)]
fn _unused(_: VfsError) {}
