//! `d_revalidate` in the path walk (Linux `fs/namei.c` `lookup_fast` →
//! `d_revalidate`). Two contracts:
//!   1. a cached dentry whose `d_op->d_revalidate` returns false is dropped and
//!      re-resolved via the slow `i_op->lookup` (cache MISS), never reused.
//!   2. `LOOKUP_REVAL` (the ESTALE-retry / forced-revalidation flag) is threaded
//!      to the hook, so a filesystem that trusts its cache normally can force a
//!      non-cached revalidation on the retry walk (`flags & LOOKUP_REVAL`).
//! Drives the real `path_lookup` walker over a synthetic inode tree; the
//! lookup-call counter observes whether the slow path re-ran.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use vfs::dentry::DentryOps;
use vfs::inode::Inode;
use vfs::{Dentry, FileType, InodeRef, KResult, LookupFlags, VfsError};

// GLOBAL dcache + the static counters below are process-wide: serialize.
static SERIAL: Mutex<()> = Mutex::new(());

// `i_op->lookup` invocation counter — increments only on a slow-path miss.
static LOOKUPS: AtomicUsize = AtomicUsize::new(0);
// Records the `reval` flag the hook last saw (proves LOOKUP_REVAL threading).
static SAW_REVAL: AtomicBool = AtomicBool::new(false);

/// Directory whose every `lookup` mints a fresh leaf file and bumps `LOOKUPS`,
/// so a re-resolved (dropped-then-re-looked-up) child is observable.
struct CountDir(u64);
impl Inode for CountDir {
    fn ino(&self) -> vfs::Ino { self.0 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> {
        LOOKUPS.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(Leaf(0x4000)))
    }
}

struct Leaf(u64);
impl Inode for Leaf {
    fn ino(&self) -> vfs::Ino { self.0 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

// Always stale: every cache hit must be dropped + re-resolved (contract 1).
fn rev_always_stale(_d: &Arc<Dentry>, _reval: bool) -> bool { false }
static OPS_STALE: DentryOps = DentryOps {
    d_revalidate: Some(rev_always_stale),
    d_hash: None, d_compare: None, d_delete: None, d_release: None, d_iput: None, d_dname: None,
};

// Valid normally, stale ONLY under a forced LOOKUP_REVAL walk (contract 2):
// mirrors NFS/FUSE/AFS `d_revalidate` honoring `flags & LOOKUP_REVAL`.
fn rev_on_reval(_d: &Arc<Dentry>, reval: bool) -> bool {
    SAW_REVAL.store(reval, Ordering::SeqCst);
    !reval
}
static OPS_REVAL: DentryOps = DentryOps {
    d_revalidate: Some(rev_on_reval),
    d_hash: None, d_compare: None, d_delete: None, d_release: None, d_iput: None, d_dname: None,
};

fn root_with(ops: &'static DentryOps, ino: u64) -> Arc<Dentry> {
    Dentry::new_root(Arc::new(CountDir(ino))).set_d_op(ops)
}

#[test]
fn stale_revalidate_forces_relookup_in_walk() {
    let _g = SERIAL.lock().unwrap();
    LOOKUPS.store(0, Ordering::SeqCst);
    let root = root_with(&OPS_STALE, 0x10);

    // First walk: cold cache → one slow lookup.
    vfs::path_lookup(root.clone(), root.clone(), "/f", LookupFlags::default()).expect("resolve f");
    assert_eq!(LOOKUPS.load(Ordering::SeqCst), 1, "cold cache: one i_op->lookup");

    // Second walk: cache HIT, but revalidate=false drops it → slow path re-runs.
    vfs::path_lookup(root.clone(), root.clone(), "/f", LookupFlags::default()).expect("resolve f again");
    assert_eq!(LOOKUPS.load(Ordering::SeqCst), 2, "stale revalidate must force a re-lookup, not reuse the cached dentry");
}

#[test]
fn lookup_reval_flag_threaded_to_hook() {
    let _g = SERIAL.lock().unwrap();
    LOOKUPS.store(0, Ordering::SeqCst);
    SAW_REVAL.store(false, Ordering::SeqCst);
    let root = root_with(&OPS_REVAL, 0x20);

    // Cold cache: one lookup (no revalidate on a miss).
    vfs::path_lookup(root.clone(), root.clone(), "/f", LookupFlags::default()).expect("resolve f");
    assert_eq!(LOOKUPS.load(Ordering::SeqCst), 1);

    // Ordinary walk (reval=false): hook returns valid → cache hit, no re-lookup.
    vfs::path_lookup(root.clone(), root.clone(), "/f", LookupFlags::default()).expect("resolve f");
    assert_eq!(LOOKUPS.load(Ordering::SeqCst), 1, "non-reval walk trusts the cache");
    assert!(!SAW_REVAL.load(Ordering::SeqCst), "hook saw reval=false on the ordinary walk");

    // Forced revalidation (LOOKUP_REVAL): hook sees reval=true, returns stale →
    // dentry dropped, slow path re-runs.
    let reval = LookupFlags { reval: true, ..Default::default() };
    vfs::path_lookup(root.clone(), root.clone(), "/f", reval).expect("resolve f under reval");
    assert!(SAW_REVAL.load(Ordering::SeqCst), "LOOKUP_REVAL must reach the d_revalidate hook");
    assert_eq!(LOOKUPS.load(Ordering::SeqCst), 2, "forced revalidation re-resolves the dentry");
}
