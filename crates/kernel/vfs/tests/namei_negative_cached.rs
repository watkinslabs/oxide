//! D5 (READ side) — the path walk honors a cached NEGATIVE dentry as a
//! definitive `ENOENT` WITHOUT re-invoking the (possibly blocking) slow-path
//! `i_op->lookup` (Linux `lookup_fast` → a negative dcache hit short-circuits
//! to `-ENOENT`). The insert side is deliberately NOT wired (a negative cached
//! for a dynamically-appearing pseudo-fs node would mask it forever — see the
//! `walk` D6 NOTE), so this locks ONLY the read contract:
//!   1. a planted negative under the parent → walk returns `ENOENT`, and the
//!      directory's `i_op->lookup` counter is UNCHANGED (the negative was the
//!      authority, the fs was never consulted);
//!   2. under RESOLVE_CACHED the SAME negative is still `ENOENT`, NOT `EAGAIN`
//!      (a negative is a definitive answer served from cache, not a cold miss
//!      that needs the blocking path — the match-arm ordering in `walk`);
//!   3. a non-cached sibling name still takes the slow path (counter bumps),
//!      proving the negative is specific to its (parent,name), not a blanket
//!      short-circuit.
//! Drives the REAL `vfs::path_lookup` over a synthetic inode tree. d_delete.rs
//! already exercises `d_lookup` returning a negative directly; this is the
//! missing coverage of that negative being honored THROUGH the walk.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use vfs::inode::Inode;
use vfs::{Dentry, FileType, InodeRef, KResult, LookupFlags, VfsError};

// The global DENTRY_HASHTABLE + the counter below are process-wide: serialize.
static SERIAL: Mutex<()> = Mutex::new(());

// `i_op->lookup` invocation counter — bumps ONLY when the slow path runs, so a
// short-circuited (cached-negative) component leaves it untouched.
static LOOKUPS: AtomicUsize = AtomicUsize::new(0);

/// Directory whose every `lookup` mints a fresh leaf file and bumps `LOOKUPS`.
/// So if the walk EVER consults the fs for a planted-negative name, the counter
/// catches it.
struct CountDirOps;
impl vfs::InodeOps for CountDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> {
        LOOKUPS.fetch_add(1, Ordering::SeqCst);
        Ok(mk_leaf(0x5000))
    }
}
fn mk_countdir(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755),
        Arc::new(CountDirOps), vfs::default_file_ops()).build()
}
fn mk_leaf(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Regular, 0o644),
        vfs::default_inode_ops(), vfs::default_file_ops()).build()
}

fn cached() -> LookupFlags { let mut f = LookupFlags::default(); f.cached = true; f }

// A planted negative dentry is a definitive ENOENT, served WITHOUT the fs being
// consulted — the directory's `lookup` (which would otherwise mint a file for
// ANY name) is never called for the negative's name.
#[test]
fn cached_negative_is_enoent_without_fs_lookup() {
    let _g = SERIAL.lock().unwrap();
    LOOKUPS.store(0, Ordering::SeqCst);
    let root = Dentry::new_root(mk_countdir(0x10));

    // Plant a negative for `ghost` under the root (Linux `d_add_negative`).
    let neg = vfs::d_add_negative(&root, "ghost");
    assert!(neg.is_negative(), "planted dentry is negative");

    // The walk hits the cached negative → ENOENT, and NEVER calls i_op->lookup
    // (so the counter stays 0) even though CountDir would mint a file for any
    // name. THIS is the read-side short-circuit the walk must honor.
    assert_eq!(
        vfs::path_lookup(root.clone(), root.clone(), "/ghost", LookupFlags::default()).err(),
        Some(VfsError::Enoent),
        "a cached negative dentry resolves to ENOENT through the walk",
    );
    assert_eq!(LOOKUPS.load(Ordering::SeqCst), 0,
        "the negative was authoritative — i_op->lookup must NOT be consulted");
}

// Under RESOLVE_CACHED a cached negative is STILL a definitive ENOENT, NOT the
// EAGAIN a cold (uncached) miss would yield — the negative is a cached answer,
// not a slow-path-needed gap. Locks the `Some(_) => ENOENT` arm preceding the
// `None if cached => EAGAIN` arm in `walk`.
#[test]
fn cached_negative_under_resolve_cached_is_enoent_not_eagain() {
    let _g = SERIAL.lock().unwrap();
    LOOKUPS.store(0, Ordering::SeqCst);
    let root = Dentry::new_root(mk_countdir(0x20));
    vfs::d_add_negative(&root, "ghost");

    assert_eq!(
        vfs::path_lookup(root.clone(), root.clone(), "/ghost", cached()).err(),
        Some(VfsError::Enoent),
        "RESOLVE_CACHED + cached negative is a definitive ENOENT, not EAGAIN",
    );
    assert_eq!(LOOKUPS.load(Ordering::SeqCst), 0, "no fs lookup under cached negative");
}

// The negative is specific to its (parent,name): a DIFFERENT, uncached sibling
// still takes the slow path and resolves (counter bumps) — proving the cached
// negative is not a blanket directory short-circuit.
#[test]
fn sibling_name_still_takes_slow_path() {
    let _g = SERIAL.lock().unwrap();
    LOOKUPS.store(0, Ordering::SeqCst);
    let root = Dentry::new_root(mk_countdir(0x30));
    vfs::d_add_negative(&root, "ghost");

    // `real` is not cached → slow path mints the leaf, counter bumps.
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/real", LookupFlags::default())
        .expect("uncached sibling resolves via the slow path");
    assert_eq!(i.ino(), 0x5000, "sibling resolved to the minted leaf");
    assert_eq!(LOOKUPS.load(Ordering::SeqCst), 1, "the uncached sibling consulted i_op->lookup once");

    // ...and the negative remains ENOENT (still no extra fs consult for it).
    assert_eq!(
        vfs::path_lookup(root.clone(), root.clone(), "/ghost", LookupFlags::default()).err(),
        Some(VfsError::Enoent),
        "the planted negative is still honored after a sibling slow-path resolve",
    );
    assert_eq!(LOOKUPS.load(Ordering::SeqCst), 1, "the negative added no further fs lookups");
}
