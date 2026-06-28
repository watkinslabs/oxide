//! dcache-D27 lockref chain — the `dcache.rs` half (B192). `dentry.rs` already
//! carries the lockref primitives (`inc_count_not_dead`, `mark_dead`); this
//! pins the dcache wiring: `d_lookup` must read a dentry mid-kill (lockref
//! stamped `LOCKREF_DEAD`) as a cache MISS, and every genuine eviction
//! (`dput`-to-zero, the LRU shrinker) must stamp the dentry dead BEFORE
//! unhashing so a racing lookup cannot resurrect a dying dentry.
//!
//! These tests mutate the process-global dcache hash table + LRU, so they take
//! a serial guard to avoid racing sibling tests in this binary.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::dcache::shrink_dcache;
use vfs::dentry::{DentryOps, LOCKREF_DEAD};
use vfs::inode::Inode;
use vfs::{Dentry, FileType, InodeRef, KResult, VfsError};

static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

struct Dir { ino: u64 }
impl Inode for Dir {
    fn ino(&self) -> u64 { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn dir(ino: u64) -> InodeRef { Arc::new(Dir { ino }) }
fn root() -> Arc<Dentry> { Dentry::new_root(dir(1)) }

// A dentry whose lockref is DEAD but is STILL hashed (the window inside
// `dentry_kill` between `mark_dead` and `__d_drop`) must read as a MISS:
// `d_lookup`'s `inc_count_not_dead` gate refuses to resurrect it (Linux
// `__d_lookup` + `lockref_get_not_dead`). Pre-change `d_lookup` returned the
// candidate unconditionally — this is the fails-before/passes-after.
#[test]
fn d_lookup_skips_dead_but_still_hashed() {
    let _g = guard();
    let r = root();
    let c = vfs::d_add(&r, "dying", dir(50));
    assert!(vfs::d_lookup(&r, "dying").is_some(), "a live dentry is a normal hit");
    c.mark_dead();
    assert_eq!(c.d_count(), LOCKREF_DEAD, "mark_dead stamps the kill sentinel");
    assert!(c.is_hashed(), "still in the global hash table (kill mid-flight)");
    assert!(vfs::d_lookup(&r, "dying").is_none(), "a dead dentry must be a lookup miss");
}

// A successful lookup leaves the lockref balanced (net zero) — this dcache hands
// out an `Arc`, not a counted dput-owed ref — but stamps the two-hand-clock
// `D_REFERENCED` access bit so the shrinker rotates a freshly-used dentry.
#[test]
fn d_lookup_is_refcount_neutral_and_marks_referenced() {
    let _g = guard();
    let r = root();
    let c = vfs::d_add(&r, "f", dir(51));
    assert_eq!(c.d_count(), 0, "fresh cached dentry is unused");
    let hit = vfs::d_lookup(&r, "f").expect("hit");
    assert!(Arc::ptr_eq(&hit, &c), "lookup returns the canonical dentry");
    assert_eq!(c.d_count(), 0, "lookup pins-then-releases: net-zero d_count");
    assert!(c.is_referenced(), "lookup stamps the two-hand-clock access bit");
}

// `d_delete` opts a pseudo-fs into immediate eviction on final `dput`: the kill
// runs through `dentry_kill`, which stamps DEAD BEFORE unhashing. Pre-change the
// final `dput` called bare `d_drop` and left `is_dead() == false`.
static DEL_OPS: DentryOps = DentryOps {
    d_delete: Some(|_d| true),
    d_hash: None, d_compare: None, d_revalidate: None, d_release: None, d_iput: None, d_dname: None, d_init: None, d_prune: None,
};
#[test]
fn dput_to_zero_marks_dead_before_unhash() {
    let _g = guard();
    let r = Dentry::new_root(dir(1)).set_d_op(&DEL_OPS);
    let c = vfs::d_add(&r, "k", dir(52));
    assert!(c.is_hashed());
    let held = vfs::dget(&c);    // d_count 1
    vfs::dput(held);             // d_count 0 -> d_delete -> dentry_kill
    assert!(c.is_dead(), "the final dput killed it -> lockref DEAD");
    assert!(!c.is_hashed(), "and it was unhashed (d_drop ran after mark_dead)");
    assert!(vfs::d_lookup(&r, "k").is_none(), "a killed dentry is no longer cached");
}

// The LRU shrinker is also a `__dentry_kill` site: an evicted unused dentry is
// stamped DEAD before it leaves the hash table.
#[test]
fn shrink_marks_evicted_dead() {
    let _g = guard();
    let r = root();
    let c = vfs::d_add_negative(&r, "neg");
    let held = vfs::dget(&c);    // count 1, sets D_REFERENCED
    vfs::dput(held);             // count 0, hashed -> joins the LRU
    assert!(c.is_on_lru(), "unused hashed negative joins the LRU");
    let _ = shrink_dcache(8);    // first pass: referenced -> rotate, clear bit
    let freed = shrink_dcache(8); // second pass: evict (dentry_kill)
    assert!(freed >= 1, "the unused negative is evicted on the second pass");
    assert!(c.is_dead(), "a shrinker-evicted dentry is stamped DEAD");
    assert!(r.cached_child("neg").is_none(), "and forgotten by its parent");
}
