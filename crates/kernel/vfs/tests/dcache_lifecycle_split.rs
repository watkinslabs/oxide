//! dcache-D7: the dentry lifecycle is split into the Linux primitives
//!   `d_alloc`  — allocate an UNHASHED negative child,
//!   `d_instantiate` — bind an inode (negative→positive), and
//!   `d_add`    — alloc+instantiate+HASH in one shot,
//! plus `d_add_negative` (hashed negative). This locks each primitive's
//! distinct observable contract (hashed-ness + positivity) so a regression that
//! collapses them back into one monolithic "make child" helper fails here.
//!
//! Also covers dcache-D27: `cache_child` is first-wins — a racing second
//! instantiation is DISCARDED and every caller shares ONE canonical dentry per
//! (parent,name).

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::dcache::shrink_dcache; // pull the module into scope (and prove it links)
use vfs::inode::Inode;
use vfs::{d_add, d_add_negative, d_alloc, d_instantiate, d_lookup, Dentry, FileType, InodeRef, KResult, VfsError, D_NEGATIVE};

struct Dir(u64);
impl Inode for Dir {
    fn ino(&self) -> vfs::Ino { self.0 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn dir(ino: u64) -> InodeRef { Arc::new(Dir(ino)) }

// The global dentry hashtable is process-wide; serialize the tests that probe
// it so concurrent inserts under distinct roots can't interleave a probe.
static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

#[test]
fn d_alloc_is_unhashed_negative() {
    let _g = guard();
    let r = Dentry::new_root(dir(1));
    let c = d_alloc(&r, "scratch");
    assert!(c.is_negative(), "d_alloc yields a NEGATIVE dentry");
    assert_ne!(c.flags() & D_NEGATIVE, 0);
    assert!(c.is_unhashed(), "d_alloc does NOT hash (Linux d_alloc)");
    // Not hashed ⇒ a global cache lookup misses it.
    assert!(d_lookup(&r, "scratch").is_none());
}

#[test]
fn d_add_is_hashed_positive_and_found() {
    let _g = guard();
    let r = Dentry::new_root(dir(2));
    let c = d_add(&r, "file", dir(50));
    assert!(!c.is_negative());
    assert!(c.is_hashed(), "d_add HASHES the dentry");
    let hit = d_lookup(&r, "file").expect("d_add result is cache-visible");
    assert!(Arc::ptr_eq(&hit, &c));
}

#[test]
fn d_add_negative_is_hashed_negative_and_found() {
    let _g = guard();
    let r = Dentry::new_root(dir(3));
    let c = d_add_negative(&r, "absent");
    assert!(c.is_negative());
    assert!(c.is_hashed(), "d_add_negative HASHES the negative (cached miss)");
    let hit = d_lookup(&r, "absent").expect("cached negative is found");
    assert!(hit.is_negative());
    assert!(Arc::ptr_eq(&hit, &c));
}

#[test]
fn d_instantiate_flips_negative_to_positive() {
    let _g = guard();
    let r = Dentry::new_root(dir(4));
    let c = d_alloc(&r, "later");
    assert!(c.is_negative());
    d_instantiate(&c, dir(60));
    assert!(!c.is_negative(), "d_instantiate binds the inode");
    assert_eq!(c.flags() & D_NEGATIVE, 0);
}

#[test]
fn cache_child_first_wins_discards_racing_instantiation() {
    // dcache-D27: a second build for the same (parent,name) is DISCARDED;
    // both callers observe the FIRST dentry.
    let r = Dentry::new_root(dir(5));
    let first = Dentry::new_child(&r, "x", Some(dir(70)));
    let second = Dentry::new_child(&r, "x", Some(dir(71)));
    let w1 = r.cache_child("x", first.clone());
    let w2 = r.cache_child("x", second.clone());
    assert!(Arc::ptr_eq(&w1, &first), "first install wins");
    assert!(Arc::ptr_eq(&w2, &first), "racing second install returns the WINNER, not itself");
    assert!(!Arc::ptr_eq(&w2, &second), "the loser is discarded");

    // d_add layers the same race-safety: same name twice ⇒ one canonical Arc.
    let a = d_add(&r, "y", dir(80));
    let b = d_add(&r, "y", dir(81));
    assert!(Arc::ptr_eq(&a, &b), "d_add returns the canonical shared dentry");

    let _ = shrink_dcache;
}
