//! dcache-D6: negative dentries are a LIVE cache, not dead code. A confirmed
//! miss cached via `d_add_negative` is hashed and a later `d_lookup` HITS it
//! (returning the negative) WITHOUT re-walking `i_op->lookup`; `set_inode`
//! flips D_NEGATIVE→positive on a subsequent create. Locks the cached-negative
//! contract so a regression that stops honoring/hashing negatives fails here.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::{d_add_negative, d_lookup, Dentry, FileType, InodeRef};

// A lookup MUST NOT be consulted once the negative is cached; default ops
// suffice (the cache short-circuits before any `i_op->lookup`).
fn dir(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755), vfs::default_inode_ops(), vfs::default_file_ops()).build()
}

static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

#[test]
fn cached_negative_is_hit_by_lookup() {
    let _g = guard();
    let r = Dentry::new_root(dir(1));
    assert!(d_lookup(&r, "ghost").is_none(), "not cached yet ⇒ miss");
    let neg = d_add_negative(&r, "ghost");
    assert!(neg.is_negative());
    assert!(neg.is_hashed());
    let hit = d_lookup(&r, "ghost").expect("cached negative is a HIT");
    assert!(hit.is_negative(), "the hit is the cached miss");
    assert!(Arc::ptr_eq(&hit, &neg), "same canonical negative dentry");
}

#[test]
fn negative_then_create_flips_positive() {
    let _g = guard();
    let r = Dentry::new_root(dir(2));
    let neg = d_add_negative(&r, "willcreate");
    assert!(neg.is_negative());
    // A create binds an inode into the SAME cached dentry (negative→positive).
    neg.set_inode(Some(dir(30)));
    assert!(!neg.is_negative());
    let hit = d_lookup(&r, "willcreate").expect("still hashed after the flip");
    assert!(!hit.is_negative(), "now positive");
    assert!(Arc::ptr_eq(&hit, &neg));
}
