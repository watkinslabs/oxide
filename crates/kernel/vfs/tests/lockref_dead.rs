//! dcache-D27: `d_count` lockref production guards (Linux `lib/lockref.c`).
//! The bare `inc_count`/`dec_count` accounting is unconditional; the dcache
//! RCU lookup + `__dentry_kill` race needs three more primitives:
//!   - `inc_count_not_zero`  (Linux `lockref_get_not_zero`): pin only count > 0.
//!   - `inc_count_not_dead`  (Linux `lockref_get_not_dead`): pin unless dead;
//!     DOES resurrect an unused count-0 dentry (the `__d_lookup_rcu` pin).
//!   - `mark_dead`/`is_dead` (Linux `lockref_mark_dead`): stamp `LOCKREF_DEAD`,
//!     after which no `get` resurrects the dentry.
//! Pre-change these did not exist (compile failure); this proves the semantics.

use std::sync::Arc;

use vfs::{Dentry, FileType, InodeBuilder, InodeRef, default_file_ops, default_inode_ops, mk_mode};
use vfs::dentry::LOCKREF_DEAD;

/// Regular-file inode (struct-`Inode` model): a non-dir, `lookup`→`ENOTDIR`
/// via the default `i_op`.
fn make_file(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

fn dentry() -> Arc<Dentry> {
    Dentry::new(None, String::from("x"), make_file(0x1))
}

#[test]
fn fresh_dentry_is_count_zero_not_dead() {
    let d = dentry();
    assert_eq!(d.d_count(), 0, "fresh dentry unused (count 0)");
    assert!(!d.is_dead(), "fresh dentry is not dead");
}

#[test]
fn get_not_zero_refuses_unused_dentry() {
    // Linux `lockref_get_not_zero`: an unused (count 0) dentry is NOT pinned —
    // it may be on the LRU/shrinker, so the fast path must not resurrect it.
    let d = dentry();
    assert!(!d.inc_count_not_zero(), "count-0 dentry must not be get_not_zero-pinned");
    assert_eq!(d.d_count(), 0, "refused get_not_zero leaves count untouched");
}

#[test]
fn get_not_dead_resurrects_unused_but_get_not_zero_does_not() {
    // The defining distinction (Linux `__d_lookup_rcu`): `get_not_dead`
    // legitimately re-pins a count-0 LRU dentry; `get_not_zero` refuses.
    let d = dentry();
    assert!(d.inc_count_not_dead(), "get_not_dead resurrects an unused (count 0) dentry");
    assert_eq!(d.d_count(), 1, "get_not_dead bumped count 0 -> 1");
    assert!(d.is_referenced(), "a successful pin marks the two-hand-clock bit");

    // Now in-use: get_not_zero succeeds.
    assert!(d.inc_count_not_zero(), "in-use (count 1) dentry is get_not_zero-pinnable");
    assert_eq!(d.d_count(), 2, "get_not_zero bumped count 1 -> 2");
}

#[test]
fn mark_dead_blocks_every_get() {
    // Linux `__dentry_kill`: stamp `LOCKREF_DEAD`, after which neither
    // `get_not_dead` nor `get_not_zero` can resurrect the dentry.
    let d = dentry();
    assert!(!d.is_dead());
    d.mark_dead();
    assert!(d.is_dead(), "mark_dead -> is_dead");
    assert_eq!(d.d_count(), LOCKREF_DEAD, "mark_dead stamps the LOCKREF_DEAD sentinel");

    assert!(!d.inc_count_not_dead(), "no get_not_dead on a dead dentry");
    assert!(!d.inc_count_not_zero(), "no get_not_zero on a dead dentry");
    assert_eq!(d.d_count(), LOCKREF_DEAD, "refused gets leave the dead sentinel intact");
    assert!(d.is_dead(), "still dead after refused gets");
}

#[test]
fn dead_sentinel_is_negative() {
    // The dead marker must be < 0 so `get_not_dead`'s `old < 0` gate trips.
    assert!(LOCKREF_DEAD < 0, "LOCKREF_DEAD must be negative");
}
