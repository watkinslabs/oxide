//! dcache d_invalidate edge: Linux `d_invalidate` opens with
//! `if (d_unhashed(dentry)) return;`. An already-unhashed dentry was invalidated
//! before (or never entered the hash), so a re-entry is a no-op — it must NOT
//! re-tear-down the subtree hanging off it. This guards idempotency (a parallel
//! rmdir + revalidate racing two teardowns) and the non-canonical-name case.

use std::sync::Arc;

use vfs::dentry::Dentry;
use vfs::{d_add, d_invalidate, d_lookup, FileType, InodeRef};

fn dir(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755), vfs::default_inode_ops(), vfs::default_file_ops()).build()
}

// An UNHASHED dentry's subtree is left intact: d_invalidate early-returns, so a
// hashed child below it is NOT torn down. Pre-fix the walk dropped the whole
// subtree regardless of the top dentry's hash state.
#[test]
fn unhashed_top_is_a_noop() {
    let r = Dentry::new_root(dir(1));
    let a = d_add(&r, "a", dir(10)); // hashed
    // `p` is a connected but UNHASHED node (built by new_child, never d_add-ed).
    let p = Dentry::new_child(&a, "p", Some(dir(11)));
    assert!(p.is_unhashed(), "p is unhashed by construction");
    let kid = d_add(&p, "kid", dir(12)); // hashed child under the unhashed p
    assert!(kid.is_hashed());
    assert!(d_lookup(&p, "kid").is_some(), "kid cached pre-invalidate");

    d_invalidate(&p); // p unhashed ⇒ early return ⇒ subtree untouched

    assert!(kid.is_hashed(), "hashed child survives invalidate of an unhashed parent");
    assert!(d_lookup(&p, "kid").is_some(), "subtree of an unhashed dentry is NOT torn down");
}

// A hashed dentry IS torn down; a SECOND invalidate is then idempotent (the
// dentry is now unhashed, so the early return fires — no panic, no re-teardown).
#[test]
fn second_invalidate_is_idempotent() {
    let r = Dentry::new_root(dir(2));
    let a = d_add(&r, "a", dir(20)); // hashed
    let _b = d_add(&a, "b", dir(21));
    assert!(d_lookup(&r, "a").is_some());

    d_invalidate(&a);
    assert!(a.is_unhashed(), "first invalidate unhashed the subtree root");
    assert!(d_lookup(&r, "a").is_none(), "subtree torn down");

    // Idempotent: the second call hits the d_unhashed early-return.
    d_invalidate(&a);
    assert!(d_lookup(&r, "a").is_none());
}
