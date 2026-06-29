//! dcache-D21: `d_drop` properly UNHASHES a dentry from the global table AND
//! forgets it from its parent's `d_subdirs` — vs the bare `forget_child` which
//! only removes the per-parent index entry and leaves the dentry HASHED (so a
//! global `d_lookup` would still resurrect a stale positive). Locks the
//! difference so a regression that routes eviction through `forget_child` alone
//! (leaving the global hash entry) fails here.
//!
//! dcache-D12: the no-`call_rcu` substitute — buckets hold `Weak`, so once the
//! last `Arc` of a hashed dentry dies, a concurrent `d_lookup` fails the
//! `Weak::upgrade` and reports a clean MISS (never a use-after-free). Locks that
//! a freed dentry is not resurrected from the bucket.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::dcache::d_drop;
use vfs::{d_add, d_lookup, Dentry, FileType, InodeRef};

fn dir(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755), vfs::default_inode_ops(), vfs::default_file_ops()).build()
}

static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

#[test]
fn d_drop_unhashes_and_forgets() {
    let _g = guard();
    let r = Dentry::new_root(dir(1));
    let c = d_add(&r, "victim", dir(40));
    assert!(c.is_hashed());
    assert!(d_lookup(&r, "victim").is_some());
    assert!(r.cached_child("victim").is_some());

    d_drop(&c);

    assert!(!c.is_hashed(), "d_drop clears D_HASHED");
    assert!(d_lookup(&r, "victim").is_none(), "global table no longer resurrects it");
    assert!(r.cached_child("victim").is_none(), "forgotten from parent d_subdirs");
}

#[test]
fn forget_child_alone_leaves_global_hash_entry() {
    // Demonstrates WHY d_drop (not bare forget_child) is the correct evict: a
    // plain forget_child removes only the per-parent index — the dentry stays
    // HASHED and a global d_lookup still hits it.
    let _g = guard();
    let r = Dentry::new_root(dir(2));
    let c = d_add(&r, "halfgone", dir(41));
    r.forget_child("halfgone");
    assert!(r.cached_child("halfgone").is_none(), "gone from parent index");
    assert!(c.is_hashed(), "but STILL hashed — the orphan d_drop fixes");
    assert!(d_lookup(&r, "halfgone").is_some(), "global table still resurrects it");
    // Now fully evict.
    d_drop(&c);
    assert!(d_lookup(&r, "halfgone").is_none());
}

#[test]
fn freed_dentry_is_not_resurrected_from_bucket() {
    // dcache-D12: drop every strong Arc, then look up — the bucket's Weak fails
    // to upgrade and the probe is a clean miss.
    let _g = guard();
    let r = Dentry::new_root(dir(3));
    let c = d_add(&r, "ephemeral", dir(42));
    assert!(d_lookup(&r, "ephemeral").is_some());
    // Strong refs: local `c` + the parent's d_subdirs entry. Remove the parent's
    // (without unhashing), then drop ours ⇒ last Arc dies, dentry frees.
    r.forget_child("ephemeral");
    drop(c);
    // The bucket still holds a Weak; upgrade now fails ⇒ miss, no UAF.
    assert!(d_lookup(&r, "ephemeral").is_none(), "freed dentry not resurrected");
}
