//! dcache-D21: `d_drop` properly UNHASHES a dentry from the global table AND
//! forgets it from its parent's `d_subdirs` — vs the bare `forget_child` which
//! only removes the per-parent index entry and leaves the dentry HASHED (so a
//! global `d_lookup` would still resurrect a stale positive). Locks the
//! difference so a regression that routes eviction through `forget_child` alone
//! (leaving the global hash entry) fails here.
//!
//! dcache-D12 (revised per `c7d034785` "retain hashed dentry ownership"): the
//! hash bucket holds a durable `Arc`, not a `Weak` — a still-hashed dentry
//! cannot be freed out from under a concurrent lookup (the earlier `Weak`
//! design let a bucket retain an expired, non-owning control block across a
//! lookup snapshot). Only `d_drop`'s unhash releases the bucket's ownership
//! reference; once every `Arc` (bucket's included) is gone, the dentry frees
//! and a subsequent `d_lookup` reports a clean MISS (never a use-after-free).

use std::sync::{Mutex, MutexGuard};

use vfs::dcache::{d_drop, d_drop_child};
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
fn d_drop_child_unhashes_from_object_parent() {
    let _g = guard();
    let r = Dentry::new_root(dir(4));
    let c = d_add(&r, "object", dir(43));
    assert!(c.is_hashed());
    assert!(d_lookup(&r, "object").is_some());

    d_drop_child(&r, "object");

    assert!(!c.is_hashed(), "object child drop clears D_HASHED");
    assert!(d_lookup(&r, "object").is_none(), "global table no longer hits");
    assert!(r.cached_child("object").is_none(), "parent index no longer hits");
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
    // dcache-D12 (revised): the hash bucket owns a durable Arc, so removing
    // every OTHER strong ref does not free a still-hashed dentry — it stays
    // alive and resurrects, by design (this is the fix for the UAF class
    // where a hashed dentry could be freed out from under a concurrent
    // lookup; see `dcache::hash::Bucket` doc + `c7d034785`).
    let _g = guard();
    let r = Dentry::new_root(dir(3));
    let c = d_add(&r, "ephemeral", dir(42));
    assert!(d_lookup(&r, "ephemeral").is_some());
    // Strong refs: local `c` + the parent's d_subdirs entry + the hash
    // bucket's own owning Arc. Remove the parent's index entry (without
    // unhashing) and drop ours ⇒ only the bucket's Arc remains, so the
    // dentry is still ALIVE and the global table still resurrects it.
    r.forget_child("ephemeral");
    drop(c);
    assert!(d_lookup(&r, "ephemeral").is_some(), "hash membership keeps a hashed dentry alive");
    // Only d_drop's unhash releases the bucket's ownership reference. Drop
    // the Arc that lookup handed back and every ref is now gone ⇒ the
    // dentry frees. A subsequent lookup is a clean miss, never a UAF.
    let looked_up = d_lookup(&r, "ephemeral").unwrap();
    d_drop(&looked_up);
    drop(looked_up);
    assert!(d_lookup(&r, "ephemeral").is_none(), "freed dentry not resurrected");
}
