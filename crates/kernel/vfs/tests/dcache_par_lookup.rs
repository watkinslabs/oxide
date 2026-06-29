//! dcache-D21/D27/D7: DCACHE_PAR_LOOKUP in-flight-lookup placeholder
//! (`d_alloc_parallel` / `d_lookup_done`). Two walkers that miss the main hash
//! for the SAME (parent,name) no longer each construct a dentry and run
//! `i_op->lookup` then race in `cache_child`: the first becomes the LEADER and
//! installs a `D_PAR_LOOKUP` placeholder, the rest become WAITERS that share the
//! leader's single placeholder and block on its `is_in_lookup()` wake gate.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::dcache::{d_alloc_parallel, d_lookup_done, DParLookup};
use vfs::{d_instantiate, d_lookup, Dentry, FileType, InodeRef};

fn dir(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755), vfs::default_inode_ops(), vfs::default_file_ops()).build()
}

// The global hashtable + in-lookup table are process-wide; serialize.
static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

#[test]
fn leader_then_waiter_share_one_lookup() {
    let _g = guard();
    let r = Dentry::new_root(dir(1));
    // Walker A misses the fast path, becomes the leader.
    assert!(d_lookup(&r, "f").is_none());
    let leader = match d_alloc_parallel(&r, "f") {
        DParLookup::Leader(d) => d,
        DParLookup::Waiter(_) => panic!("first caller must be the leader"),
    };
    assert!(leader.is_in_lookup(), "placeholder carries D_PAR_LOOKUP");
    assert!(leader.is_negative(), "placeholder starts negative");
    assert!(leader.is_unhashed(), "placeholder is NOT hashed until published");

    // Walker B for the SAME key becomes a waiter sharing the placeholder —
    // it does NOT launch a second i_op->lookup.
    let waiter = match d_alloc_parallel(&r, "f") {
        DParLookup::Waiter(d) => d,
        DParLookup::Leader(_) => panic!("concurrent caller must wait, not lead"),
    };
    assert!(Arc::ptr_eq(&leader, &waiter), "waiter shares the leader's single placeholder");
    assert!(waiter.is_in_lookup(), "wake gate still set while leader resolves");

    // Leader resolves (lookup hit) and publishes.
    d_instantiate(&leader, dir(50));
    let canon = d_lookup_done(&leader);
    assert!(!leader.is_in_lookup(), "wake gate cleared — waiters released");
    assert!(canon.is_hashed(), "published placeholder is now hashed");
    assert!(Arc::ptr_eq(&canon, &waiter), "the published dentry IS the shared one");

    // The cache hit returns the same shared, now-positive dentry.
    let hit = d_lookup(&r, "f").expect("published placeholder is cache-visible");
    assert!(Arc::ptr_eq(&hit, &leader));
    assert!(!hit.is_negative());
}

#[test]
fn distinct_keys_both_lead() {
    let _g = guard();
    let r = Dentry::new_root(dir(2));
    let a = match d_alloc_parallel(&r, "a") { DParLookup::Leader(d) => d, _ => panic!("a leads") };
    let b = match d_alloc_parallel(&r, "b") { DParLookup::Leader(d) => d, _ => panic!("b leads") };
    assert!(!Arc::ptr_eq(&a, &b), "different names are independent lookups");
    d_lookup_done(&a);
    d_lookup_done(&b);
}

#[test]
fn leader_negative_result_publishes_cached_miss() {
    let _g = guard();
    let r = Dentry::new_root(dir(3));
    let leader = match d_alloc_parallel(&r, "absent") { DParLookup::Leader(d) => d, _ => panic!("leads") };
    // i_op->lookup returned ENOENT: leave it negative, publish as a cached miss.
    let canon = d_lookup_done(&leader);
    assert!(canon.is_negative());
    assert!(canon.is_hashed());
    let hit = d_lookup(&r, "absent").expect("cached negative is visible");
    assert!(hit.is_negative());
    assert!(Arc::ptr_eq(&hit, &leader));
}

#[test]
fn adopts_already_published_key() {
    // If a prior leader already published the key into the main hash before this
    // caller runs, adopt it as a waiter — no redundant lookup launched.
    let _g = guard();
    let r = Dentry::new_root(dir(4));
    let l = match d_alloc_parallel(&r, "x") { DParLookup::Leader(d) => d, _ => panic!("leads") };
    d_instantiate(&l, dir(60));
    let published = d_lookup_done(&l);
    match d_alloc_parallel(&r, "x") {
        DParLookup::Waiter(d) => assert!(Arc::ptr_eq(&d, &published), "adopt the published dentry"),
        DParLookup::Leader(_) => panic!("must adopt the already-published dentry, not relead"),
    }
}
