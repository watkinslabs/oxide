extern crate alloc;
use super::*;
use super::hash::{DENTRY_HASHTABLE, RcuProbe};
use alloc::sync::Arc;
use crate::dentry::{Dentry, DentryOps, D_HASHED, D_NEGATIVE, D_OP_WEAK_REVALIDATE};
use core::sync::atomic::{AtomicBool, Ordering};
use crate::inode::{Inode, InodeBuilder, InodeRef};
use crate::inode_ops::{mk_mode, InodeOps};
use crate::file_ops::default_file_ops;
use crate::types::{FileType, KResult, VfsError};
use alloc::string::String;
use alloc::format;
use alloc::vec::Vec;

// Minimal directory inode for positive-dentry tests. `i_sb` defaults to
// None so no superblock/alias machinery is needed; `lookup` → Enoent.
struct DirOps;
impl InodeOps for DirOps {
fn lookup(&self, _inode: &Inode, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn dir(ino: u64) -> InodeRef {
InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(DirOps), default_file_ops()).build()
}

fn root() -> Arc<Dentry> { Dentry::new_root(dir(1)) }

// hashed == tree: every (parent,name) added is found by the global table
// and the table returns the SAME Arc as the per-parent d_subdirs index.
#[test]
fn global_hash_agrees_with_tree() {
let r = root();
let mut names: Vec<String> = Vec::new();
for i in 0..200u32 { names.push(format!("child{i}")); }
for (i, n) in names.iter().enumerate() {
        if i % 2 == 0 { d_add(&r, n, dir(100 + i as u64)); } else { d_add_negative(&r, n); }
}
for n in &names {
        let via_table = d_lookup(&r, n).expect("table hit");
        let via_tree  = r.cached_child(n).expect("tree hit");
        assert!(Arc::ptr_eq(&via_table, &via_tree), "table != tree for {n}");
        assert!(via_table.is_hashed());
}
    // Uncached name misses.
assert!(d_lookup(&r, "absent").is_none());
}

// The locked walk and the rcu (seqcount) probe return the same dentry.
#[test]
fn rcu_path_agrees_with_locked() {
let r = root();
for i in 0..64u32 { d_add(&r, &format!("f{i}"), dir(200 + i as u64)); }
for i in 0..64u32 {
        let n = format!("f{i}");
        let qhash = Dentry::compute_hash(Some(&r), &n);
        let pptr = Arc::as_ptr(&r);
        let locked = DENTRY_HASHTABLE.lookup_locked(pptr, qhash, &n).unwrap();
        let rcu = match DENTRY_HASHTABLE.lookup_rcu(pptr, qhash, &n) {
            RcuProbe::Done(c) => c.unwrap(),
            RcuProbe::Retry   => DENTRY_HASHTABLE.lookup_locked(pptr, qhash, &n).unwrap(),
        };
        assert!(Arc::ptr_eq(&locked, &rcu));
}
}

// A published dcache entry is owned by its hash bucket until d_drop. Linux
// keeps the dentry hash link live until __d_drop; using a Weak here lets a
// bucket retain an expired/non-owning control block during a lookup snapshot.
#[test]
fn hash_membership_owns_dentry_until_drop() {
let r = root();
let child = Dentry::new_child(&r, "hash-owner", None);
let weak = Arc::downgrade(&child);
let qhash = child.d_hash();
let pptr = Arc::as_ptr(&r);
DENTRY_HASHTABLE.insert(&child);
drop(child);
let published = DENTRY_HASHTABLE.lookup_locked(pptr, qhash, "hash-owner").expect("hash owns published dentry");
assert!(weak.upgrade().is_some(), "published dentry survives external references");
DENTRY_HASHTABLE.remove(&published);
drop(published);
assert!(weak.upgrade().is_none(), "d_drop releases the hash ownership reference");
}

// O(1): with 256 buckets and 256 random keys, no bucket should hold more
// than a small constant chain (uniform hash ⇒ bounded chain length).
#[test]
fn lookup_is_o1_bounded_chains() {
let r = root();
for i in 0..256u32 { d_add_negative(&r, &format!("e{i}")); }
let max = DENTRY_HASHTABLE.buckets.iter()
        .map(|b| b.entries.lock().len())
        .max().unwrap_or(0);
assert!(max <= 12, "max chain {max} too long — not O(1)");
}

// d_compare / d_hash hook: case-insensitive lookup hits a lower-case entry.
static CI_OPS: DentryOps = DentryOps {
d_hash:    Some(|name| {
        let mut h: u64 = 0xcbf29ce484222325;
        for b in name.bytes() { h = (h ^ (b.to_ascii_lowercase() as u64)).wrapping_mul(0x100000001B3); }
        (h ^ (h >> 32)) as u32
}),
d_compare: Some(|name, cand| name.eq_ignore_ascii_case(cand.name())),
d_revalidate: None, d_weak_revalidate: None, d_delete: None, d_release: None, d_iput: None, d_dname: None, d_init: None, d_prune: None,
};
#[test]
fn d_compare_case_insensitive() {
let r = Dentry::new_root(dir(1)).set_d_op(&CI_OPS);
d_add(&r, "foo", dir(7));
let hit = d_lookup(&r, "FOO").expect("case-insensitive hit");
assert_eq!(hit.name(), "foo");
let hit2 = d_lookup(&r, "FoO").expect("case-insensitive hit2");
assert!(Arc::ptr_eq(&hit, &hit2));
}

// d_revalidate: a stale dentry is dropped on lookup.
static STALE_OPS: DentryOps = DentryOps {
d_revalidate: Some(|_d, _reval| false), // everything is stale
d_weak_revalidate: None,
d_hash: None, d_compare: None, d_delete: None, d_release: None, d_iput: None, d_dname: None, d_init: None, d_prune: None,
};
#[test]
fn d_revalidate_drops_stale() {
let r = Dentry::new_root(dir(1)).set_d_op(&STALE_OPS);
d_add_negative(&r, "x");
assert!(d_lookup(&r, "x").is_none(), "stale dentry must be dropped");
    // and it was unhashed
let qhash = Dentry::compute_hash(Some(&r), "x");
assert!(DENTRY_HASHTABLE.lookup_locked(Arc::as_ptr(&r), qhash, "x").is_none());
}

// lockref d_count: dget/dput balance; at 0 the dentry joins the LRU.
#[test]
fn lockref_count_and_lru() {
let r = root();
let c = d_add_negative(&r, "n");
assert_eq!(c.d_count(), 0);
let g = dget(&c);
assert_eq!(c.d_count(), 1);
assert!(!c.is_on_lru());
    dput(g);
assert_eq!(c.d_count(), 0);
assert!(c.is_on_lru(), "unused dentry must be on the LRU");
}

// shrink_dcache evicts unused negatives; referenced/in-use survive.
#[test]
fn shrink_evicts_unused_negatives() {
let r = root();
    // 100 unused negatives -> all eligible after dput-to-0.
let mut kids = Vec::new();
for i in 0..100u32 {
        let c = d_add_negative(&r, &format!("neg{i}"));
        let g = dget(&c);  // count 1
        dput(g);           // back to 0 -> LRU, referenced bit set by dget
        kids.push(c);
}
    // First shrink pass: all are referenced (dget set the bit) -> rotated,
    // bit cleared, nothing freed.
let first = shrink_dcache(100);
assert_eq!(first, 0);
    // One in-use dentry must never be evicted.
let pinned = d_add_negative(&r, "pinned");
let _hold = dget(&pinned); // count 1
    // Second pass: bits cleared -> evict unused negatives.
let freed = shrink_dcache(200);
assert!(freed >= 90, "expected most negatives evicted, got {freed}");
    // Evicted ones are unhashed + forgotten by the parent.
let mut gone = 0;
for (i, _c) in kids.iter().enumerate() {
        if r.cached_child(&format!("neg{i}")).is_none() { gone += 1; }
}
assert!(gone >= 90);
assert!(pinned.d_count() > 0);
assert!(r.cached_child("pinned").is_some(), "in-use dentry survived");
}

// d_invalidate unhashes a whole subtree.
#[test]
fn d_invalidate_subtree() {
let r = root();
let a = d_add(&r, "a", dir(10));
let b = d_add(&a, "b", dir(11));
let _c = d_add(&b, "c", dir(12));
assert!(d_lookup(&r, "a").is_some());
assert!(d_lookup(&a, "b").is_some());
assert!(d_lookup(&b, "c").is_some());
d_invalidate(&a);
assert!(d_lookup(&r, "a").is_none());
assert!(d_lookup(&a, "b").is_none());
assert!(d_lookup(&b, "c").is_none());
assert_eq!(a.flags() & D_HASHED, 0);
}

// d_move rehomes under a new (parent,name) key.
#[test]
fn d_move_rehomes() {
let r = root();
let p2 = d_add(&r, "dst", dir(20));
d_add(&r, "old", dir(21));
assert!(d_lookup(&r, "old").is_some());
let moved = d_move(&d_lookup(&r, "old").unwrap(), &p2, "new");
assert!(d_lookup(&r, "old").is_none());
let hit = d_lookup(&p2, "new").unwrap();
assert!(Arc::ptr_eq(&hit, &moved));
}

// shrink_dcache_parent prunes the unused subtree but pins the path to an
// in-use descendant.
#[test]
fn shrink_dcache_parent_prunes_unused_pins_in_use() {
let r = root();
let a = d_add(&r, "a", dir(10));
let b = d_add(&a, "b", dir(11));
let c = d_add(&b, "c", dir(12));
let _d = d_add(&a, "d", dir(13));
    // Nothing held -> whole subtree under `a` pruned, `a` survives.
let r2 = root();
let a2 = d_add(&r2, "a", dir(20));
let b2 = d_add(&a2, "b", dir(21));
let _c2 = d_add(&b2, "c", dir(22));
assert_eq!(shrink_dcache_parent(&a2), 2);
assert!(a2.children_snapshot().is_empty());
assert!(d_lookup(&r2, "a").is_some());
    // Pin `c` -> `b` survives, sibling `d` pruned.
let hold = dget(&c);
let freed = shrink_dcache_parent(&a);
assert_eq!(freed, 1, "only unused sibling d");
assert!(a.cached_child("b").is_some());
assert!(b.cached_child("c").is_some());
assert!(a.cached_child("d").is_none());
    dput(hold);
}

// set_inode flips D_NEGATIVE and fires d_iput on disassociation.
#[test]
fn negative_to_positive_flags() {
let r = root();
let c = d_add_negative(&r, "z");
assert_ne!(c.flags() & D_NEGATIVE, 0);
    c.set_inode(Some(dir(30)));
assert_eq!(c.flags() & D_NEGATIVE, 0);
assert!(!c.is_negative());
}

// Regression for object-parent invalidation after inode-op-direct create paths
// (AF_UNIX bind mknod_child, etc.): an earlier failed lookup may leave a
// NEGATIVE child cached under the exact parent. Dropping that child must make
// d_lookup miss so the next walk re-reads the parent and instantiates the node.
#[test]
fn drop_negative_forces_relookup() {
let r = root();
let neg = d_add_negative(&r, "sock");
assert!(neg.is_negative());
assert!(d_lookup(&r, "sock").is_some(), "negative is cached and returned");
    d_drop(&neg);
assert!(d_lookup(&r, "sock").is_none(), "dropped negative no longer shadows the name");
}

// d_weak_revalidate (Linux `complete_walk` final-dentry hook): the presence
// bit is stamped, the hook fires with the `LOOKUP_REVAL` flag threaded, and a
// STALE weak result does NOT drop the dentry (unlike per-component
// d_revalidate) — only this resolution is rejected.
static WEAK_SAW_REVAL: AtomicBool = AtomicBool::new(false);
static WEAK_VALID:     AtomicBool = AtomicBool::new(true);
fn weak_rev(_d: &Arc<Dentry>, reval: bool) -> bool {
WEAK_SAW_REVAL.store(reval, Ordering::SeqCst);
WEAK_VALID.load(Ordering::SeqCst)
}
static WEAK_OPS: DentryOps = DentryOps {
d_weak_revalidate: Some(weak_rev),
d_hash: None, d_compare: None, d_revalidate: None, d_delete: None,
d_release: None, d_iput: None, d_dname: None, d_init: None, d_prune: None,
};
#[test]
fn d_weak_revalidate_hook_and_no_drop() {
    // Presence bit stamped from the non-NULL hook (d_set_d_op).
let r = Dentry::new_root(dir(1)).set_d_op(&WEAK_OPS);
assert_ne!(r.flags() & D_OP_WEAK_REVALIDATE, 0);
assert!(r.d_has_op_weak_revalidate());
let c = d_add(&r, "leaf", dir(40)); // child inherits WEAK_OPS via new_child
assert!(c.d_has_op_weak_revalidate());
assert!(c.is_hashed());

    // Valid path: hook returns true; `reval` flag is threaded through.
WEAK_VALID.store(true, Ordering::SeqCst);
assert!(d_weak_revalidate(&c, true));
assert!(WEAK_SAW_REVAL.load(Ordering::SeqCst), "LOOKUP_REVAL threaded");
assert!(d_weak_revalidate(&c, false));
assert!(!WEAK_SAW_REVAL.load(Ordering::SeqCst));

    // Stale path: hook returns false, but the dentry stays a valid cache node
    // (still hashed, still found by d_lookup) — complete_walk rejects the
    // resolution without unhashing, unlike d_lookup_reval's d_drop.
WEAK_VALID.store(false, Ordering::SeqCst);
assert!(!d_weak_revalidate(&c, false));
assert!(c.is_hashed(), "weak-stale must NOT unhash the dentry");
assert!(d_lookup(&r, "leaf").is_some(), "dentry still cached after weak-stale");

    // A dentry with no weak hook is always valid, no deref.
let plain = root();
assert!(!plain.d_has_op_weak_revalidate());
assert!(d_weak_revalidate(&plain, true));
}
