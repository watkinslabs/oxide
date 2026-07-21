extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Dentry as DentryClass, Spinlock};

use crate::dentry::Dentry;

// ---------------------------------------------------------------------------
// Global dentry hash table (`16§96`). Power-of-2 buckets; index = low bits of
// the precomputed `full_name_hash` (parent already folded into the hash by
// `Dentry::compute_hash`, so bucketing on `hash` alone keys on (parent,name)).
// ---------------------------------------------------------------------------

const DHASH_BITS:     usize = 8;            // 256 buckets — hosted/test scale
const DHASH_NBUCKETS: usize = 1 << DHASH_BITS;
const DHASH_MASK:     u32   = (DHASH_NBUCKETS - 1) as u32;

/// One hash bucket: a seqcount (even = quiescent, odd = writer in progress)
/// + the spinlock-guarded ownership chain. Hash membership is a durable
/// dcache reference: a published dentry remains allocated until `d_drop`
/// removes that membership, as Linux keeps a hashed dentry linked until
/// `__d_drop` under the bucket lock. The seqcount lets the read path validate
/// its snapshot (Linux `__d_lookup_rcu` seqcount).
pub(super) struct Bucket {
    seq:     AtomicU32,
    pub(super) entries: Spinlock<Vec<Arc<Dentry>>, DentryClass>,
}

pub(super) struct DentryHashTable {
    pub(super) buckets: [Bucket; DHASH_NBUCKETS],
}

/// Result of the lock-free (`rcu`) probe: `Ok` = authoritative (hit/miss),
/// `Err` = writer raced, retry under the bucket lock.
pub(super) enum RcuProbe { Done(Option<Arc<Dentry>>), Retry }

impl DentryHashTable {
    const fn new() -> Self {
        DentryHashTable {
            buckets: [const { Bucket { seq: AtomicU32::new(0), entries: Spinlock::new(Vec::new()) } }; DHASH_NBUCKETS],
        }
    }

    fn bucket(&self, hash: u32) -> &Bucket { &self.buckets[(hash & DHASH_MASK) as usize] }

    /// Hash `d` into the table (idempotent by `Arc` identity). The bucket owns
    /// one durable dcache reference until [`remove`] performs Linux `__d_drop`.
    /// Sets `D_HASHED`. # C: O(bucket_len)
    pub(super) fn insert(&self, d: &Arc<Dentry>) {
        let b = self.bucket(d.d_hash());
        let dptr = Arc::as_ptr(d);
        let mut g = b.entries.lock();
        b.seq.fetch_add(1, Ordering::Release); // begin (odd)
        let mut present = false;
        for e in g.iter() {
            if Arc::as_ptr(e) == dptr { present = true; break; }
        }
        if !present { g.push(Arc::clone(d)); }
        b.seq.fetch_add(1, Ordering::Release); // end (even)
        drop(g);
        d.set_hashed(true);
    }

    /// Unhash `d` (Linux `__d_drop`). Clears `D_HASHED`. # C: O(bucket_len)
    pub(super) fn remove(&self, d: &Dentry) {
        let b = self.bucket(d.d_hash());
        let dptr = d as *const Dentry;
        let mut g = b.entries.lock();
        b.seq.fetch_add(1, Ordering::Release);
        g.retain(|e| Arc::as_ptr(e) != dptr);
        b.seq.fetch_add(1, Ordering::Release);
        drop(g);
        d.set_hashed(false);
    }

    /// Locked ref-walk (Linux `__d_lookup`). # C: O(bucket_len)
    pub(super) fn lookup_locked(&self, parent: *const Dentry, qhash: u32, name: &str) -> Option<Arc<Dentry>> {
        let b = self.bucket(qhash);
        let g = b.entries.lock();
        for e in g.iter() {
            if e.key_matches(parent, qhash, name) { return Some(Arc::clone(e)); }
        }
        None
    }

    /// Lock-free seqcount-gated probe (Linux `__d_lookup_rcu`). The bucket
    /// lock is held only to snapshot the dcache-owned `Arc` chain (cheap
    /// refcount bumps); the `key_matches` walk runs lock-free and is validated
    /// by the seqcount — if a writer mutated the bucket meanwhile, retry under
    /// the lock. The bucket's durable `Arc` is the Rust lifetime equivalent of
    /// Linux's hash-link + RCU lifetime: readers never inspect an expired,
    /// non-owning control block.
    /// # C: O(bucket_len)
    pub(super) fn lookup_rcu(&self, parent: *const Dentry, qhash: u32, name: &str) -> RcuProbe {
        let b = self.bucket(qhash);
        let (s1, snap) = {
            let g = b.entries.lock();
            (b.seq.load(Ordering::Acquire), g.clone())
        };
        if s1 & 1 != 0 { return RcuProbe::Retry; } // snapshot taken mid-write
        let mut found = None;
        for e in snap.iter() {
            if e.key_matches(parent, qhash, name) { found = Some(Arc::clone(e)); break; }
        }
        if b.seq.load(Ordering::Acquire) != s1 { return RcuProbe::Retry; }
        RcuProbe::Done(found)
    }
}

pub(super) static DENTRY_HASHTABLE: DentryHashTable = DentryHashTable::new();
