extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Dentry as DentryClass, Spinlock};

use crate::dentry::Dentry;

// ---------------------------------------------------------------------------
// Global dentry hash table (`16§96`). Power-of-2 buckets; index = low bits of
// the precomputed `full_name_hash` (parent already folded into the hash by
// `Dentry::compute_hash`, so bucketing on `hash` alone keys on (parent,name)).
// ---------------------------------------------------------------------------

// Bucket count. The reference sizes this from memory in
// `alloc_large_system_hash` — one bucket per 8 KiB of kernel memory — which on
// a machine of this class lands between 2^16 and 2^19. It was 256 here, sized
// "hosted/test scale": a desktop holds tens of thousands of live dentries, so
// every bucket became a chain of hundreds and every name lookup walked it.
// 2^16 keeps the chains at a handful of entries on that working set.
const DHASH_BITS:     usize = 16;
const DHASH_NBUCKETS: usize = 1 << DHASH_BITS;
const DHASH_MASK:     u32   = (DHASH_NBUCKETS - 1) as u32;

/// One hash bucket: the spinlock-guarded ownership chain. Hash membership is a
/// durable dcache reference: a published dentry remains allocated until
/// `d_drop` removes that membership, as Linux keeps a hashed dentry linked
/// until `__d_drop` under the bucket lock.
pub(super) struct Bucket {
    pub(super) entries: Spinlock<Vec<Arc<Dentry>>, DentryClass>,
}

pub(super) struct DentryHashTable {
    pub(super) buckets: [Bucket; DHASH_NBUCKETS],
}

impl DentryHashTable {
    const fn new() -> Self {
        DentryHashTable {
            buckets: [const { Bucket { entries: Spinlock::new(Vec::new()) } }; DHASH_NBUCKETS],
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
        let mut present = false;
        for e in g.iter() {
            if Arc::as_ptr(e) == dptr { present = true; break; }
        }
        if !present { g.push(Arc::clone(d)); }
        drop(g);
        d.set_hashed(true);
    }

    /// Unhash `d` (Linux `__d_drop`). Clears `D_HASHED`. # C: O(bucket_len)
    pub(super) fn remove(&self, d: &Dentry) {
        let b = self.bucket(d.d_hash());
        let dptr = d as *const Dentry;
        let mut g = b.entries.lock();
        g.retain(|e| Arc::as_ptr(e) != dptr);
        drop(g);
        d.set_hashed(false);
    }

    /// Chain walk under the bucket lock (Linux `__d_lookup`), taking exactly
    /// one reference, on the hit.
    ///
    /// There used to be a second "rcu" probe in front of this one that
    /// snapshotted the bucket — `entries.lock().clone()` — and walked the copy
    /// outside the lock under a seqcount. The reference's `__d_lookup_rcu`
    /// walks the live chain and copies nothing; ours put a heap allocation
    /// plus a refcount increment AND decrement per resident entry on every
    /// `d_lookup`, which is the hot path of every component of every path
    /// resolution. Without an RCU-safe chain walk this locked form is both the
    /// correct shape and the cheap one.
    /// # C: O(bucket_len)
    pub(super) fn lookup_locked(&self, parent: *const Dentry, qhash: u32, name: &str) -> Option<Arc<Dentry>> {
        let b = self.bucket(qhash);
        let g = b.entries.lock();
        for e in g.iter() {
            if e.key_matches(parent, qhash, name) {
                // Corruption-hunt guard (state.md): a live sample this session
                // found Arc::clone's own internal refcount-overflow abort()
                // firing here with zero diagnostic output — the strong count
                // had been corrupted (most likely to a small negative value,
                // by something entirely outside dcache) before Rust's std
                // trapped on it. Check first so a corrupted count prints the
                // dentry's address and the bad count before panicking, instead
                // of an opaque ud2. One atomic load; negligible cost on the
                // hit path.
                let sc = Arc::strong_count(e);
                if sc < 1 || sc >= (1 << 32) {
                    klog::write_raw(b"[DENTRY-REFCOUNT] corrupted strong_count dentry=0x");
                    klog::write_hex_u64(Arc::as_ptr(e) as u64);
                    klog::write_raw(b" strong_count=0x");
                    klog::write_hex_u64(sc as u64);
                    klog::write_raw(b"\n");
                }
                hal::kassert!(sc >= 1 && sc < (1 << 32), "dcache: corrupted Arc strong count on lookup hit");
                return Some(Arc::clone(e));
            }
        }
        None
    }

}

pub(super) static DENTRY_HASHTABLE: DentryHashTable = DentryHashTable::new();

/// Diagnostic-only (`debug-heappoison`): scan every currently-hashed dentry
/// for a corrupted `d_op` (mirrors the live-object hardening check in
/// `Dentry::drop`, `dentry/lifecycle.rs`). A live `Dentry` sits in the dcache
/// hash table from creation until unhashed, so this catches a corrupted
/// `d_op` WHILE the dentry is still alive, instead of only discovering it
/// whenever that dentry's refcount happens to hit zero (which can be
/// arbitrarily later than the corrupting write). Call from a periodic
/// checkpoint to narrow the corruption's timing window. Returns the first
/// bad `(dentry_addr, d_op_addr)` found, or `None`. # C: O(total hashed dentries)
#[cfg(feature = "debug-heappoison")]
pub fn debug_scan_d_op_sanity() -> Option<(u64, u64)> {
    for b in DENTRY_HASHTABLE.buckets.iter() {
        // SAFETY: none — this clones the bucket's Arc chain under its own
        // lock, then inspects each dentry's d_op with no other lock held.
        let snap = { b.entries.lock().clone() };
        for d in snap.iter() {
            if let Some(o) = d.d_op() {
                let addr = o as *const crate::dentry::DentryOps as u64;
                if addr < hal::USER_VA_END {
                    return Some((Arc::as_ptr(d) as u64, addr));
                }
            }
        }
    }
    None
}
