extern crate alloc;
use alloc::sync::Arc;
use alloc::boxed::Box;

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

struct HashNode {
    next: core::sync::atomic::AtomicPtr<HashNode>,
    dentry: Arc<Dentry>,
}

/// One hash bucket: writers serialize insertion/removal, while readers follow
/// the published chain under an RCU read-side section. Hash membership owns
/// one dentry reference until the removed node passes a grace period.
pub(super) struct Bucket {
    lock: Spinlock<(), DentryClass>,
    head: core::sync::atomic::AtomicPtr<HashNode>,
}

pub(super) struct DentryHashTable {
    pub(super) buckets: [Bucket; DHASH_NBUCKETS],
}

impl DentryHashTable {
    const fn new() -> Self {
        DentryHashTable {
            buckets: [const { Bucket {
                lock: Spinlock::new(()),
                head: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            } }; DHASH_NBUCKETS],
        }
    }

    fn bucket(&self, hash: u32) -> &Bucket { &self.buckets[(hash & DHASH_MASK) as usize] }

    #[cfg(test)]
    pub(super) fn bucket_len(bucket: &Bucket) -> usize {
        let _g = bucket.lock.lock();
        let mut n = 0;
        let mut node = bucket.head.load(core::sync::atomic::Ordering::Acquire);
        while !node.is_null() {
            n += 1;
            // SAFETY: the bucket lock prevents unlink and reclamation while
            // the test counts the published chain.
            node = unsafe { (*node).next.load(core::sync::atomic::Ordering::Acquire) };
        }
        n
    }

    /// Hash `d` into the table (idempotent by `Arc` identity). The bucket owns
    /// one durable dcache reference until [`remove`] performs Linux `__d_drop`.
    /// Sets `D_HASHED`. # C: O(bucket_len)
    pub(super) fn insert(&self, d: &Arc<Dentry>) {
        let b = self.bucket(d.d_hash());
        let dptr = Arc::as_ptr(d);
        let _g = b.lock.lock();
        let mut node = b.head.load(core::sync::atomic::Ordering::Acquire);
        while !node.is_null() {
            // SAFETY: the writer lock excludes node removal, and RCU
            // retirement keeps every published node allocated after unlink.
            if unsafe { Arc::as_ptr(&(*node).dentry) } == dptr { d.set_hashed(true); return; }
            // SAFETY: the current node is protected by the writer lock while
            // its published next link is read.
            node = unsafe { (*node).next.load(core::sync::atomic::Ordering::Acquire) };
        }
        let new = Box::into_raw(Box::new(HashNode {
            next: core::sync::atomic::AtomicPtr::new(b.head.load(core::sync::atomic::Ordering::Acquire)),
            dentry: Arc::clone(d),
        }));
        b.head.store(new, core::sync::atomic::Ordering::Release);
        d.set_hashed(true);
    }

    /// Unhash `d` (Linux `__d_drop`). Clears `D_HASHED`. # C: O(bucket_len)
    pub(super) fn remove(&self, d: &Dentry) {
        let b = self.bucket(d.d_hash());
        let dptr = d as *const Dentry;
        let _g = b.lock.lock();
        let mut prev: *mut HashNode = core::ptr::null_mut();
        let mut node = b.head.load(core::sync::atomic::Ordering::Acquire);
        while !node.is_null() {
            // SAFETY: the writer lock excludes unlink, and RCU defers node
            // reclamation until readers that saw it have quiesced.
            let next = unsafe { (*node).next.load(core::sync::atomic::Ordering::Acquire) };
            // SAFETY: the node remains published and alive under the writer
            // lock while its owned dentry pointer is compared.
            if unsafe { Arc::as_ptr(&(*node).dentry) } == dptr {
                if prev.is_null() { b.head.store(next, core::sync::atomic::Ordering::Release); }
                else {
                    // SAFETY: prev is a node reached from this bucket under
                    // the same writer lock, so its link can be unlinked here.
                    unsafe { (*prev).next.store(next, core::sync::atomic::Ordering::Release); }
                }
                let addr = node as usize;
                sync::call_rcu(Box::new(move || {
                    // SAFETY: the node was unlinked before this callback was
                    // queued, and the grace period protects all readers.
                    unsafe { drop(Box::from_raw(addr as *mut HashNode)); }
                }));
                break;
            }
            prev = node;
            node = next;
        }
        d.set_hashed(false);
    }

    /// Chain walk under the bucket lock (Linux `__d_lookup`), taking exactly
    /// one reference on a hit. The RCU read section covers node retirement;
    /// the bucket lock remains the writer/read serialization for this path.
    /// # C: O(bucket_len)
    pub(super) fn lookup_locked(&self, parent: *const Dentry, qhash: u32, name: &str) -> Option<Arc<Dentry>> {
        let _rcu = sync::rcu_read_lock();
        let b = self.bucket(qhash);
        let _g = b.lock.lock();
        let mut node = b.head.load(core::sync::atomic::Ordering::Acquire);
        while !node.is_null() {
            // SAFETY: the writer lock prevents unlink and node reclamation in
            // this locked compatibility path.
            let e = unsafe { &(*node).dentry };
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
            // SAFETY: the writer lock keeps this node allocated while its
            // published next link is read.
            node = unsafe { (*node).next.load(core::sync::atomic::Ordering::Acquire) };
        }
        None
    }

    /// RCU dentry probe for the lazy pathname walk. The returned Arc is
    /// cloned before the guard leaves, so the caller owns the dentry after the
    /// hash node becomes eligible for retirement. # C: O(bucket_len)
    pub(super) fn lookup_rcu(&self, parent: *const Dentry, qhash: u32, name: &str) -> Option<Arc<Dentry>> {
        let _rcu = sync::rcu_read_lock();
        let b = self.bucket(qhash);
        let mut node = b.head.load(core::sync::atomic::Ordering::Acquire);
        while !node.is_null() {
            // SAFETY: RCU keeps an unlinked node allocated until this guard
            // drops, and acquire observes initialized node contents.
            let e = unsafe { &(*node).dentry };
            if !e.is_hashed() {
                // SAFETY: the node remains allocated under RCU while the
                // unhashed dentry is skipped.
                node = unsafe { (*node).next.load(core::sync::atomic::Ordering::Acquire) };
                continue;
            }
            if e.key_matches(parent, qhash, name) {
                let found = Arc::clone(e);
                if found.is_hashed() { return Some(found); }
            }
            // SAFETY: every next link was published before this node became
            // reachable, and RCU protects the link's storage from reclaim.
            node = unsafe { (*node).next.load(core::sync::atomic::Ordering::Acquire) };
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
        let _g = b.lock.lock();
        let mut node = b.head.load(core::sync::atomic::Ordering::Acquire);
        while !node.is_null() {
            // SAFETY: the bucket lock prevents unlink and node reclamation
            // while this diagnostic inspects the owned dentry.
            let d = unsafe { &(*node).dentry };
            if let Some(o) = d.d_op() {
                let addr = o as *const crate::dentry::DentryOps as u64;
                if addr < hal::USER_VA_END {
                    return Some((Arc::as_ptr(d) as u64, addr));
                }
            }
            // SAFETY: the bucket lock keeps the current node alive while its
            // published link is read.
            node = unsafe { (*node).next.load(core::sync::atomic::Ordering::Acquire) };
        }
    }
    None
}
