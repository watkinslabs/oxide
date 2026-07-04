extern crate alloc;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use sync::{Dentry as DentryClass, Spinlock};

use crate::dentry::Dentry;

use super::hash::DENTRY_HASHTABLE;

// ---------------------------------------------------------------------------
// In-lookup table (`16§2`, Linux `in_lookup_hashtable` / `d_alloc_parallel`).
// Holds the PLACEHOLDER dentries of (parent,name) lookups CURRENTLY IN FLIGHT,
// so two walkers that miss the main hash for the SAME key do not each build a
// dentry and run `i_op->lookup` then race in `cache_child` (D27 efficiency gap):
// the first becomes the LEADER (its placeholder goes here, flagged
// `D_PAR_LOOKUP`), the rest become WAITERS that block on the placeholder's
// `D_PAR_LOOKUP` bit and share the leader's single lookup. Entries live only
// between `d_alloc_parallel` and `d_lookup_done`. `Weak` so a crashed/leaked
// leader can't pin the table; dead weaks self-prune on probe.
// ---------------------------------------------------------------------------

static IN_LOOKUP: Spinlock<Vec<Weak<Dentry>>, DentryClass> = Spinlock::new(Vec::new());

/// Outcome of [`d_alloc_parallel`] — which role the caller plays in the
/// in-flight lookup of one (parent,name).
pub enum DParLookup {
    /// This caller WON the race and owns the in-flight placeholder (flagged
    /// `D_PAR_LOOKUP`, NOT yet hashed). It MUST run the slow `i_op->lookup`,
    /// `d_instantiate` the placeholder if the name resolved (leave it negative
    /// otherwise), then call [`d_lookup_done`] to publish + wake waiters.
    Leader(Arc<Dentry>),
    /// Another caller is already resolving this key; this is that SHARED
    /// placeholder. The caller must NOT run its own `i_op->lookup` — it waits
    /// for `is_in_lookup()` to clear (Linux `d_wait_lookup`) and then uses the
    /// now-published dentry. In the cooperative kernel walker the wait is a
    /// `D_PAR_LOOKUP` wait-queue sleep; the primitive only exposes the gate.
    Waiter(Arc<Dentry>),
}

/// Begin a PARALLEL lookup of `(parent, name)` (Linux `d_alloc_parallel`).
/// Re-checks the main hash + the in-lookup table under one lock: if another
/// walker is already resolving this key, returns [`DParLookup::Waiter`] sharing
/// that in-flight placeholder; otherwise installs a fresh `D_PAR_LOOKUP`
/// placeholder and returns [`DParLookup::Leader`]. Only the leader runs the
/// slow `i_op->lookup`; concurrent walkers no longer each construct + race a
/// dentry (D27). The caller is expected to have already missed [`d_lookup`]
/// (the fast path) before calling this. # C: O(bucket_len + in_lookup_len)
pub fn d_alloc_parallel(parent: &Arc<Dentry>, name: &str) -> DParLookup {
    let qhash = Dentry::compute_hash(Some(parent), name);
    let pptr = Arc::as_ptr(parent);
    let mut g = IN_LOOKUP.lock();
    // An in-flight placeholder for this key already present ⇒ become a waiter.
    g.retain(|w| w.upgrade().is_some()); // prune dead leaders
    for w in g.iter() {
        if let Some(e) = w.upgrade() {
            if e.is_in_lookup() && e.key_matches(pptr, qhash, name) {
                return DParLookup::Waiter(e);
            }
        }
    }
    // The key may have been published into the main hash since the caller's
    // fast-path miss (a leader finished between then and now) — adopt it rather
    // than launch a redundant lookup. Hashed result ⇒ already resolved.
    if let Some(existing) = DENTRY_HASHTABLE.lookup_locked(pptr, qhash, name) {
        return DParLookup::Waiter(existing);
    }
    // We are the leader: install an unhashed placeholder under D_PAR_LOOKUP.
    let placeholder = Dentry::new_child(parent, name, None);
    placeholder.set_par_lookup(true);
    g.push(Arc::downgrade(&placeholder));
    DParLookup::Leader(placeholder)
}

/// Publish a leader's resolved placeholder and wake its waiters (Linux
/// `__d_lookup_done` + the `__d_add` rehash tail). Clears `D_PAR_LOOKUP` (the
/// waiters' wake gate), removes the placeholder from the in-lookup table, caches
/// it under its parent's `d_subdirs`, and hashes it into the global table — so a
/// subsequent [`d_lookup`] of the key hits it. Call AFTER the leader has
/// `d_instantiate`-d the placeholder (positive result) or left it negative
/// (cached miss). Returns the canonical dentry. # C: O(bucket_len + in_lookup_len)
pub fn d_lookup_done(placeholder: &Arc<Dentry>) -> Arc<Dentry> {
    placeholder.set_par_lookup(false); // wake gate clears
    {
        let mut g = IN_LOOKUP.lock();
        let dptr = Arc::as_ptr(placeholder);
        g.retain(|w| match w.upgrade() { Some(e) => Arc::as_ptr(&e) != dptr, None => false });
    }
    let canon = match placeholder.parent() {
        Some(p) => p.cache_child(placeholder.name(), placeholder.clone()),
        None    => placeholder.clone(),
    };
    DENTRY_HASHTABLE.insert(&canon);
    canon
}
