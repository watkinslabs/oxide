//! A request's encryption context, and the rule that decides whether two runs
//! of data may share one request.
//!
//! The context says two things and no more: which key, and which data unit
//! number the FIRST data unit of the request carries. Everything after it is
//! that number plus its offset in units — which is exactly why the merge rule
//! is the whole of the correctness argument. A request is en/decrypted as one
//! run from one starting number, so any data placed in it that does not
//! continue that run is encrypted at the wrong keystream position, produces
//! bytes that decrypt to noise, and reports no error at any layer.

extern crate alloc;
use alloc::sync::Arc;

use crate::crypto::dun::Dun;
use crate::crypto::key::Key;

/// The key and starting data unit number a request's contents are encrypted
/// under.
#[derive(Clone)]
pub struct Ctx {
    key: Arc<Key>,
    dun: Dun,
}

impl Ctx {
    /// A context over `key` starting at `dun`. # C: O(1)
    pub fn new(key: Arc<Key>, dun: Dun) -> Ctx { Ctx { key, dun } }

    /// The key. # C: O(1)
    pub fn key(&self) -> &Arc<Key> { &self.key }

    /// The data unit number of the request's first data unit. # C: O(1)
    pub fn dun(&self) -> Dun { self.dun }

    /// Advance the starting number by the units in `bytes` — what a request
    /// that has already consumed a prefix carries. # C: O(1)
    pub fn advance(&mut self, bytes: u64) { self.dun.increment(self.key.units(bytes)); }

    /// Whether two contexts name the SAME key, which is a weaker question
    /// than whether they may be merged.
    ///
    /// Kept separate because a request that has not yet been given any data
    /// has no run to continue, so key identity is the whole test for it; a
    /// request that has data must also satisfy contiguity.
    /// # C: O(1)
    pub fn compatible(&self, other: &Ctx) -> bool { Arc::ptr_eq(&self.key, &other.key) }

    /// Whether `next` may be placed into a request that already holds
    /// `bytes` of data under this context.
    ///
    /// Both halves are load-bearing. A different key means the device would
    /// be asked to encrypt one request under two keys, which it cannot do. A
    /// discontiguous number means the second run would be encrypted as the
    /// continuation of the first, which every layer accepts and no layer can
    /// detect afterwards.
    /// # C: O(1)
    pub fn mergeable(&self, bytes: u64, next: &Ctx) -> bool {
        self.compatible(next) && self.dun.is_contiguous(self.key.units(bytes), &next.dun)
    }
}

/// Whether a request currently carrying `have` may take data described by
/// `next`, when either side may be absent.
///
/// The absent cases are not a detail: unencrypted data must not join an
/// encrypted request and encrypted data must not join an unencrypted one. The
/// first would be encrypted by a device that was never told to leave it alone;
/// the second would reach the medium in the clear.
/// # C: O(1)
pub fn mergeable(have: Option<&Ctx>, bytes: u64, next: Option<&Ctx>) -> bool {
    match (have, next) {
        (None, None) => true,
        (Some(a), Some(b)) => a.mergeable(bytes, b),
        _ => false,
    }
}
