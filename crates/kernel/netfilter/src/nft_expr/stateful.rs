//! State the counting expressions keep between packets.
//!
//! A stateful object and the expression of the same name share one state
//! type: `limit`, `quota`, `connlimit` and `last` exist in both forms and
//! must behave identically whichever way a ruleset reaches them.

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

type Lock<T> = sync::Spinlock<T, sync::Socket>;

/// Token bucket shared by the `limit` expression and the `limit` object.
pub struct LimitState { inner: Lock<LimitTokens> }

impl Default for LimitState {
    fn default() -> Self { Self::new() }
}

#[derive(Copy, Clone, Debug, Default)]
struct LimitTokens { last: u64, tokens: u64 }

impl LimitState {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { inner: sync::Spinlock::new(LimitTokens { last: 0, tokens: 0 }) }
    }

    /// Fill the bucket and start its clock. # C: O(1)
    pub fn prime(&self, tokens_max: u64, now: u64) {
        let mut g = self.inner.lock();
        g.tokens = tokens_max;
        g.last = now;
    }

    /// Charge `cost` against the bucket. Returns whether the packet is over
    /// the limit — the caller applies the inversion. Refill is unconditional
    /// so an over-limit packet still advances the clock without spending.
    /// # C: O(1)
    pub fn charge(&self, cost: u64, tokens_max: u64, now: u64) -> bool {
        let mut g = self.inner.lock();
        let refilled = (g.tokens + now.saturating_sub(g.last)).min(tokens_max);
        g.last = now;
        match refilled.checked_sub(cost) {
            Some(left) => { g.tokens = left; false }
            None => { g.tokens = refilled; true }
        }
    }

    /// Tokens currently in the bucket, for a dump. # C: O(1)
    pub fn tokens(&self) -> u64 { self.inner.lock().tokens }
}

/// Byte budget shared by the `quota` expression and the `quota` object.
#[derive(Debug, Default)]
pub struct QuotaState { consumed: AtomicU64, depleted: AtomicBool }

/// Outcome of charging a quota: whether the budget is exhausted, and whether
/// this is the packet that reached it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct QuotaCharge { pub over: bool, pub report: bool }

impl QuotaState {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { consumed: AtomicU64::new(0), depleted: AtomicBool::new(false) }
    }

    /// Start from an already-consumed amount. # C: O(1)
    pub fn preset(&self, consumed: u64) { self.consumed.store(consumed, Ordering::Relaxed); }

    /// Consume `len` bytes. The counter keeps rising past the quota, so a
    /// depleted quota stays depleted. Consuming exactly the quota is not yet
    /// over it, but does report depletion. # C: O(1)
    pub fn consume(&self, len: u64, quota: u64) -> QuotaCharge {
        let consumed = self.consumed.fetch_add(len, Ordering::Relaxed) + len;
        QuotaCharge { over: consumed > quota, report: consumed >= quota }
    }

    /// Whether this call is the first to observe depletion. # C: O(1)
    pub fn latch_depleted(&self) -> bool { !self.depleted.swap(true, Ordering::Relaxed) }

    /// # C: O(1)
    pub fn consumed(&self) -> u64 { self.consumed.load(Ordering::Relaxed) }
}

/// Counter behind the incremental number generator.
#[derive(Debug, Default)]
pub struct NumgenState { counter: AtomicU32 }

impl NumgenState {
    /// # C: O(1)
    pub const fn new() -> Self { Self { counter: AtomicU32::new(0) } }

    /// Seed so the first generated value is zero. # C: O(1)
    pub fn prime(&self, modulus: u32) {
        self.counter.store(modulus.wrapping_sub(1), Ordering::Relaxed);
    }

    /// Next value in `0..modulus`. # C: O(1) amortised
    pub fn next(&self, modulus: u32) -> u32 {
        let mut old = self.counter.load(Ordering::Relaxed);
        loop {
            let new = if old + 1 < modulus { old + 1 } else { 0 };
            match self.counter.compare_exchange_weak(old, new, Ordering::Relaxed,
                                                     Ordering::Relaxed) {
                Ok(_) => return new,
                Err(seen) => old = seen,
            }
        }
    }
}

/// Last-hit timestamp shared by the `last` expression and the `last` object.
#[derive(Debug, Default)]
pub struct LastState { set: AtomicBool, at_ms: AtomicU64 }

impl LastState {
    /// # C: O(1)
    pub const fn new() -> Self { Self { set: AtomicBool::new(false), at_ms: AtomicU64::new(0) } }

    /// # C: O(1)
    pub fn hit(&self, now_ms: u64) {
        self.at_ms.store(now_ms, Ordering::Relaxed);
        self.set.store(true, Ordering::Relaxed);
    }

    /// Milliseconds recorded, or `None` while the expression has never
    /// fired — which is what a dump reports as unset. # C: O(1)
    pub fn last(&self) -> Option<u64> {
        self.set.load(Ordering::Relaxed).then(|| self.at_ms.load(Ordering::Relaxed))
    }
}

/// Every stateful slot one rule owns, indexed by the expression's position in
/// the rule's stateful list.
#[derive(Default)]
pub struct ExprStates {
    pub limits: Vec<LimitState>,
    pub quotas: Vec<QuotaState>,
    pub numgens: Vec<NumgenState>,
    pub lasts: Vec<LastState>,
}

impl ExprStates {
    /// # C: O(1)
    pub const fn empty() -> Self {
        Self { limits: Vec::new(), quotas: Vec::new(), numgens: Vec::new(), lasts: Vec::new() }
    }
}

impl ExprStates {
    /// Build and prime the slots one rule's expressions need. A rule's state
    /// lives as long as the rule does; a walk that builds its own gets a
    /// fresh bucket, a fresh budget and a fresh counter every packet.
    /// # C: O(N exprs)
    pub fn for_exprs(exprs: &[crate::nft_expr::expr::Expr]) -> Self {
        use crate::nft_expr::expr::Expr;
        let mut out = Self::default();
        for expr in exprs {
            match expr {
                Expr::Limit { index, tokens_max, .. } => {
                    while out.limits.len() <= *index { out.limits.push(LimitState::new()); }
                    out.limits[*index].prime(*tokens_max, 0);
                }
                Expr::Quota { index, consumed, .. } => {
                    while out.quotas.len() <= *index { out.quotas.push(QuotaState::new()); }
                    out.quotas[*index].preset(*consumed);
                }
                Expr::Numgen { index, modulus, .. } => {
                    while out.numgens.len() <= *index { out.numgens.push(NumgenState::new()); }
                    out.numgens[*index].prime(*modulus);
                }
                Expr::Last { index, set, msecs } => {
                    while out.lasts.len() <= *index { out.lasts.push(LastState::new()); }
                    if *set { out.lasts[*index].hit(*msecs); }
                }
                _ => {}
            }
        }
        out
    }
}
