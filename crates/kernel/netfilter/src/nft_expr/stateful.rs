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

/// Persistent state owned by one nft object instance. The object reference
/// evaluates this state directly; it is never rebuilt from a rule walk.
pub enum ObjectState {
    Counter { packets: AtomicU64, bytes: AtomicU64 },
    Quota { state: QuotaState, quota: u64, invert: bool },
    Limit { state: LimitState, limit_type: u32, rate: u64, nsecs: u64,
            tokens_max: u64, invert: bool },
    Unsupported,
}

impl core::fmt::Debug for ObjectState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Counter { .. } => "Counter",
            Self::Quota { .. } => "Quota",
            Self::Limit { .. } => "Limit",
            Self::Unsupported => "Unsupported",
        })
    }
}

impl ObjectState {
    /// Build state from the nested object-data ABI. # C: O(len(data))
    pub fn from_wire(ty: u32, data: &[u8]) -> Self {
        use crate::nft_expr::flags::{NFT_LIMIT_F_INV, NFT_QUOTA_F_INV};
        use crate::nft_expr::limits::{NSEC_PER_SEC, NFT_LIMIT_PKT_BURST_DEFAULT};
        use crate::nft_expr::nla::{find_u32_be, find_u64_be};
        use crate::nft_expr::parse::misc::limit_tokens_max;
        use crate::nft_expr::uapi::{NFTA_LIMIT_BURST, NFTA_LIMIT_FLAGS,
            NFTA_LIMIT_RATE, NFTA_LIMIT_TYPE, NFTA_LIMIT_UNIT, NFTA_QUOTA_BYTES,
            NFTA_QUOTA_CONSUMED, NFTA_QUOTA_FLAGS, NFT_OBJECT_COUNTER,
            NFT_OBJECT_LIMIT, NFT_OBJECT_QUOTA, NFT_LIMIT_PKTS};
        match ty {
            NFT_OBJECT_COUNTER => Self::Counter {
                packets: AtomicU64::new(find_u64_be(data, 2).unwrap_or(0)),
                bytes: AtomicU64::new(find_u64_be(data, 1).unwrap_or(0)),
            },
            NFT_OBJECT_QUOTA => {
                let quota = find_u64_be(data, NFTA_QUOTA_BYTES).unwrap_or(0);
                let consumed = find_u64_be(data, NFTA_QUOTA_CONSUMED).unwrap_or(0).min(quota);
                Self::Quota { state: { let q = QuotaState::new(); q.preset(consumed); q },
                    quota, invert: find_u32_be(data, NFTA_QUOTA_FLAGS)
                        .is_some_and(|f| f & NFT_QUOTA_F_INV != 0) }
            }
            NFT_OBJECT_LIMIT => {
                let rate = find_u64_be(data, NFTA_LIMIT_RATE).unwrap_or(0);
                if rate == 0 { return Self::Unsupported; }
                let unit = find_u64_be(data, NFTA_LIMIT_UNIT).unwrap_or(0);
                let nsecs = unit.saturating_mul(NSEC_PER_SEC);
                let limit_type = find_u32_be(data, NFTA_LIMIT_TYPE).unwrap_or(NFT_LIMIT_PKTS);
                let burst = find_u32_be(data, NFTA_LIMIT_BURST).unwrap_or_else(||
                    (limit_type == NFT_LIMIT_PKTS).then_some(NFT_LIMIT_PKT_BURST_DEFAULT).unwrap_or(0));
                let Ok(tokens_max) = limit_tokens_max(limit_type == NFT_LIMIT_PKTS, nsecs, rate, burst)
                    else { return Self::Unsupported; };
                let state = LimitState::new(); state.prime(tokens_max, 0);
                Self::Limit { state, limit_type, rate, nsecs, tokens_max,
                    invert: find_u32_be(data, NFTA_LIMIT_FLAGS)
                        .is_some_and(|f| f & NFT_LIMIT_F_INV != 0) }
            }
            _ => Self::Unsupported,
        }
    }

    /// Evaluate one packet against the persistent object state. # C: O(1)
    pub fn eval(&self, pkt_len: u64, now_ns: u64) -> Option<i32> {
        use crate::nft_expr::uapi::NFT_BREAK;
        match self {
            Self::Counter { packets, bytes } => {
                packets.fetch_add(1, Ordering::Relaxed);
                bytes.fetch_add(pkt_len, Ordering::Relaxed);
                None
            }
            Self::Quota { state, quota, invert } => {
                let over = state.consume(pkt_len, *quota).over;
                (over ^ *invert).then_some(NFT_BREAK)
            }
            Self::Limit { state, limit_type, rate, nsecs, tokens_max, invert } => {
                let cost = crate::nft_expr::run::count::limit_cost(
                    *limit_type, *nsecs, *rate, pkt_len);
                let over = state.charge(cost, *tokens_max, now_ns);
                (over ^ *invert).then_some(NFT_BREAK)
            }
            Self::Unsupported => Some(NFT_BREAK),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ObjectState;
    use crate::nft_expr::uapi::{NFTA_QUOTA_BYTES, NFT_OBJECT_QUOTA, NFT_BREAK};

    fn attr(kind: u16, bytes: &[u8]) -> alloc::vec::Vec<u8> {
        let len = 4 + bytes.len();
        let mut out = alloc::vec![0; (len + 3) & !3];
        out[..2].copy_from_slice(&(len as u16).to_ne_bytes());
        out[2..4].copy_from_slice(&kind.to_ne_bytes());
        out[4..len].copy_from_slice(bytes);
        out
    }

    #[test]
    fn quota_object_keeps_consumption_across_evaluations() {
        let data = attr(NFTA_QUOTA_BYTES, &10u64.to_be_bytes());
        let state = ObjectState::from_wire(NFT_OBJECT_QUOTA, &data);
        assert_eq!(state.eval(6, 0), None);
        assert_eq!(state.eval(5, 0), Some(NFT_BREAK));
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
