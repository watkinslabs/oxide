//! State the counting expressions keep between packets.
//!
//! A stateful object and the expression of the same name share one state
//! type: `limit`, `quota`, `connlimit` and `last` exist in both forms and
//! must behave identically whichever way a ruleset reaches them.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
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
    Connlimit { flows: Lock<BTreeMap<ConnlimitKey, Option<alloc::sync::Arc<conntrack::Conn>>>>, limit: u32,
                invert: bool },
    CtHelper { name: String, l4proto: u8, l3proto: Option<u16> },
    CtTimeout { l3proto: Option<u16>, l4proto: u8, values: [u32; 14] },
    CtExpect { l3proto: Option<u16>, l4proto: u8, dport: u16, timeout_ms: u32, size: u8 },
    Secmark { context: String, secid: u32 },
    Synproxy { mss: u16, wscale: u8, flags: u32 },
    Unsupported,
}

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ConnlimitKey {
    Tracked(u64),
    Untracked(conntrack::tuple::Tuple),
}

impl core::fmt::Debug for ObjectState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Counter { .. } => "Counter",
            Self::Quota { .. } => "Quota",
            Self::Limit { .. } => "Limit",
            Self::Connlimit { .. } => "Connlimit",
            Self::CtHelper { .. } => "CtHelper",
            Self::CtTimeout { .. } => "CtTimeout",
            Self::CtExpect { .. } => "CtExpect",
            Self::Secmark { .. } => "Secmark",
            Self::Synproxy { .. } => "Synproxy",
            Self::Unsupported => "Unsupported",
        })
    }
}

impl ObjectState {
    /// Build state from the nested object-data ABI. # C: O(len(data))
    pub fn from_wire(ty: u32, data: &[u8]) -> Self {
        use crate::nft_expr::flags::{NFT_LIMIT_F_INV, NFT_QUOTA_F_INV};
        use crate::nft_expr::limits::{NSEC_PER_SEC, NFT_LIMIT_PKT_BURST_DEFAULT};
        use crate::nft_expr::nla::{find_str, find_u8, find_u16_be, find_u32_be, find_u64_be};
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
            crate::nft_expr::uapi::NFT_OBJECT_CONNLIMIT => {
                let limit = find_u32_be(data, crate::nft_expr::uapi::NFTA_CONNLIMIT_COUNT)
                    .unwrap_or(0);
                let invert = find_u32_be(data, crate::nft_expr::uapi::NFTA_CONNLIMIT_FLAGS)
                    .is_some_and(|f| f & crate::nft_expr::flags::NFT_CONNLIMIT_F_INV != 0);
                Self::Connlimit { flows: Lock::new(BTreeMap::new()), limit, invert }
            }
            crate::nft_expr::uapi::NFT_OBJECT_CT_HELPER => {
                let Some(name) = find_str(data, crate::nft_expr::uapi::NFTA_CT_HELPER_NAME)
                    .filter(|name| !name.is_empty()) else { return Self::Unsupported; };
                let Some(l4proto) = find_u8(data, crate::nft_expr::uapi::NFTA_CT_HELPER_L4PROTO)
                    .filter(|proto| *proto != 0) else { return Self::Unsupported; };
                Self::CtHelper { name: String::from(name), l4proto,
                    l3proto: find_u16_be(data, crate::nft_expr::uapi::NFTA_CT_HELPER_L3PROTO) }
            }
            crate::nft_expr::uapi::NFT_OBJECT_SYNPROXY => {
                let flags = find_u32_be(data, crate::nft_expr::uapi::NFTA_SYNPROXY_FLAGS).unwrap_or(0);
                if flags & !crate::nft_expr::flags::NF_SYNPROXY_OPT_MASK != 0 { return Self::Unsupported; }
                Self::Synproxy {
                    mss: find_u16_be(data, crate::nft_expr::uapi::NFTA_SYNPROXY_MSS).unwrap_or(0),
                    wscale: find_u8(data, crate::nft_expr::uapi::NFTA_SYNPROXY_WSCALE).unwrap_or(0),
                    flags,
                }
            }
            crate::nft_expr::uapi::NFT_OBJECT_CT_TIMEOUT => {
                let Some(l4proto) = find_u8(data, crate::nft_expr::uapi::NFTA_CT_TIMEOUT_L4PROTO)
                    .filter(|proto| *proto != 0) else { return Self::Unsupported; };
                let Some(nested) = crate::nft_expr::nla::find_bytes(
                    data, crate::nft_expr::uapi::NFTA_CT_TIMEOUT_DATA) else {
                    return Self::Unsupported;
                };
                let mut values = [0u32; 14];
                match l4proto {
                    crate::nft_expr::limits::IPPROTO_TCP => {
                        values[..conntrack::proto::tcp_state::TCP_TIMEOUTS.len()].copy_from_slice(
                            &conntrack::proto::tcp_state::TCP_TIMEOUTS);
                        let ids = [
                            crate::nft_expr::uapi::CTA_TIMEOUT_TCP_SYN_SENT,
                            crate::nft_expr::uapi::CTA_TIMEOUT_TCP_SYN_RECV,
                            crate::nft_expr::uapi::CTA_TIMEOUT_TCP_ESTABLISHED,
                            crate::nft_expr::uapi::CTA_TIMEOUT_TCP_FIN_WAIT,
                            crate::nft_expr::uapi::CTA_TIMEOUT_TCP_CLOSE_WAIT,
                            crate::nft_expr::uapi::CTA_TIMEOUT_TCP_LAST_ACK,
                            crate::nft_expr::uapi::CTA_TIMEOUT_TCP_TIME_WAIT,
                            crate::nft_expr::uapi::CTA_TIMEOUT_TCP_CLOSE,
                            crate::nft_expr::uapi::CTA_TIMEOUT_TCP_SYN_SENT2,
                            crate::nft_expr::uapi::CTA_TIMEOUT_TCP_RETRANS,
                            crate::nft_expr::uapi::CTA_TIMEOUT_TCP_UNACK,
                        ];
                        for (index, attr) in ids.into_iter().enumerate() {
                            if let Some(value) = find_u32_be(nested, attr) { values[index + 1] = value; }
                        }
                        values[0] = values[1];
                    }
                    crate::nft_expr::limits::IPPROTO_UDP => {
                        values[0] = conntrack::proto::udp::UDP_TIMEOUTS[0];
                        values[1] = conntrack::proto::udp::UDP_TIMEOUTS[1];
                        if let Some(value) = find_u32_be(nested,
                            crate::nft_expr::uapi::CTA_TIMEOUT_UDP_UNREPLIED) { values[0] = value; }
                        if let Some(value) = find_u32_be(nested,
                            crate::nft_expr::uapi::CTA_TIMEOUT_UDP_REPLIED) { values[1] = value; }
                    }
                    _ => return Self::Unsupported,
                }
                Self::CtTimeout { l3proto: find_u16_be(
                    data, crate::nft_expr::uapi::NFTA_CT_TIMEOUT_L3PROTO), l4proto, values }
            }
            crate::nft_expr::uapi::NFT_OBJECT_CT_EXPECT => {
                let Some(l4proto) = find_u8(data, crate::nft_expr::uapi::NFTA_CT_EXPECT_L4PROTO)
                    .filter(|proto| matches!(*proto, crate::nft_expr::limits::IPPROTO_TCP
                        | crate::nft_expr::limits::IPPROTO_UDP
                        | 33 | 132)) else { return Self::Unsupported; };
                let Some(dport) = find_u16_be(data, crate::nft_expr::uapi::NFTA_CT_EXPECT_DPORT)
                    .filter(|port| *port != 0) else { return Self::Unsupported; };
                let Some(timeout_ms) = find_u32_be(data,
                    crate::nft_expr::uapi::NFTA_CT_EXPECT_TIMEOUT) else { return Self::Unsupported; };
                let Some(size) = find_u8(data, crate::nft_expr::uapi::NFTA_CT_EXPECT_SIZE)
                    .filter(|size| *size != 0) else { return Self::Unsupported; };
                Self::CtExpect { l3proto: find_u16_be(
                    data, crate::nft_expr::uapi::NFTA_CT_EXPECT_L3PROTO),
                    l4proto, dport, timeout_ms, size }
            }
            crate::nft_expr::uapi::NFT_OBJECT_SECMARK => {
                let Some(context) = find_str(data, crate::nft_expr::uapi::NFTA_SECMARK_CTX)
                    .filter(|context| !context.is_empty()) else { return Self::Unsupported; };
                let Some(secid) = net::selinux_glue::secmark_sid(context) else {
                    return Self::Unsupported;
                };
                Self::Secmark { context: String::from(context), secid }
            }
            _ => Self::Unsupported,
        }
    }

    /// Evaluate one packet against the persistent object state. # C: O(1)
    pub fn eval(&self, pkt_len: u64, now_ns: u64) -> Option<i32> {
        self.eval_for(pkt_len, now_ns, None)
    }

    /// Evaluate one object with the live packet's connection identity. # C: O(N flows)
    pub fn eval_for(&self, pkt_len: u64, now_ns: u64,
                    ct: Option<&dyn crate::nft_expr::access::CtAccess>) -> Option<i32> {
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
            Self::Connlimit { flows, limit, invert } => {
                let Some(ct) = ct else { return Some(crate::nft_expr::uapi::NF_DROP) };
                let mut flows = flows.lock();
                let now = now_ns / crate::nft_expr::limits::NSEC_PER_SEC;
                flows.retain(|_, flow| flow.as_ref().is_none_or(|flow| {
                    !flow.dying() && !flow.expired(now)
                }));
                let (key, value) = if let Some(flow) = ct.flow() {
                    (ConnlimitKey::Tracked(flow.id), Some(flow))
                } else if let Some(tuple) = ct.tuple(0) {
                    (ConnlimitKey::Untracked(tuple), None)
                } else {
                    return Some(crate::nft_expr::uapi::NF_DROP);
                };
                flows.entry(key).or_insert(value);
                let over = flows.len() as u32 > *limit;
                (over ^ *invert).then_some(NFT_BREAK)
            }
            Self::CtHelper { name, l4proto, l3proto } => {
                let Some(ct) = ct else { return None; };
                let Some(tuple) = ct.tuple(0) else { return None; };
                if tuple.protonum != *l4proto
                    || l3proto.is_some_and(|family| {
                        !matches!(family as u8, crate::nft_expr::uapi::NFPROTO_INET
                            | crate::nft_expr::uapi::NFPROTO_NETDEV
                            | crate::nft_expr::uapi::NFPROTO_BRIDGE)
                            && family as u8 != tuple.l3num
                    }) {
                    return None;
                }
                let _ = ct.set_helper(name, *l4proto);
                None
            }
            Self::CtTimeout { .. } => Some(NFT_BREAK),
            Self::CtExpect { .. } => Some(NFT_BREAK),
            Self::Secmark { .. } => Some(NFT_BREAK),
            Self::Synproxy { .. } => Some(NFT_BREAK),
            Self::Unsupported => Some(NFT_BREAK),
        }
    }

    /// Evaluate an object whose Linux operation also records a packet action.
    pub fn eval_packet(&self, pkt: &[u8], family: u8,
                       ct: Option<&dyn crate::nft_expr::access::CtAccess>, now_ns: u64,
                       synproxy: Option<&dyn crate::nft_expr::access::SynproxyAccess>,
                       actions: &mut Vec<crate::nft_expr::action::Action>,
                       packet_secmark: &mut u32) -> Option<i32> {
        match self {
            Self::CtTimeout { l3proto, l4proto, values } => {
                let Some(ct) = ct else { return None; };
                let Some(tuple) = ct.tuple(0) else { return None; };
                if tuple.protonum != *l4proto
                    || l3proto.is_some_and(|family| family != tuple.l3num as u16) {
                    return None;
                }
                let _ = ct.set_timeout_policy(l3proto.unwrap_or(tuple.l3num as u16), *l4proto,
                                               values, now_ns);
                None
            }
            Self::CtExpect { l3proto, l4proto, dport, timeout_ms, size } => {
                let Some(ct) = ct else { return Some(crate::nft_expr::uapi::NFT_BREAK); };
                let Some(tuple) = ct.tuple(0) else { return Some(crate::nft_expr::uapi::NFT_BREAK); };
                if l3proto.is_some_and(|family| family != tuple.l3num as u16) {
                    return Some(crate::nft_expr::uapi::NFT_BREAK);
                }
                if !ct.set_expectation(l3proto.unwrap_or(tuple.l3num as u16), *l4proto,
                                       *dport, *timeout_ms, *size, now_ns) {
                    return Some(crate::nft_expr::uapi::NF_DROP);
                }
                None
            }
            Self::Secmark { secid, .. } => {
                *packet_secmark = *secid;
                None
            }
            Self::Synproxy { mss, wscale, flags } =>
                crate::nft_expr::run::action::synproxy_packet(
                    pkt, family, synproxy, *mss, *wscale, *flags, actions),
            _ => self.eval_for(pkt.len() as u64, 0, None),
        }
    }
}

#[cfg(test)]
#[path = "stateful_tests.rs"]
mod tests;

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
