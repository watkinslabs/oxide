// The per-destination metrics cache: what this host learned from every
// destination it has spoken to. One row per address pair holds both the
// congestion metrics a closing connection writes back and the fast-open state
// a client presents on its next handshake — the reference keeps them in the
// same block for the same reason, because both are facts about a destination
// rather than about any one connection.
//
// A cookie names a host pair, not a connection (`super::cookie`), so one
// learned on any connection to a server is presentable on every later one.
// The cache is therefore keyed by the address pair and holds no port, and it
// is namespace state — a cookie is minted by a server under a key that says
// nothing about which namespace here asked for it, but the destination it
// names is only reachable through the namespace that routed to it.
//
// Sizing follows the reference and is deliberately not a global bound. Each
// bucket keeps its own short chain; a chain that has grown past
// `RECLAIM_DEPTH` takes its next entry by reusing the least recently
// refreshed one rather than growing. So the cache is bounded by the bucket
// count and nothing has to walk it to evict, which matters because the walk
// would run under the transmit path of every connection.
//
// An entry older than `ENTRY_TIMEOUT_NS` has its fast-open state cleared on
// the next touch: a cookie that old names a key the server has almost
// certainly rotated away from, and presenting it costs a round trip that
// asking for a fresh one does not.
//
// Losing an entry never costs a connection — a miss opens the ordinary way
// and asks for a cookie (`super::client`).
//
// No target gate: the eviction and staleness rules decide which connections
// can fast open, so they live where `cargo test` compiles them (`docs/53§4`).

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use sync::{Socket as SockLockClass, Spinlock};

use crate::addr::IpAddr;
use crate::tcp_conn::fastopen::Cookie;

use super::ids;

/// Nanoseconds in one second.
const NS_PER_SEC: u64 = 1_000_000_000;

/// Independent chains. A destination lands in one of these by its address.
pub const BUCKETS: usize = 256;

/// A chain longer than this reclaims instead of growing.
pub const RECLAIM_DEPTH: usize = 5;

/// How long an entry's fast-open state is believed. Past this, the next touch
/// clears it and the connection asks for a fresh cookie.
pub const ENTRY_TIMEOUT_NS: u64 = 3600 * NS_PER_SEC;

/// The option kinds a cookie request may be made under. A destination that
/// never answered a request under the assigned kind is asked under the
/// experimental one next, and then under the assigned one again: some
/// middleboxes pass exactly one of the two.
pub const TRY_EXP_NONE: u8 = 0;
pub const TRY_EXP_EXPERIMENTAL: u8 = 1;
pub const TRY_EXP_ASSIGNED: u8 = 2;

/// What one destination taught this host.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Entry {
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
    /// When the entry was last refreshed, for the staleness rule and for the
    /// chain reclaim's choice of victim.
    stamp_ns: u64,
    cookie: Option<Cookie>,
    /// The MSS the destination advertised, so a SYN carrying data can be
    /// sized before the SYN-ACK says how big it may be.
    mss: u16,
    /// Which option kind the next cookie request should use.
    try_exp: u8,
    /// Consecutive fast-open SYNs to this destination that went unanswered.
    syn_loss: u16,
    /// When the most recent one was recorded.
    last_syn_loss_ns: u64,
    /// Congestion metrics closing connections left behind, indexed by
    /// `super::ids`.
    vals: [u32; ids::COUNT],
    /// Slots an administrator pinned against the connection-driven update.
    lock: u32,
}

/// What the cache knows about one destination.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Cached {
    pub cookie: Option<Cookie>,
    pub mss: u16,
    /// The next cookie request travels under the experimental option kind.
    pub try_exp: bool,
}

/// One cache row projected for the TCP metrics ABI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metrics {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub age_ns: u64,
    pub mss: u16,
    pub syn_loss: u16,
    pub syn_loss_age_ns: u64,
    pub cookie: Option<Cookie>,
    /// Congestion metrics, indexed by `super::ids`.
    pub vals: [u32; ids::COUNT],
    pub lock: u32,
}

/// One namespace's destination metrics cache.
///
/// The bucket array is a separate heap allocation reached by pointer, not an
/// inline member. Inline, `BUCKETS` locks made this 8192 B and, embedded in
/// the per-namespace state, gave that state a 9336 B constructor that the
/// compiler reserved on the stack of every namespace-state lookup — over half
/// a 16 KiB kernel stack, on a path reachable from softirq receive. The
/// reference keeps its destination-metrics hash in exactly this shape: a
/// separately allocated bucket array the namespace refers to.
pub struct MetricsCache {
    chains: Box<[Spinlock<Vec<Entry>, SockLockClass>]>,
}

impl Default for MetricsCache {
    /// # C: O(BUCKETS)
    fn default() -> Self { Self::new() }
}

/// Which chain a destination falls in. The reference hashes the destination
/// alone and compares both addresses on the walk, so every source address
/// reaching one destination shares a chain. # C: O(1)
fn bucket(dst: IpAddr) -> usize {
    let mut acc: u32 = 0;
    match dst {
        IpAddr::V4(ip) => for byte in ip.octets() { acc = acc.wrapping_mul(31).wrapping_add(byte as u32); },
        IpAddr::V6(ip) => for byte in ip.0 { acc = acc.wrapping_mul(31).wrapping_add(byte as u32); },
    }
    (acc as usize) % BUCKETS
}

impl MetricsCache {
    /// Buckets are pushed one at a time into a heap vector, never built as an
    /// array temporary — the temporary is what put `BUCKETS` locks on the
    /// stack. # C: O(BUCKETS)
    pub fn new() -> Self {
        let mut chains = Vec::with_capacity(BUCKETS);
        for _ in 0..BUCKETS { chains.push(Spinlock::new(Vec::new())); }
        Self { chains: chains.into_boxed_slice() }
    }

    /// What this host knows about `dst` from `src`. A miss and a stale entry
    /// read the same, which is what makes the ordinary handshake the answer
    /// to both. # C: O(RECLAIM_DEPTH)
    pub fn get(&self, src: IpAddr, dst: IpAddr, now_ns: u64) -> Cached {
        let chain = self.chains[bucket(dst)].lock();
        let Some(entry) = chain.iter().find(|e| e.src == Some(src) && e.dst == Some(dst))
            else { return Cached::default() };
        if now_ns.wrapping_sub(entry.stamp_ns) >= ENTRY_TIMEOUT_NS { return Cached::default(); }
        let cookie = entry.cookie.filter(|c| !c.is_request());
        Cached {
            cookie,
            mss: entry.mss,
            try_exp: cookie.is_none() && entry.try_exp == TRY_EXP_EXPERIMENTAL,
        }
    }

    /// Record what a handshake to `dst` taught. A cookie replaces whatever
    /// was held; a request kind is only recorded while no cookie is held, so
    /// learning a cookie ends the search for a kind that works. # C: O(depth)
    pub fn set(&self, src: IpAddr, dst: IpAddr, now_ns: u64, mss: u16,
               cookie: Option<Cookie>, syn_lost: bool, try_exp: u8)
    {
        let mut chain = self.chains[bucket(dst)].lock();
        let index = match chain.iter().position(|e| e.src == Some(src) && e.dst == Some(dst)) {
            Some(index) => {
                // Past the staleness horizon the entry names a key the server
                // has moved on from; it is refreshed empty rather than
                // amended.
                if now_ns.wrapping_sub(chain[index].stamp_ns) >= ENTRY_TIMEOUT_NS {
                    chain[index] = Entry { src: Some(src), dst: Some(dst), ..Entry::default() };
                }
                index
            }
            None => Self::insert(&mut chain, src, dst),
        };
        let entry = &mut chain[index];
        entry.stamp_ns = now_ns;
        if mss != 0 { entry.mss = mss; }
        match cookie {
            Some(cookie) if !cookie.is_request() => entry.cookie = Some(cookie),
            _ => {
                let held = entry.cookie.map(|c| !c.is_request()).unwrap_or(false);
                let held_exp = entry.cookie.map(|c| c.exp).unwrap_or(false);
                if try_exp > entry.try_exp && !held && !held_exp { entry.try_exp = try_exp; }
            }
        }
        if syn_lost {
            entry.syn_loss = entry.syn_loss.saturating_add(1);
            entry.last_syn_loss_ns = now_ns;
        } else { entry.syn_loss = 0; }
    }

    /// Take a slot for a destination the chain does not hold. Past the
    /// reclaim depth the least recently refreshed entry is reused, so the
    /// chain never grows further. # C: O(depth)
    fn insert(chain: &mut Vec<Entry>, src: IpAddr, dst: IpAddr) -> usize {
        let fresh = Entry { src: Some(src), dst: Some(dst), ..Entry::default() };
        if chain.len() > RECLAIM_DEPTH {
            let mut oldest = 0;
            for index in 1..chain.len() {
                if chain[index].stamp_ns < chain[oldest].stamp_ns { oldest = index; }
            }
            chain[oldest] = fresh;
            return oldest;
        }
        chain.push(fresh);
        chain.len() - 1
    }

    /// Entries held for one destination's chain. # C: O(1)
    pub fn chain_len(&self, dst: IpAddr) -> usize { self.chains[bucket(dst)].lock().len() }

    /// Recurring unanswered fast-open SYNs recorded for one destination.
    /// # C: O(depth)
    pub fn syn_loss(&self, src: IpAddr, dst: IpAddr) -> u16 {
        self.chains[bucket(dst)].lock().iter()
            .find(|e| e.src == Some(src) && e.dst == Some(dst))
            .map(|e| e.syn_loss).unwrap_or(0)
    }

    /// The live metrics row for `dst`, narrowed by `src` when supplied.
    /// # C: O(depth)
    pub fn metrics(&self, src: Option<IpAddr>, dst: IpAddr, now_ns: u64) -> Option<Metrics> {
        let chain = self.chains[bucket(dst)].lock();
        let entry = chain.iter().find(|e| e.dst == Some(dst)
            && (src.is_none() || e.src == src))?;
        Some(Metrics {
            src: entry.src?, dst: entry.dst?,
            age_ns: now_ns.wrapping_sub(entry.stamp_ns),
            mss: entry.mss, syn_loss: entry.syn_loss,
            syn_loss_age_ns: now_ns.wrapping_sub(entry.last_syn_loss_ns),
            cookie: entry.cookie.filter(|cookie| !cookie.is_request()),
            vals: entry.vals, lock: entry.lock,
        })
    }

    /// The congestion metrics held for one destination. A miss and a
    /// destination nothing is known about read the same, which is what makes
    /// the compiled defaults the answer to both. # C: O(depth)
    pub fn cached(&self, src: IpAddr, dst: IpAddr) -> super::init::CachedMetrics {
        let chain = self.chains[bucket(dst)].lock();
        chain.iter().find(|e| e.src == Some(src) && e.dst == Some(dst))
            .map(|e| super::init::CachedMetrics { vals: e.vals, lock: e.lock })
            .unwrap_or_default()
    }

    /// Whether a previous connection to this destination proved it reachable.
    ///
    /// A stored round-trip time is the evidence: it can only have come from a
    /// connection this host completed. The reference asks exactly this
    /// question of exactly this field. # C: O(depth)
    pub fn peer_is_proven(&self, src: IpAddr, dst: IpAddr) -> bool {
        self.cached(src, dst).get(ids::RTT) != 0
    }

    /// Fold one closing connection's measurements into its destination's row,
    /// creating the row if this is the first connection to reach it.
    /// # C: O(depth)
    pub fn record(&self, src: IpAddr, dst: IpAddr, now_ns: u64, conn: super::update::Closing) {
        let mut chain = self.chains[bucket(dst)].lock();
        let existing = chain.iter().position(|e| e.src == Some(src) && e.dst == Some(dst));
        let row = existing.map(|index| super::update::Row {
            vals: chain[index].vals, lock: chain[index].lock,
        }).unwrap_or_default();
        match super::update::update(row, conn) {
            super::update::Update::Store(row) => {
                let index = match existing {
                    Some(index) => index,
                    None => Self::insert(&mut chain, src, dst),
                };
                chain[index].vals = row.vals;
                chain[index].stamp_ns = now_ns;
            }
            // A connection that measured nothing creates no row: an entry
            // holding only the absence of a round-trip time is what a miss
            // already reads as.
            super::update::Update::ForgetRtt => {
                if let Some(index) = existing {
                    if !ids::locked(chain[index].lock, ids::RTT) {
                        chain[index].vals[ids::RTT] = 0;
                    }
                }
            }
        }
    }

    /// Administrative write of one destination's metrics, which also pins
    /// every slot it names against the connection-driven update. # C: O(depth)
    pub fn pin(&self, src: IpAddr, dst: IpAddr, now_ns: u64, vals: [Option<u32>; ids::COUNT]) {
        let mut chain = self.chains[bucket(dst)].lock();
        let index = match chain.iter().position(|e| e.src == Some(src) && e.dst == Some(dst)) {
            Some(index) => index,
            None => Self::insert(&mut chain, src, dst),
        };
        let entry = &mut chain[index];
        entry.stamp_ns = now_ns;
        for (metric, value) in vals.iter().enumerate() {
            let Some(value) = *value else { continue; };
            entry.vals[metric] = value;
            entry.lock = ids::with_lock(entry.lock, metric);
        }
    }

    /// Drop one destination's whole row, or every row naming that
    /// destination when no source narrows it. Reports whether anything was
    /// held. # C: O(depth)
    pub fn forget(&self, src: Option<IpAddr>, dst: IpAddr) -> bool {
        let mut chain = self.chains[bucket(dst)].lock();
        let before = chain.len();
        chain.retain(|e| !(e.dst == Some(dst) && (src.is_none() || e.src == src)));
        before != chain.len()
    }

    /// Drop every row this namespace holds. # C: O(BUCKETS × depth)
    pub fn forget_all(&self) {
        for chain in self.chains.iter() { chain.lock().clear(); }
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
