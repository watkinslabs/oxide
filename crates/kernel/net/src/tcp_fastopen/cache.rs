// The client cookie cache: what this host learned from each destination it
// fast-opened to.
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
use alloc::vec::Vec;

use sync::{Socket as SockLockClass, Spinlock};

use crate::addr::IpAddr;
use crate::tcp_conn::fastopen::Cookie;

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
}

/// What the cache knows about one destination.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Cached {
    pub cookie: Option<Cookie>,
    pub mss: u16,
    /// The next cookie request travels under the experimental option kind.
    pub try_exp: bool,
}

/// One namespace's client cookie cache.
pub struct ClientCache {
    chains: [Spinlock<Vec<Entry>, SockLockClass>; BUCKETS],
}

impl Default for ClientCache {
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

impl ClientCache {
    /// # C: O(BUCKETS)
    pub fn new() -> Self {
        Self { chains: core::array::from_fn(|_| Spinlock::new(Vec::new())) }
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
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
