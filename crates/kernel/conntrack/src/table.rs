//! The conntrack table. Every confirmed entry is reachable under BOTH its
//! tuples, so a reply packet finds its flow with one lookup instead of
//! inverting and searching again — and, critically, so a NAT-translated reply
//! (whose tuple is not the inverse of the original) is still found.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Socket as SocketLockClass, Spinlock};

use crate::entry::Conn;
use crate::limits::{CT_HASH_BUCKETS, CT_MAX_DEFAULT};
use crate::tuple::Tuple;
use crate::uapi::*;

/// Which half of an entry a lookup matched.
#[derive(Clone, Debug)]
pub struct Found { pub conn: Arc<Conn>, pub dir: u8 }

struct Bucket { entries: Vec<Arc<Conn>> }

/// Per-namespace conntrack table.
pub struct CtTable {
    buckets: Vec<Spinlock<Bucket, SocketLockClass>>,
    /// Unconfirmed entries, held until their first packet leaves the hooks.
    /// They are not in the hash: an unconfirmed entry has no committed reply
    /// tuple, so publishing it would let a second packet match a binding that
    /// is still being decided.
    pending: Spinlock<Vec<Arc<Conn>>, SocketLockClass>,
    next_id: AtomicU64,
    random: AtomicU64,
    count: AtomicU64,
    /// Hard ceiling. New flows are refused above it rather than evicting a
    /// live one at random.
    pub max: AtomicU64,
    seed: u32,
    pub drops: AtomicU64,
    pub insert_failed: AtomicU64,
    pub early_drops: AtomicU64,
}

impl CtTable {
    /// # C: O(N_buckets)
    pub fn new(seed: u32) -> Self { Self::with_buckets(CT_HASH_BUCKETS, seed) }

    /// Table with an explicit bucket count. A namespace may be sized smaller
    /// than the global default, and the collision paths must behave the same
    /// when two tuples land in one bucket as when they land in two.
    /// # C: O(N_buckets)
    pub fn with_buckets(n: usize, seed: u32) -> Self {
        let n = if n == 0 { 1 } else { n };
        let mut buckets = Vec::with_capacity(n);
        for _ in 0..n {
            buckets.push(Spinlock::new(Bucket { entries: Vec::new() }));
        }
        Self {
            buckets,
            pending: Spinlock::new(Vec::new()),
            next_id: AtomicU64::new(1),
            random: AtomicU64::new(seed as u64 | 1),
            count: AtomicU64::new(0),
            max: AtomicU64::new(CT_MAX_DEFAULT),
            seed,
            drops: AtomicU64::new(0),
            insert_failed: AtomicU64::new(0),
            early_drops: AtomicU64::new(0),
        }
    }

    fn bucket_of(&self, t: &Tuple) -> &Spinlock<Bucket, SocketLockClass> {
        &self.buckets[(t.hash(self.seed) as usize) % self.buckets.len()]
    }

    /// # C: O(1)
    pub fn alloc_id(&self) -> u64 { self.next_id.fetch_add(1, Ordering::Relaxed) }
    /// Namespace-owned pseudo-random stream used by bounded NAT allocation.
    /// # C: O(1)
    pub fn random_u16(&self) -> u16 {
        let old = self.random.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
        (old ^ (old >> 17) ^ (old >> 31)) as u16
    }
    /// # C: O(1)
    pub fn count(&self) -> u64 { self.count.load(Ordering::Relaxed) }

    /// Find the confirmed entry matching `t`, and which direction it matched.
    /// An expired entry is not a match: reporting one would hand a new
    /// connection the state, NAT binding and verdict of a dead flow.
    /// # C: O(bucket length)
    pub fn lookup(&self, t: &Tuple, now: u64) -> Option<Found> {
        let g = self.bucket_of(t).lock();
        for c in g.entries.iter() {
            if c.dying() || c.expired(now) { continue; }
            if c.orig == *t { return Some(Found { conn: c.clone(), dir: IP_CT_DIR_ORIGINAL }); }
            if c.reply_tuple() == *t { return Some(Found { conn: c.clone(), dir: IP_CT_DIR_REPLY }); }
        }
        None
    }

    /// Whether any live entry already occupies `t` in either direction. This
    /// is the collision test NAT source allocation runs: a chosen tuple that
    /// is already taken would make two flows indistinguishable on the wire.
    /// # C: O(bucket length)
    pub fn tuple_taken(&self, t: &Tuple, ignore: Option<&Arc<Conn>>, now: u64) -> bool {
        let g = self.bucket_of(t).lock();
        g.entries.iter().any(|c| {
            if let Some(skip) = ignore { if Arc::ptr_eq(c, skip) { return false; } }
            !c.dying() && !c.expired(now) && (c.orig == *t || c.reply_tuple() == *t)
        })
    }

    /// Register a freshly created, unconfirmed entry.
    /// # C: O(1)
    pub fn add_pending(&self, conn: Arc<Conn>) {
        self.pending.lock().push(conn);
    }

    /// Publish an entry into the hash. Fails when the table is full, or when
    /// another packet raced this one and already installed a flow on either
    /// tuple — in which case this entry must be discarded, not merged.
    /// # C: O(bucket length)
    pub fn confirm(&self, conn: &Arc<Conn>, now: u64) -> bool {
        {
            let mut p = self.pending.lock();
            match p.iter().position(|c| Arc::ptr_eq(c, conn)) {
                Some(i) => { p.remove(i); }
                None => return false,
            }
        }
        if conn.dying() { return false; }
        if self.count() >= self.max.load(Ordering::Relaxed) {
            self.drops.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        // Both tuples must be free, and they may hash to the same bucket, so
        // the two checks and both inserts happen with each bucket held in
        // turn — a check-then-insert with the lock dropped between is exactly
        // how two racing SYNs both win.
        let ok = self.insert_both(conn, now);
        if !ok {
            self.insert_failed.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        conn.set_status_bits(IPS_CONFIRMED);
        self.count.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn insert_both(&self, conn: &Arc<Conn>, now: u64) -> bool {
        let hi = (conn.orig.hash(self.seed) as usize) % self.buckets.len();
        let reply = conn.reply_tuple();
        let hj = (reply.hash(self.seed) as usize) % self.buckets.len();
        if hi == hj {
            let mut g = self.buckets[hi].lock();
            if bucket_taken(&g, &conn.orig, now) || bucket_taken(&g, &reply, now) {
                return false;
            }
            g.entries.push(conn.clone());
            return true;
        }
        // Take the lower index first so two concurrent confirms of mirrored
        // tuples cannot deadlock against each other. Each tuple is checked in
        // the bucket it hashes to, and only there — a cross-check would pass
        // for the wrong reason and hide a missing one.
        let (first, second) = if hi < hj { (hi, hj) } else { (hj, hi) };
        let mut g1 = self.buckets[first].lock();
        let mut g2 = self.buckets[second].lock();
        let (orig_g, reply_g) = if hi < hj { (&g1, &g2) } else { (&g2, &g1) };
        if bucket_taken(orig_g, &conn.orig, now) || bucket_taken(reply_g, &reply, now) {
            return false;
        }
        g1.entries.push(conn.clone());
        g2.entries.push(conn.clone());
        true
    }

    /// Mark an entry dying and unlink it. # C: O(bucket length)
    pub fn kill(&self, conn: &Arc<Conn>) -> bool {
        if conn.status.fetch_or(IPS_DYING, Ordering::AcqRel) & IPS_DYING != 0 {
            return false;
        }
        if conn.confirmed() {
            self.unlink(conn);
            self.count.fetch_sub(1, Ordering::Relaxed);
        } else {
            let mut p = self.pending.lock();
            if let Some(i) = p.iter().position(|c| Arc::ptr_eq(c, conn)) { p.remove(i); }
        }
        true
    }

    fn unlink(&self, conn: &Arc<Conn>) {
        let reply = conn.reply_tuple();
        for t in [&conn.orig, &reply] {
            let mut g = self.bucket_of(t).lock();
            if let Some(i) = g.entries.iter().position(|c| Arc::ptr_eq(c, conn)) {
                g.entries.remove(i);
            }
        }
    }

    /// Retire every expired entry. Returns how many went. # C: O(N)
    pub fn gc(&self, now: u64) -> usize {
        let mut dead = Vec::new();
        for b in self.buckets.iter() {
            let g = b.lock();
            for c in g.entries.iter() {
                if c.expired(now) && !c.dying() { dead.push(c.clone()); }
            }
        }
        let mut n = 0;
        for c in dead { if self.kill(&c) { n += 1; } }
        n
    }

    /// Every live entry, for `/proc/net/nf_conntrack` and ctnetlink dumps.
    /// Each entry appears once even though it is linked under two tuples.
    /// # C: O(N)
    pub fn snapshot(&self, now: u64) -> Vec<Arc<Conn>> {
        let mut out: Vec<Arc<Conn>> = Vec::new();
        for b in self.buckets.iter() {
            let g = b.lock();
            for c in g.entries.iter() {
                if c.dying() || c.expired(now) { continue; }
                if out.iter().any(|e| Arc::ptr_eq(e, c)) { continue; }
                out.push(c.clone());
            }
        }
        out
    }

    /// Entries still awaiting confirmation. # C: O(N)
    pub fn unconfirmed(&self) -> Vec<Arc<Conn>> { self.pending.lock().clone() }

    /// Drop one evictable entry to make room, the reference's early-drop under
    /// table pressure. Only states that are already closing qualify.
    /// # C: O(N)
    pub fn early_drop(&self, now: u64) -> bool {
        use crate::entry::ProtoState;
        use crate::proto::tcp_state::can_early_drop;
        for b in self.buckets.iter() {
            let victim = {
                let g = b.lock();
                g.entries.iter().find(|c| {
                    if c.dying() { return false; }
                    match *c.proto.lock() {
                        ProtoState::Tcp(t) => can_early_drop(t.state),
                        _ => c.status() & IPS_ASSURED == 0,
                    }
                }).cloned()
            };
            if let Some(v) = victim {
                if self.kill(&v) {
                    self.early_drops.fetch_add(1, Ordering::Relaxed);
                    let _ = now;
                    return true;
                }
            }
        }
        false
    }
}

fn bucket_taken(b: &Bucket, t: &Tuple, now: u64) -> bool {
    b.entries.iter().any(|c| !c.dying() && !c.expired(now)
        && (c.orig == *t || c.reply_tuple() == *t))
}
