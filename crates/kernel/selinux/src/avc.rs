// Access-vector cache: the memo in front of the decision engine.
//
// Every entry is keyed by the FULL subject/object/class triple and answers a
// question the policy would otherwise be re-walked to answer. Two rules decide
// whether this cache is a speed-up or a security hole:
//
//   * a lookup matches all three key components or it misses — a partial-key
//     match returns another subject's decision and grants access the policy
//     refuses;
//   * a decision computed against a superseded policy is never cached — the
//     sequence number carried on the decision is compared against the latest
//     reload notification, and a stale one is dropped rather than stored.

use alloc::vec::Vec;

use crate::sidtab::{HashStats, Sid};

/// Flag: the source domain runs permissive.
pub const AVD_FLAGS_PERMISSIVE: u32 = 0x0001;
/// Flag: denials against this domain are never audited.
pub const AVD_FLAGS_NEVERAUDIT: u32 = 0x0002;

/// Entry count above which an insertion triggers reclaim.
pub const AVC_DEF_CACHE_THRESHOLD: u32 = 512;
/// Entries one reclaim pass tries to free.
pub const AVC_CACHE_RECLAIM: u32 = 16;

/// Largest cache the caller may ask for, bounding the slot allocation against
/// an absurd argument.
const MAX_SLOTS_LOG2: u32 = 16;

/// Shift applied to the target SID when mixing the key, so that swapping
/// source and target selects a different bucket.
const TSID_SHIFT: u32 = 2;
/// Shift applied to the class when mixing the key.
const TCLASS_SHIFT: u32 = 4;

/// One decision: the permission masks the policy yields for a triple.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AvDecision {
    /// Permissions granted.
    pub allowed: u32,
    /// Permissions audited when granted.
    pub auditallow: u32,
    /// Permissions audited when denied.
    pub auditdeny: u32,
    /// Policy sequence number this decision was computed against.
    pub seqno: u32,
    /// `AVD_FLAGS_*` describing the source domain.
    pub flags: u32,
}

impl AvDecision {
    /// Initial state of a decision before any rule is applied. # C: O(1)
    ///
    /// `auditdeny` starts all-ones because auditing is accumulated by AND: a
    /// suppression rule only ever CLEARS bits. Starting at zero would leave
    /// nothing to clear and silently stop auditing every denial.
    pub const fn init(seqno: u32) -> Self {
        Self { allowed: 0, auditallow: 0, auditdeny: u32::MAX, seqno, flags: 0 }
    }
}

/// Cache activity counters.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct CacheStats {
    /// Lookups attempted.
    pub lookups: u64,
    /// Lookups that found no entry.
    pub misses: u64,
    /// Entries created.
    pub allocations: u64,
    /// Reclaim passes run.
    pub reclaims: u64,
    /// Entries destroyed, by reclaim or flush.
    pub frees: u64,
}

/// One cached decision with its key.
struct Node {
    ssid: Sid,
    tsid: Sid,
    tclass: u16,
    avd: AvDecision,
}

/// Access-vector cache.
pub struct Avc {
    /// Buckets of nodes, most recently used first within each bucket.
    slots: Vec<Vec<Node>>,
    /// Bucket selector mask; `slots.len()` is a power of two.
    mask: usize,
    /// Rotating bucket the next reclaim pass starts from, so reclaim spreads
    /// over the whole cache instead of repeatedly emptying one bucket.
    hint: usize,
    /// Entries currently held.
    active: u32,
    /// Entry count above which an insertion reclaims.
    threshold: u32,
    /// Highest policy sequence number seen; decisions older than this are
    /// stale and must not be cached.
    latest_notif: u32,
    stats: CacheStats,
}

impl Avc {
    /// Cache with `1 << slots_log2` buckets. # C: O(slots)
    pub fn new(slots_log2: u32) -> Self {
        let log2 = slots_log2.min(MAX_SLOTS_LOG2);
        let n = 1usize << log2;
        let mut slots = Vec::new();
        slots.resize_with(n, Vec::new);
        Self {
            slots, mask: n - 1, hint: 0, active: 0,
            threshold: AVC_DEF_CACHE_THRESHOLD, latest_notif: 0,
            stats: CacheStats::default(),
        }
    }

    /// Cached decision for the exact triple. # C: O(chain)
    pub fn lookup(&mut self, ssid: Sid, tsid: Sid, tclass: u16) -> Option<AvDecision> {
        self.stats.lookups += 1;
        let b = self.bucket(ssid, tsid, tclass);
        match Self::position(&self.slots[b], ssid, tsid, tclass) {
            Some(i) => {
                // Recency ordering is what makes reclaim drop the coldest
                // entries: it frees from the tail of a bucket.
                self.slots[b][..=i].rotate_right(1);
                Some(self.slots[b][0].avd)
            }
            None => { self.stats.misses += 1; None }
        }
    }

    /// Cache one decision, unless it predates the latest policy. # C: O(chain)
    pub fn insert(&mut self, ssid: Sid, tsid: Sid, tclass: u16, avd: AvDecision) {
        if avd.seqno > self.latest_notif { self.latest_notif = avd.seqno; }
        if avd.seqno < self.latest_notif { return; }
        let b = self.bucket(ssid, tsid, tclass);
        if let Some(i) = Self::position(&self.slots[b], ssid, tsid, tclass) {
            self.slots[b][i].avd = avd;
            self.slots[b][..=i].rotate_right(1);
            return;
        }
        if self.slots[b].try_reserve(1).is_err() { return; }
        self.slots[b].insert(0, Node { ssid, tsid, tclass, avd });
        self.stats.allocations += 1;
        self.active += 1;
        if self.active > self.threshold { self.reclaim(); }
    }

    /// Widen a cached decision's allowed mask, for a permissive-domain grant. # C: O(chain)
    ///
    /// Without this a permissive domain re-consults the policy on every repeat
    /// of the same denied access, since the cached decision keeps refusing it.
    pub fn grant(&mut self, ssid: Sid, tsid: Sid, tclass: u16, perms: u32) {
        let b = self.bucket(ssid, tsid, tclass);
        if let Some(i) = Self::position(&self.slots[b], ssid, tsid, tclass) {
            self.slots[b][i].avd.allowed |= perms;
        }
    }

    /// Drop every entry. # C: O(entries)
    pub fn flush(&mut self) {
        for s in &mut self.slots { s.clear(); }
        self.stats.frees += u64::from(self.active);
        self.active = 0;
    }

    /// Drop every entry and record that decisions older than `seqno` are
    /// stale. # C: O(entries)
    pub fn reset(&mut self, seqno: u32) {
        self.flush();
        self.latest_notif = seqno;
    }

    /// Highest policy sequence number this cache has seen. # C: O(1)
    pub fn latest_notif(&self) -> u32 { self.latest_notif }

    /// Set the entry count above which an insertion reclaims. # C: O(1)
    pub fn set_threshold(&mut self, n: u32) { self.threshold = n; }

    /// Entry count above which an insertion reclaims. # C: O(1)
    pub fn threshold(&self) -> u32 { self.threshold }

    /// Entries currently held. # C: O(1)
    pub fn active_nodes(&self) -> u32 { self.active }

    /// Activity counters. # C: O(1)
    pub fn stats(&self) -> CacheStats { self.stats }

    /// Shape of the bucket array. # C: O(slots)
    pub fn hash_stats(&self) -> HashStats {
        let mut st = HashStats {
            entries: 0, buckets: self.slots.len() as u32,
            used_buckets: 0, longest_chain: 0,
        };
        for s in &self.slots {
            let n = s.len() as u32;
            if n == 0 { continue; }
            st.entries += n;
            st.used_buckets += 1;
            if n > st.longest_chain { st.longest_chain = n; }
        }
        st
    }

    /// Bucket holding this triple. # C: O(1)
    fn bucket(&self, ssid: Sid, tsid: Sid, tclass: u16) -> usize {
        let h = ssid ^ (tsid << TSID_SHIFT) ^ (u32::from(tclass) << TCLASS_SHIFT);
        (h as usize) & self.mask
    }

    /// Index of the node matching all three key components. # C: O(chain)
    fn position(slot: &[Node], ssid: Sid, tsid: Sid, tclass: u16) -> Option<usize> {
        slot.iter().position(|n| n.ssid == ssid && n.tsid == tsid && n.tclass == tclass)
    }

    /// Free up to `AVC_CACHE_RECLAIM` coldest entries, starting at the
    /// rotating hint. # C: O(slots)
    fn reclaim(&mut self) {
        let mut freed = 0u32;
        for _ in 0..self.slots.len() {
            let i = self.hint;
            self.hint = (self.hint + 1) & self.mask;
            while freed < AVC_CACHE_RECLAIM && self.slots[i].pop().is_some() {
                freed += 1;
                self.active -= 1;
            }
            if freed >= AVC_CACHE_RECLAIM { break; }
        }
        self.stats.reclaims += 1;
        self.stats.frees += u64::from(freed);
    }
}

#[cfg(test)]
#[path = "tests/avc.rs"]
mod tests;
