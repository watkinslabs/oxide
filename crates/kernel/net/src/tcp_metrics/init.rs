// What a cached destination row seeds into a connection that has just
// finished its handshake.
//
// The point is the first retransmit timeout. A handshake measures its RTT on
// a SYN and a SYN-ACK, which are small and often delayed differently from
// data, so the reference does NOT let that sample drive the estimator. It
// seeds the timeout from the cached round-trip time instead and leaves the
// estimator's own variables alone, so the first data acknowledgement replaces
// the seed with a real measurement.
//
// A connection that got no RTT sample at all — its SYN was retransmitted, or
// it was rebuilt from a cookie — and finds no cached value falls back to a
// conservative timeout rather than the aggressive one a fresh socket carries.

use super::ids;

/// The cached row a new connection is seeded from.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct CachedMetrics {
    pub vals: [u32; ids::COUNT],
    pub lock: u32,
}

impl CachedMetrics {
    /// # C: O(1)
    pub const fn get(&self, metric: usize) -> u32 { self.vals[metric] }
    /// # C: O(1)
    pub const fn locked(&self, metric: usize) -> bool { ids::locked(self.lock, metric) }
    /// Whether any metric is held for this destination. # C: O(COUNT)
    pub fn is_empty(&self) -> bool { self.vals.iter().all(|value| *value == 0) }
}

/// The connection state the seed is decided against, as it stands when the
/// handshake completes.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Fresh {
    /// Smoothed round-trip time the handshake produced, in microseconds.
    /// Zero means the handshake produced no usable sample.
    pub srtt: u32,
    /// The connection's own congestion-window ceiling before the cache spoke.
    pub cwnd_clamp: u32,
    /// The namespace's `net.ipv4.tcp_reordering`, which is what the
    /// connection carries until a cached value replaces it.
    pub reordering: u32,
    /// `tcp_rto_min` for this connection's route.
    pub rto_min_ns: u64,
    /// `net.ipv4.tcp_no_ssthresh_metrics_save`: the cached slow-start
    /// threshold is not believed.
    pub no_ssthresh_save: bool,
}

/// `TCP_INFINITE_SSTHRESH`: the value a connection carries while slow start
/// has not been left. The handshake may have reduced the threshold for no
/// good reason, so it is restored before the cache is consulted.
pub const INFINITE_SSTHRESH: u32 = 0x7fff_ffff;

/// Conservative retransmit timeout for a connection that measured nothing.
/// The aggressive one a fresh socket carries produces spurious retransmits
/// when the handshake itself was already retransmitting.
pub const TIMEOUT_FALLBACK_NS: u64 = 3_000_000_000;

/// What a connection adopts from the cache.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Seed {
    pub ssthresh: u32,
    pub cwnd_clamp: u32,
    pub reordering: u32,
    /// Retransmit timeout, when the cache or the missing sample names one.
    /// `None` leaves the connection's own.
    pub rto_ns: Option<u64>,
    /// Reset the round-trip variation to the fallback timeout: the handshake
    /// produced no sample, so the estimator has nothing of its own either.
    pub reset_rttvar: bool,
}

/// Nanoseconds per unit of the stored round-trip scale, which is plain
/// microseconds — the unit the microsecond ABI attribute reports raw.
const NS_PER_RTT_UNIT: u64 = 1_000;

/// Seed one new connection from what this host remembers about the
/// destination. # C: O(1)
pub fn seed(cached: CachedMetrics, fresh: Fresh) -> Seed {
    // The handshake may have cut the threshold; it is restored first, so a
    // cache that says nothing leaves the connection at the default rather
    // than at whatever the handshake happened to reach.
    let mut ssthresh = INFINITE_SSTHRESH;
    let mut cwnd_clamp = fresh.cwnd_clamp;
    let mut reordering = fresh.reordering;

    if cached.locked(ids::CWND) { cwnd_clamp = cached.get(ids::CWND); }
    let stored = if fresh.no_ssthresh_save { 0 } else { cached.get(ids::SSTHRESH) };
    if stored != 0 { ssthresh = core::cmp::min(stored, cwnd_clamp); }
    let stored = cached.get(ids::REORDERING);
    if stored != 0 { reordering = stored; }

    let crtt = cached.get(ids::RTT);
    if crtt > fresh.srtt {
        // The same shape the estimator uses, from the cached value: one
        // round trip plus twice its own variation, floored at the route's
        // minimum.
        let crtt_ns = u64::from(crtt) * NS_PER_RTT_UNIT;
        let rto = crtt_ns.saturating_add(
            core::cmp::max(crtt_ns.saturating_mul(2), fresh.rto_min_ns));
        return Seed { ssthresh, cwnd_clamp, reordering, rto_ns: Some(rto),
            reset_rttvar: false };
    }
    if fresh.srtt == 0 {
        return Seed { ssthresh, cwnd_clamp, reordering,
            rto_ns: Some(TIMEOUT_FALLBACK_NS), reset_rttvar: true };
    }
    Seed { ssthresh, cwnd_clamp, reordering, rto_ns: None, reset_rttvar: false }
}

#[cfg(test)]
#[path = "init_tests.rs"]
mod tests;
