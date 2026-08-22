// The two moments a connection talks to the destination metrics cache: it
// reads the cache once, when its handshake finishes, and writes back once,
// when it closes.
//
// Everything the cache holds is in the units the metrics ABI reports —
// microseconds for the round trip, SEGMENTS for the windows — while this
// connection carries its windows in bytes. The conversion lives here, at the
// boundary, so neither the cache nor the congestion control has to know about
// the other's unit.

use super::TcpConn;
use crate::tcp_metrics::{init, update};

/// Nanoseconds in one microsecond.
const NS_PER_US: u64 = 1_000;

/// This connection's segment size for the window conversion. A connection
/// that never learned one converts against nothing, so its windows are not
/// offered to the cache at all. # C: O(1)
fn segment(conn: &TcpConn) -> u32 {
    let mss = if conn.peer_mss != 0 { conn.peer_mss } else { conn.own_mss };
    u32::from(mss)
}

/// Windows in segments, as the ABI counts them. # C: O(1)
fn segments(bytes: u32, mss: u32) -> u32 {
    if mss == 0 { 0 } else { bytes / mss }
}

/// Windows in bytes, as this connection counts them. # C: O(1)
fn bytes(segments: u32, mss: u32) -> u32 { segments.saturating_mul(mss) }

impl TcpConn {
    /// Microseconds, from this connection's nanosecond estimator. # C: O(1)
    fn srtt_us(&self) -> u32 { u32::try_from(self.srtt_ns / NS_PER_US).unwrap_or(u32::MAX) }

    /// How this connection stands when its handshake finishes, in the terms
    /// the cache's seed is decided from. # C: O(1)
    pub fn metrics_fresh(&self, reordering: u32, no_ssthresh_save: bool) -> init::Fresh {
        let mss = segment(self);
        init::Fresh {
            srtt: self.srtt_us(),
            cwnd_clamp: segments(self.cwnd_clamp, mss),
            reordering,
            rto_min_ns: self.rto_min_ns,
            no_ssthresh_save,
        }
    }

    /// Adopt what the cache remembered about this destination.
    ///
    /// The retransmit timeout is the point: the handshake's own round-trip
    /// sample is taken on SYN-sized segments and is a poor guide to how data
    /// will behave, so the cached value seeds the timeout while the
    /// estimator's own variables are left for the first data acknowledgement
    /// to fill in. # C: O(1)
    pub fn apply_metrics_seed(&mut self, seed: init::Seed) {
        let mss = segment(self);
        self.ssthresh = if seed.ssthresh == init::INFINITE_SSTHRESH {
            u32::MAX
        } else {
            bytes(seed.ssthresh, mss)
        };
        if seed.cwnd_clamp != 0 {
            let clamp = bytes(seed.cwnd_clamp, mss);
            if clamp != 0 { self.cwnd_clamp = clamp; }
        }
        if seed.reordering != 0 { self.reordering = seed.reordering; }
        if seed.reset_rttvar { self.rttvar_ns = init::TIMEOUT_FALLBACK_NS; }
        if let Some(rto_ns) = seed.rto_ns {
            self.rto_ns = core::cmp::min(rto_ns, self.rto_max_ns);
        }
    }

    /// What this connection leaves behind about its destination. # C: O(1)
    pub fn metrics_closing(&self, default_reordering: u32, no_ssthresh_save: bool)
        -> update::Closing
    {
        let mss = segment(self);
        // The threshold is only meaningful once something reduced it; while
        // it is still infinite the connection has not left slow start.
        let in_initial_slow_start = self.ssthresh == u32::MAX;
        let phase = if in_initial_slow_start {
            update::Phase::InitialSlowStart
        } else if self.cwnd >= self.ssthresh && self.dup_acks == 0 {
            update::Phase::Open
        } else {
            update::Phase::Lossy
        };
        update::Closing {
            srtt: self.srtt_us(),
            mdev: u32::try_from(self.rttvar_ns / NS_PER_US).unwrap_or(u32::MAX),
            cwnd: segments(self.cwnd, mss),
            ssthresh: if in_initial_slow_start { 0 } else { segments(self.ssthresh, mss) },
            reordering: self.reordering,
            phase,
            // A connection whose retransmit timer had doubled past its floor
            // was backing off, so nothing it measured describes the path.
            backing_off: self.rto_ns > self.rto_min_ns.saturating_mul(2),
            no_ssthresh_save,
            default_reordering,
        }
    }

    /// Whether this connection has anything to tell the cache. A connection
    /// that never left the handshake, or never learned a segment size,
    /// measured nothing worth remembering. # C: O(1)
    pub fn metrics_worth_recording(&self) -> bool {
        segment(self) != 0 && self.srtt_ns != 0
    }
}

#[cfg(test)]
#[path = "metrics_tests.rs"]
mod tests;
