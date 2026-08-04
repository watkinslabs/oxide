//! Timers and retransmission.

use crate::tcp_conn::TcpConn;

/// Segments in flight below which duplicate-acknowledgement recovery cannot
/// fire, so the stream is "thin" for `TCP_THIN_LINEAR_TIMEOUTS`.
pub const THIN_STREAM_SEGMENTS: usize = 4;

impl TcpConn {
    /// Update SRTT/RTTVAR/RTO from a new sample (RFC 6298 §2.2-2.3).
    /// `r_ns` is the measured RTT.
    /// # C: O(1)
    pub fn update_rtt(&mut self, r_ns: u64) {
        if self.srtt_ns == 0 {
            self.srtt_ns   = r_ns;
            self.rttvar_ns = r_ns / 2;
        } else {
            let diff = if r_ns > self.srtt_ns { r_ns - self.srtt_ns } else { self.srtt_ns - r_ns };
            self.rttvar_ns = (3 * self.rttvar_ns + diff) / 4;
            self.srtt_ns   = (7 * self.srtt_ns + r_ns) / 8;
        }
        let k4 = self.rttvar_ns.saturating_mul(4);
        let g  = 10_000_000u64;
        self.rto_ns = self.srtt_ns + core::cmp::max(g, k4);
        if self.rto_ns < self.rto_min_ns {
            self.rto_ns = self.rto_min_ns;
        }
        if self.rto_ns > self.rto_max_ns {
            self.rto_ns = self.rto_max_ns;
        }
    }

    /// Walk retransmit queue at `now_ns` and re-emit expired entries.
    /// # C: O(retx_q.len())
    pub fn retransmit_due(&mut self, now_ns: u64) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let mut out = alloc::vec::Vec::new();
        // Repair holds the sequence state still, so nothing may be re-sent
        // from under the process restoring it.
        if self.repair { return out; }
        // The user timeout is measured from when the queue first went
        // unacknowledged, not from the last retransmit, so the mark is taken
        // when the queue becomes non-empty and cleared when it drains.
        if self.retx_q.is_empty() { self.first_unacked_ns = 0; }
        else if self.first_unacked_ns == 0 { self.first_unacked_ns = now_ns; }
        let rto = self.rto_ns;
        let mut expired = alloc::vec::Vec::new();
        // Nothing behind the head goes out before the handshake finishes: a
        // fast open leaves its data queued behind the SYN, and that data is
        // only sendable once there is a connection to send it on.
        let handshaking = self.state == crate::tcp_state::TcpState::SynSent;
        for (i, s) in self.retx_q.iter().enumerate() {
            if handshaking && i > 0 { break; }
            if s.sacked { continue; }
            if now_ns.saturating_sub(s.last_sent_ns) >= rto {
                expired.push(i);
            }
        }
        for i in &expired {
            let seg = {
                let s = &self.retx_q[*i];
                self.bytes_retrans = self.bytes_retrans.saturating_add(s.payload.len() as u64);
                self.build_retx(s)
            };
            out.push(seg);
            let s = &mut self.retx_q[*i];
            s.last_sent_ns = now_ns;
            s.retries += 1;
        }
        if !out.is_empty() {
            // A thin stream has too few segments in flight to trigger fast
            // retransmit, so doubling the timer after every loss compounds
            // into seconds of stall; the flat timer keeps recovery at one RTO.
            if !self.thin_lto || !self.is_thin_stream() {
                self.rto_ns = core::cmp::min(self.rto_ns.saturating_mul(2), self.rto_max_ns);
            }
            self.cc_on_rto();
        }
        out
    }

    /// Whether the acknowledgement owed for freshly received in-order data
    /// goes out at once. Quick-ACK mode always acknowledges immediately;
    /// otherwise the socket is in ping-pong mode and holds the ACK back so it
    /// can ride the application's reply, unless more than a full segment has
    /// gone unacknowledged — at which point the peer's window would stall.
    /// # C: O(1)
    pub fn ack_now(&self) -> bool {
        if self.quickack || self.repair { return true; }
        let unacked = self.rcv_nxt.wrapping_sub(self.rcv_wup);
        unacked > crate::tcp_cc::cc_mss(self)
    }

    /// Drive the delayed-acknowledgement deadline. Returns the acknowledgement
    /// once the socket has held it as long as `TCP_DELACK_MAX_US` allows.
    /// # C: O(sack blocks)
    pub fn delayed_ack_due(&mut self, now_ns: u64) -> Option<alloc::vec::Vec<u8>> {
        if !self.ack_pending { return None; }
        if self.ack_deadline_ns == 0 {
            self.ack_deadline_ns = now_ns.saturating_add(self.delack_ato_ns());
            return None;
        }
        if now_ns < self.ack_deadline_ns { return None; }
        self.ack_pending = false;
        self.ack_deadline_ns = 0;
        if !self.quickack {
            self.delack_ato_ns = self.delack_ato_ns().saturating_mul(2).min(self.rto_ns);
        }
        self.rcv_wup = self.rcv_nxt;
        Some(self.build_ack_with_sack())
    }

    /// A stream with too few packets in flight for duplicate-acknowledgement
    /// recovery to ever fire. # C: O(1)
    pub fn is_thin_stream(&self) -> bool { self.retx_q.len() < THIN_STREAM_SEGMENTS }

    /// Whether the connection has gone unacknowledged past the caller's
    /// `TCP_USER_TIMEOUT`. # C: O(1)
    pub fn user_timeout_expired(&self, now_ns: u64) -> bool {
        if self.user_timeout_ns == 0 || self.retx_q.is_empty() { return false; }
        if self.first_unacked_ns == 0 { return false; }
        now_ns.saturating_sub(self.first_unacked_ns) >= self.user_timeout_ns
    }

    /// Whether FIN-WAIT-2 has been held past `TCP_LINGER2`. `entered_ns` is
    /// when the state was entered. # C: O(1)
    pub fn linger2_expired(&self, entered_ns: u64, now_ns: u64) -> bool {
        now_ns.saturating_sub(entered_ns) >= self.linger2_ns
    }

}
