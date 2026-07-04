//! Timers and retransmission.

use crate::tcp_conn::TcpConn;

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
        if self.rto_ns < 200_000_000 {
            self.rto_ns = 200_000_000;
        }
        if self.rto_ns > 60_000_000_000 {
            self.rto_ns = 60_000_000_000;
        }
    }

    /// Walk retransmit queue at `now_ns` and re-emit expired entries.
    /// # C: O(retx_q.len())
    pub fn retransmit_due(&mut self, now_ns: u64) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let mut out = alloc::vec::Vec::new();
        let rto = self.rto_ns;
        let mut expired = alloc::vec::Vec::new();
        for (i, s) in self.retx_q.iter().enumerate() {
            if s.sacked { continue; }
            if now_ns.saturating_sub(s.last_sent_ns) >= rto {
                expired.push(i);
            }
        }
        for i in &expired {
            let seg = {
                let s = &self.retx_q[*i];
                self.build_retx(s)
            };
            out.push(seg);
            let s = &mut self.retx_q[*i];
            s.last_sent_ns = now_ns;
            s.retries += 1;
        }
        if !out.is_empty() {
            self.rto_ns = core::cmp::min(self.rto_ns.saturating_mul(2), 60_000_000_000);
            self.cc_on_rto();
        }
        out
    }

}
