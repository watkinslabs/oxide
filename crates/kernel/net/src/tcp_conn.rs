// TCP connection (TCB) per RFC 9293 §3.3.1, driven by the
// existing `tcp_state` transition table. v1 minimum:
//   - Active connect (client): emit SYN; on SYN+ACK → ESTABLISHED.
//   - Passive listen+accept (server): on incoming SYN → emit
//     SYN+ACK; on the matching ACK → ESTABLISHED.
//   - Bidirectional data: send_buf + recv_buf VecDeque<u8>.
//     output() drains send_buf into PSH+ACK segments; input()
//     applies received bytes to recv_buf and ACKs.
//   - Graceful close: send_fin() emits FIN, transitions to
//     FinWait1; on remote FIN, CloseWait then LastAck.
//
// Out of scope (next PRs): retransmission timer, congestion
// control (Cubic / BBR), window scaling, SACK, timestamps, TFO,
// listen backlog > 1.

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use crate::addr::{IpAddr, Ipv4Addr};
use crate::tcp_hdr::{TcpHdr, TCP_HDR_MIN_LEN, flags};
use crate::tcp_state::{TcpEvent, TcpState, transition};

/// Endpoint = (ip, port). F180b: `ip` is `IpAddr` (V4 or V6) so a
/// single TcpConn handles both families; `build_segment` dispatches
/// to the matching pseudo-header for checksum.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Endpoint { pub ip: IpAddr, pub port: u16 }

/// One unacked transmission record on the retransmit queue.
/// Tracks the seq the segment occupies + when it was sent so
/// the RTO timer can re-emit it on timeout. F179: `sacked`
/// marks segments the peer has confirmed receipt of via SACK;
/// `retransmit_due` skips them.
#[derive(Clone, Debug)]
pub struct UnackedSegment {
    pub seq:        u32,
    pub flags:      u8,
    pub payload:    alloc::vec::Vec<u8>,
    pub last_sent_ns: u64,
    pub retries:    u32,
    pub sacked:     bool,
}

#[derive(Debug)]
pub struct TcpConn {
    pub local:  Endpoint,
    pub remote: Endpoint,
    pub state:  TcpState,
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub rcv_nxt: u32,
    pub window:  u16,
    pub send_buf: VecDeque<u8>,
    pub recv_buf: VecDeque<u8>,
    /// Retransmission queue. Cleared on receipt of cumulative
    /// ACKs; retransmit_due() re-emits expired entries.
    pub retx_q:   VecDeque<UnackedSegment>,
    /// Smoothed round-trip time (ns). Initialised to 1s — the
    /// RFC 6298 §2.1 default before the first RTT sample.
    pub srtt_ns:    u64,
    /// Mean deviation (ns). RFC 6298 §2.3.
    pub rttvar_ns:  u64,
    /// Current RTO (ns). Caller polls retransmit_due(now) to
    /// discover when this expires; on every timeout RTO doubles
    /// (exponential backoff per `25§7`).
    pub rto_ns:     u64,
    /// F161: TimeWait entry timestamp (0 before entry, 2*MSL reap).
    pub tw_start_ns: u64,
    /// F163: async error surfaced via SO_ERROR (Linux errno).
    pub error_eno: i32,
    /// F173: peer-advertised MSS (0 = not yet observed).
    pub peer_mss: u16,
    /// F178: WSCALE (RFC 7323). 0 = no scaling.
    pub snd_wscale: u8,
    pub rcv_wscale: u8,
    /// Peer's currently-advertised window size in bytes (after
    /// applying rcv_wscale). Bounds the in-flight byte count
    /// output() will emit.
    pub snd_wnd: u32,
    /// F179: out-of-order recv stash (drained on gap-fill).
    pub ooo_buf: BTreeMap<u32, Vec<u8>>,
    /// F182: TS option state (RFC 7323) + PAWS drop on stale TSval.
    pub ts_enabled: bool,
    pub ts_recent:  u32,
    /// F184: MSS we advertise (0 = OWN_MSS_DEFAULT).
    pub own_mss: u16,
    /// F185+F187: CUBIC CC state (cwnd, ssthresh, dup-ack counter).
    pub cwnd:     u32,
    pub ssthresh: u32,
    pub dup_acks: u8,
    /// F187: CUBIC epoch + W_max (RFC 8312).
    pub cubic_w_max:    u32,
    pub cubic_epoch_ms: u32,
    pub cubic_k_ms:     u32,
    /// F186: recv-buf cap + autotune peak (× ≤ rcv_buf_max).
    pub rcv_buf_cap: u32,
    pub rcv_buf_max: u32,
    pub rcv_peak: u32,
    /// F190: ECN (negotiate via SYN ECE+CWR; arm CWR on next data,
    /// ECE on ACKs while we owe peer a congestion echo).
    pub ecn_enabled: bool,
    pub send_ece:    bool,
    pub send_cwr:    bool,
    pub ecn_last_reduce_ms: u32,
    /// F193: SO_KEEPALIVE state (defaults 7200s/75s/9).
    pub ka_enabled:  bool,
    pub ka_idle_ns:  u64,
    pub ka_intvl_ns: u64,
    pub ka_cnt_max:  u32,
    pub ka_count:    u32,
    pub last_rx_ns:  u64,
    pub next_ka_ns:  u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TcpConnError {
    BadState,
    BadHdr,
    Reset,
}

impl TcpConn {
    /// Build a brand-new client TCB. State starts CLOSED; caller
    /// then calls `active_open` to emit the initial SYN.
    /// # C: O(1)
    pub fn new_client(local: Endpoint, remote: Endpoint, isn: u32) -> Self {
        Self {
            local, remote,
            state: TcpState::Closed,
            snd_una: isn,
            snd_nxt: isn,
            rcv_nxt: 0,
            window:  65535,
            send_buf: VecDeque::new(),
            recv_buf: VecDeque::new(),
            retx_q:   VecDeque::new(),
            srtt_ns:  0,
            rttvar_ns: 0,
            rto_ns:   1_000_000_000,    // RFC 6298 §2.1 initial RTO = 1 s
            tw_start_ns: 0,
            error_eno: 0,
            peer_mss: 0,
            snd_wscale: 0,
            rcv_wscale: 0,
            snd_wnd: 65535,
            ooo_buf: BTreeMap::new(),
            ts_enabled: false,
            ts_recent:  0,
            own_mss:    0,
            cwnd:       10 * (OWN_MSS_DEFAULT as u32),
            ssthresh:   u32::MAX,
            dup_acks:   0,
            rcv_buf_cap: 65_536,
            rcv_buf_max: 4 * 1024 * 1024,
            rcv_peak:    0,
            cubic_w_max:    0,
            cubic_epoch_ms: 0,
            cubic_k_ms:     0,
            ecn_enabled: false,
            send_ece:    false,
            send_cwr:    false,
            ecn_last_reduce_ms: 0,
            ka_enabled:  false,
            ka_idle_ns:  7_200_000_000_000,
            ka_intvl_ns:    75_000_000_000,
            ka_cnt_max:  9,
            ka_count:    0,
            last_rx_ns:  0,
            next_ka_ns:  0,
        }
    }

    /// Build a brand-new listener TCB. State starts LISTEN.
    /// # C: O(1)
    pub fn new_listener(local: Endpoint) -> Self {
        Self {
            local,
            remote: Endpoint { ip: IpAddr::V4(Ipv4Addr::ANY), port: 0 },
            state: TcpState::Listen,
            snd_una: 0, snd_nxt: 0, rcv_nxt: 0, window: 65535,
            send_buf: VecDeque::new(), recv_buf: VecDeque::new(),
            retx_q:   VecDeque::new(),
            srtt_ns:  0, rttvar_ns: 0,
            rto_ns:   1_000_000_000,
            tw_start_ns: 0,
            error_eno: 0,
            peer_mss: 0,
            snd_wscale: 0,
            rcv_wscale: 0,
            snd_wnd: 65535,
            ooo_buf: BTreeMap::new(),
            ts_enabled: false,
            ts_recent:  0,
            own_mss:    0,
            cwnd:       10 * (OWN_MSS_DEFAULT as u32),
            ssthresh:   u32::MAX,
            dup_acks:   0,
            rcv_buf_cap: 65_536,
            rcv_buf_max: 4 * 1024 * 1024,
            rcv_peak:    0,
            cubic_w_max:    0,
            cubic_epoch_ms: 0,
            cubic_k_ms:     0,
            ecn_enabled: false,
            send_ece:    false,
            send_cwr:    false,
            ecn_last_reduce_ms: 0,
            ka_enabled:  false,
            ka_idle_ns:  7_200_000_000_000,
            ka_intvl_ns:    75_000_000_000,
            ka_cnt_max:  9,
            ka_count:    0,
            last_rx_ns:  0,
            next_ka_ns:  0,
        }
    }

    /// F161: graceful close from kernel-side `Drop`. RST if mid-handshake
    /// (peer never saw data); FIN if Established / CloseWait; no-op in
    /// closing-states. Returns the segment caller should xmit.
    /// # C: O(1)
    pub fn drop_close(&mut self) -> Option<Vec<u8>> {
        use crate::tcp_hdr::flags;
        match self.state {
            TcpState::SynSent | TcpState::SynRecv => {
                let seg = self.build_segment(flags::RST, &[]);
                self.state = TcpState::Closed;
                Some(seg)
            }
            TcpState::Established | TcpState::CloseWait => self.local_close().ok(),
            _ => None,
        }
    }

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
        // RTO = SRTT + max(G, K * RTTVAR), K=4, G=10ms granularity.
        let k4 = self.rttvar_ns.saturating_mul(4);
        let g  = 10_000_000u64;
        self.rto_ns = self.srtt_ns + core::cmp::max(g, k4);
        // Clamp 200 ms .. 60 s.
        if self.rto_ns < 200_000_000 { self.rto_ns = 200_000_000; }
        if self.rto_ns > 60_000_000_000 { self.rto_ns = 60_000_000_000; }
    }

    /// Walk the retransmit queue at `now_ns` and re-emit segments
    /// whose `last_sent + rto` has expired. Doubles RTO each
    /// retransmit (exponential backoff). Bumps `retries`; caller
    /// can drop the conn after N retries (v1: caller's policy).
    /// Returns the segments to xmit (caller wraps in IPv4 + sends).
    /// # C: O(retx_q.len())
    pub fn retransmit_due(&mut self, now_ns: u64) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let mut out = alloc::vec::Vec::new();
        let rto = self.rto_ns;
        // F179a: skip entries the peer has SACKed; their loss-recovery
        // burden is gone. Only un-sacked + expired entries re-emit.
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
            // Exponential backoff per RFC 6298 §5.5 — double RTO
            // each timeout, capped at 60 s.
            self.rto_ns = core::cmp::min(self.rto_ns.saturating_mul(2), 60_000_000_000);
            // F185: RTO loss event. RFC 5681 §3.1 step 2: ssthresh =
            // max(FlightSize/2, 2*MSS); cwnd = MSS; dup_acks = 0.
            self.cc_on_rto();
        }
        out
    }

    /// F193: keepalive scheduler — delegate to tcp_cc. # C: O(1)
    pub fn keepalive_due(&mut self, now_ns: u64) -> Option<Vec<u8>> {
        crate::tcp_cc::keepalive_due(self, now_ns)
    }
    /// F193: build a 0-byte probe at seq=snd_una-1. # C: O(1)
    pub(crate) fn build_keepalive_probe(&mut self) -> Vec<u8> {
        let saved = self.snd_nxt;
        self.snd_nxt = self.snd_una.wrapping_sub(1);
        let seg = self.build_segment(flags::ACK, &[]);
        self.snd_nxt = saved;
        seg
    }

    /// F185+F187: CC API delegates to tcp_cc module. # C: O(1)
    pub fn cc_on_ack(&mut self, acked: u32, payload_len: u32) {
        crate::tcp_cc::on_ack(self, acked, payload_len)
    }
    /// F187: RTO loss event. # C: O(1)
    pub fn cc_on_rto(&mut self) { crate::tcp_cc::on_rto(self) }
    /// F187: test hook for icbrt. # C: O(log x)
    #[cfg(test)]
    pub fn icbrt_test(x: u64) -> u64 { crate::tcp_cc::icbrt(x) }

    /// F186: window value to advertise on the wire = free recv-buf
    /// bytes, shifted right by snd_wscale per RFC 7323 §2.1. Clamped
    /// to u16 (the TCP header field width).
    /// # C: O(1)
    pub fn current_rcv_window(&self) -> u16 {
        let free = (self.rcv_buf_cap as usize).saturating_sub(self.recv_buf.len()) as u32;
        let scaled = free >> self.snd_wscale;
        if scaled > u16::MAX as u32 { u16::MAX } else { scaled as u16 }
    }

    /// F186: bump rcv_buf_cap when recent peak fill > cap/2 (Linux
    /// tcp_rcv_space_adjust shape). Caller invokes after appending
    /// to recv_buf so the next ACK reflects the larger window.
    /// # C: O(1)
    pub fn rcv_autotune(&mut self) {
        let len = self.recv_buf.len() as u32;
        if len > self.rcv_peak { self.rcv_peak = len; }
        if self.rcv_peak > self.rcv_buf_cap / 2 && self.rcv_buf_cap < self.rcv_buf_max {
            self.rcv_buf_cap = core::cmp::min(self.rcv_buf_cap.saturating_mul(2), self.rcv_buf_max);
            self.rcv_peak = 0;
        }
    }

    fn build_retx(&self, s: &UnackedSegment) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN + s.payload.len()];
        let mut h = TcpHdr {
            src_port: self.local.port, dst_port: self.remote.port,
            seq: s.seq, ack: self.rcv_nxt,
            data_offset: 5, flags: s.flags, window: self.current_rcv_window(),
            checksum: 0, urg_ptr: 0,
        };
        if !s.payload.is_empty() {
            buf[crate::tcp_hdr::TCP_HDR_MIN_LEN..].copy_from_slice(&s.payload);
        }
        h.build_into_ip(self.local.ip, self.remote.ip, &mut buf);
        buf
    }

    /// Client active open: emit a SYN with MSS + WindowScale,
    /// transition to SynSent. F178: we always advertise WSCALE on
    /// the active open; peer's response determines if scaling
    /// engages (RFC 7323 §1.3).
    /// # C: O(1)
    pub fn active_open(&mut self) -> Result<Vec<u8>, TcpConnError> {
        let new_state = transition(self.state, TcpEvent::ActiveOpen)
            .ok_or(TcpConnError::BadState)?;
        let seq_start = self.snd_nxt;
        self.snd_wscale = OWN_WSCALE;
        // F190: advertise ECN-capable per RFC 3168 §6.1.1. Peer
        // confirms by echoing ECE (without CWR) in the SYN-ACK.
        let seg = self.build_syn_with_opts(flags::SYN | flags::ECE | flags::CWR);
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        self.state = new_state;
        // SYN consumes one sequence; track for retransmit.
        self.retx_q.push_back(UnackedSegment {
            seq: seq_start, flags: flags::SYN, payload: alloc::vec::Vec::new(),
            last_sent_ns: 0, retries: 0, sacked: false,
        });
        Ok(seg)
    }

    /// Apply a received segment. Caller (IPv4 demux) supplies the
    /// L3 src/dst addresses so the pseudo-header checksum can be
    /// validated. Drives the state machine, applies payload bytes
    /// to `recv_buf`, possibly emits a response segment.
    /// # C: O(payload size)
    pub fn input(&mut self, src_ip: IpAddr, dst_ip: IpAddr, seg: &[u8])
        -> Result<Option<Vec<u8>>, TcpConnError>
    {
        let hdr = crate::tcp_hdr::parse_ip(seg, src_ip, dst_ip)
            .map_err(|_| TcpConnError::BadHdr)?;
        // F193: any segment from peer resets the idle timer.
        self.last_rx_ns = ka_now_ns();
        self.ka_count = 0;
        if (hdr.flags & flags::RST) != 0 {
            // F163: surface as SO_ERROR. RST during SynSent (peer
            // refused connection) is ECONNREFUSED (Linux errno 111);
            // RST after Established maps to ECONNRESET (104). Set
            // only if no prior error is pending so the first cause
            // wins.
            if self.error_eno == 0 {
                self.error_eno = if self.state == TcpState::SynSent {
                    syscall::errno::Errno::Econnrefused as i32
                } else {
                    syscall::errno::Errno::Econnreset as i32
                };
            }
            self.state = TcpState::Closed;
            return Ok(None);
        }
        match self.state {
            TcpState::Listen if (hdr.flags & flags::SYN) != 0 => {
                // SYN arrived. Adopt remote endpoint, emit SYN+ACK.
                self.remote = Endpoint { ip: src_ip, port: hdr.src_port };
                self.rcv_nxt = hdr.seq.wrapping_add(1);
                self.snd_una = 0;
                self.snd_nxt = 0;
                if let Some(m) = crate::tcp_hdr::parse_mss_option(seg) { self.peer_mss = m; }
                if let Some(s) = crate::tcp_hdr::parse_wscale_option(seg) {
                    self.rcv_wscale = s;
                    self.snd_wscale = OWN_WSCALE;
                }
                // F182: mutual TS negotiation.
                if let Some((tsval, _)) = crate::tcp_hdr::parse_ts_option(seg) {
                    self.ts_enabled = true;
                    self.ts_recent  = tsval;
                }
                self.snd_wnd = hdr.window as u32;
                self.state = transition(self.state, TcpEvent::RecvSyn)
                    .ok_or(TcpConnError::BadState)?;
                // F190: peer's SYN carrying ECE+CWR offers ECN.
                // Our SYN-ACK answers with ECE-only to confirm.
                let mut sa_flags = flags::SYN | flags::ACK;
                if (hdr.flags & (flags::ECE | flags::CWR)) == (flags::ECE | flags::CWR) {
                    self.ecn_enabled = true;
                    sa_flags |= flags::ECE;
                }
                let resp = self.build_syn_with_opts(sa_flags);
                self.snd_nxt = self.snd_nxt.wrapping_add(1);
                Ok(Some(resp))
            }
            TcpState::SynSent if (hdr.flags & (flags::SYN | flags::ACK)) == (flags::SYN | flags::ACK) => {
                self.rcv_nxt = hdr.seq.wrapping_add(1);
                self.snd_una = hdr.ack;
                if let Some(m) = crate::tcp_hdr::parse_mss_option(seg) { self.peer_mss = m; }
                if let Some(s) = crate::tcp_hdr::parse_wscale_option(seg) {
                    self.rcv_wscale = s;
                }
                // F182: SYN-ACK carrying TSopt confirms TS negotiation.
                if let Some((tsval, _)) = crate::tcp_hdr::parse_ts_option(seg) {
                    self.ts_enabled = true;
                    self.ts_recent  = tsval;
                }
                self.snd_wnd = hdr.window as u32;  // SYN: unscaled.
                // F190: peer's SYN-ACK with ECE (no CWR) confirms ECN.
                if (hdr.flags & flags::ECE) != 0 && (hdr.flags & flags::CWR) == 0 {
                    self.ecn_enabled = true;
                }
                // Pop SYN from retx_q (its seq+1 ≤ ack now).
                while let Some(front) = self.retx_q.front() {
                    let len = front.payload.len() as u32 +
                        if (front.flags & (flags::SYN | flags::FIN)) != 0 { 1 } else { 0 };
                    let end = front.seq.wrapping_add(len);
                    let diff = end.wrapping_sub(hdr.ack);
                    if (diff & 0x8000_0000) == 0 && diff != 0 { break; }
                    self.retx_q.pop_front();
                }
                self.state = transition(self.state, TcpEvent::RecvSynAck)
                    .ok_or(TcpConnError::BadState)?;
                let resp = self.build_segment(flags::ACK, &[]);
                Ok(Some(resp))
            }
            TcpState::SynRecv if (hdr.flags & flags::ACK) != 0 => {
                self.snd_una = hdr.ack;
                self.state = transition(self.state, TcpEvent::RecvAckEstablish)
                    .ok_or(TcpConnError::BadState)?;
                Ok(None)
            }
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 => {
                // F182: PAWS — RFC 7323 §5.3. Drop segments whose
                // TSval is older than ts_recent (mod 2^32, wrap-safe).
                // Older = (tsval - ts_recent) high-bit set. Skipped
                // segments produce no ACK update; peer will retx.
                if self.ts_enabled {
                    if let Some((tsval, _)) = crate::tcp_hdr::parse_ts_option(seg) {
                        let diff = tsval.wrapping_sub(self.ts_recent);
                        if diff & 0x8000_0000 != 0 {
                            return Ok(None);  // PAWS drop.
                        }
                        // Update ts_recent only for in-window data
                        // (avoids stale ack-only segments rewinding).
                        if hdr.seq == self.rcv_nxt {
                            self.ts_recent = tsval;
                        }
                    }
                }
                // F178: non-SYN segments carry the scaled window.
                self.snd_wnd = (hdr.window as u32) << self.rcv_wscale;
                // F179: deliver in-order; stash strictly-future
                // (seq > rcv_nxt) into ooo_buf for later drain.
                // Past-window (seq < rcv_nxt) or empty payload:
                // ignore (we already ACK'd that range).
                let payload = &seg[hdr.payload_offset()..];
                if !payload.is_empty() {
                    if hdr.seq == self.rcv_nxt {
                        self.recv_buf.extend(payload.iter().copied());
                        self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
                        // Drain any contiguous OOO chunks now reachable.
                        while let Some((&seq, _)) = self.ooo_buf.iter().next() {
                            if seq != self.rcv_nxt { break; }
                            let chunk = self.ooo_buf.remove(&seq).unwrap();
                            let len = chunk.len() as u32;
                            self.recv_buf.extend(chunk.into_iter());
                            self.rcv_nxt = self.rcv_nxt.wrapping_add(len);
                        }
                        // F186: peek recv_buf high-water; grow cap if
                        // we're filling >½ of it (Linux tcp_rcv_space).
                        self.rcv_autotune();
                    } else {
                        // OOO arrival: only stash if strictly ahead of
                        // rcv_nxt (wrap-safe — diff with high bit clear).
                        let diff = hdr.seq.wrapping_sub(self.rcv_nxt);
                        if (diff & 0x8000_0000) == 0 && diff != 0 {
                            // Cap the OOO buffer to bound memory; 64 KiB
                            // mirrors typical Linux tcp_rmem.
                            const OOO_CAP: usize = 64 * 1024;
                            let used: usize = self.ooo_buf.values().map(|v| v.len()).sum();
                            if used + payload.len() <= OOO_CAP {
                                self.ooo_buf.entry(hdr.seq).or_insert_with(|| payload.to_vec());
                            }
                        }
                    }
                }
                if (hdr.flags & flags::ACK) != 0 {
                    // F165: advance snd_una; bytes live in retx_q.
                    let acked = hdr.ack.wrapping_sub(self.snd_una);
                    if acked > 0 {
                        self.snd_una = hdr.ack;
                    }
                    // F185+F187: cwnd update on ACK.
                    self.cc_on_ack(acked, payload.len() as u32);
                    // F190: ECN-Echo from peer = single congestion event
                    // per RTT. Cleared when peer ACKs our CWR.
                    if self.ecn_enabled && (hdr.flags & flags::ECE) != 0 {
                        crate::tcp_cc::on_ece(self);
                    }
                    if self.ecn_enabled && (hdr.flags & flags::CWR) != 0 {
                        self.send_ece = false;
                    }
                    // F179a: apply any SACK blocks peer included.
                    let blocks = crate::tcp_hdr::parse_sack_option(seg);
                    if !blocks.is_empty() { self.apply_sack(&blocks); }
                    // Pop retx_q entries whose seq+len is fully ACK'd.
                    while let Some(front) = self.retx_q.front() {
                        let len = front.payload.len() as u32 +
                            if (front.flags & (flags::SYN | flags::FIN)) != 0 { 1 } else { 0 };
                        let end = front.seq.wrapping_add(len);
                        // Cumulative ACK covers this segment iff hdr.ack ≥ end (mod wrap).
                        let diff = end.wrapping_sub(hdr.ack);
                        // diff small + non-zero high bit means hdr.ack has not yet
                        // advanced past `end`.
                        if (diff & 0x8000_0000) == 0 && diff != 0 { break; }
                        self.retx_q.pop_front();
                    }
                }
                let mut emit_fin_ack = None;
                if (hdr.flags & flags::FIN) != 0 {
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                    let evt = match self.state {
                        TcpState::Established => TcpEvent::RecvFin,
                        TcpState::FinWait1    => TcpEvent::RecvFin, // → Closing
                        TcpState::FinWait2    => TcpEvent::RecvFin, // → TimeWait
                        _ => TcpEvent::RecvFin,
                    };
                    self.state = transition(self.state, evt).unwrap_or(self.state);
                    emit_fin_ack = Some(self.build_segment(flags::ACK, &[]));
                }
                if !payload.is_empty() && emit_fin_ack.is_none() {
                    // F179a: include SACK blocks when we have OOO
                    // data buffered so peer can fast-retx the gap.
                    return Ok(Some(self.build_ack_with_sack()));
                }
                Ok(emit_fin_ack)
            }
            TcpState::LastAck if (hdr.flags & flags::ACK) != 0 => {
                self.state = transition(self.state, TcpEvent::RecvFinAck)
                    .ok_or(TcpConnError::BadState)?;
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Drain `send_buf` into PSH+ACK segments, MSS each, in order.
    /// Each segment is moved (not copied) into `retx_q` as the
    /// authoritative copy until the peer ACKs it; `send_buf` is
    /// fully drained on return when the conn is in a sending state.
    ///
    /// Caller wraps each returned Vec in IP+xmit. Empty result when
    /// the conn isn't allowed to send (LISTEN, SynSent, FIN-WAIT*, etc.)
    /// — those states require explicit handshake/close segments.
    /// # C: O(send_buf)
    pub fn output(&mut self, mtu: usize, nodelay: bool) -> Vec<Vec<u8>> {
        // F173: MSS = min(local-MTU-derived, peer-advertised).
        let local_mss = mtu.saturating_sub(40).min(1460);  // 20 IP + 20 TCP
        let mss = if self.peer_mss != 0 {
            core::cmp::min(local_mss, self.peer_mss as usize)
        } else {
            local_mss
        };
        let mut out = Vec::new();
        if !self.state.is_established() && self.state != TcpState::CloseWait {
            return out;
        }
        // F175: Nagle. RFC 1122 §4.2.3.4.
        if !nodelay && !self.retx_q.is_empty() && self.send_buf.len() < mss {
            return out;
        }
        // F178/F185: in-flight bound = min(snd_wnd, cwnd) − in_flight.
        // cwnd governs sender-side congestion control (slow-start /
        // CA); snd_wnd governs receiver flow control. RFC 5681 §3.1.
        let in_flight: u32 = self.retx_q.iter().map(|s| s.payload.len() as u32).sum();
        let effective_wnd = core::cmp::min(self.snd_wnd, self.cwnd);
        let mut avail = effective_wnd.saturating_sub(in_flight);
        while !self.send_buf.is_empty() && avail > 0 {
            let chunk_cap = core::cmp::min(mss as u32, avail) as usize;
            let take = core::cmp::min(chunk_cap, self.send_buf.len());
            if take == 0 { break; }
            // (continue with original loop body below — pop+segment)
            let mut chunk: Vec<u8> = Vec::with_capacity(take);
            for _ in 0..take {
                chunk.push(self.send_buf.pop_front().unwrap());
            }
            let seq_start = self.snd_nxt;
            let seg = self.build_segment(flags::PSH | flags::ACK, &chunk);
            self.snd_nxt = self.snd_nxt.wrapping_add(take as u32);
            self.retx_q.push_back(UnackedSegment {
                seq: seq_start, flags: flags::PSH | flags::ACK,
                payload: chunk, last_sent_ns: 0, retries: 0, sacked: false,
            });
            out.push(seg);
            avail = avail.saturating_sub(take as u32);
        }
        out
    }

    /// Application enqueues `data` for transmission.
    /// # C: O(data.len())
    pub fn send(&mut self, data: &[u8]) {
        self.send_buf.extend(data.iter().copied());
    }

    /// Application drains up to `max` bytes from the recv buffer.
    /// # C: O(min(max, recv_buf.len()))
    pub fn recv(&mut self, max: usize) -> Vec<u8> {
        let take = core::cmp::min(max, self.recv_buf.len());
        let mut out = Vec::with_capacity(take);
        for _ in 0..take { out.push(self.recv_buf.pop_front().unwrap()); }
        out
    }

    /// Local close: emit FIN, transition out of ESTABLISHED.
    /// # C: O(1)
    pub fn local_close(&mut self) -> Result<Vec<u8>, TcpConnError> {
        let evt = match self.state {
            TcpState::Established => TcpEvent::LocalClose,
            TcpState::CloseWait   => TcpEvent::LocalClose,
            _ => return Err(TcpConnError::BadState),
        };
        let new_state = transition(self.state, evt).ok_or(TcpConnError::BadState)?;
        let seg = self.build_segment(flags::FIN | flags::ACK, &[]);
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        self.state = new_state;
        Ok(seg)
    }

    /// F179a: collapse `ooo_buf` into RFC 2018 SACK blocks. Each
    /// block = (left, right) for a contiguous run of buffered
    /// chunks. Max 4 blocks per RFC 2018 §3 (header room).
    /// # C: O(ooo_buf.len())
    pub fn sack_blocks(&self) -> alloc::vec::Vec<crate::tcp_hdr::SackBlock> {
        use crate::tcp_hdr::SackBlock;
        let mut out: alloc::vec::Vec<SackBlock> = alloc::vec::Vec::new();
        let mut iter = self.ooo_buf.iter().peekable();
        while let Some((&seq, chunk)) = iter.next() {
            let mut right = seq.wrapping_add(chunk.len() as u32);
            // Coalesce contiguous neighbors.
            while let Some(&(&nseq, nchunk)) = iter.peek() {
                if nseq == right {
                    right = right.wrapping_add(nchunk.len() as u32);
                    iter.next();
                } else { break; }
            }
            out.push(SackBlock { left: seq, right });
            if out.len() == 4 { break; }
        }
        out
    }

    /// F179a: build an ACK segment carrying any SACK blocks the
    /// peer should know about. When `ooo_buf` is empty (no holes
    /// to report) this degenerates to a plain ACK via the regular
    /// `build_segment` path.
    /// # C: O(blocks)
    pub fn build_ack_with_sack(&mut self) -> Vec<u8> {
        let blocks = self.sack_blocks();
        if blocks.is_empty() {
            return self.build_segment(flags::ACK, &[]);
        }
        use crate::tcp_hdr::{opt, TCP_HDR_MIN_LEN};
        let body = 8 * blocks.len();
        let opt_len = 2 + body;
        // 2 NOPs to align kind+len + blocks onto a 4-byte word.
        let padded = (2 + opt_len + 3) & !3;
        let total = TCP_HDR_MIN_LEN + padded;
        let mut buf = alloc::vec![0u8; total];
        let mut i = TCP_HDR_MIN_LEN;
        buf[i] = opt::NOP; i += 1;
        buf[i] = opt::NOP; i += 1;
        buf[i] = opt::SACK; buf[i + 1] = opt_len as u8;
        i += 2;
        for b in &blocks {
            buf[i..i + 4].copy_from_slice(&b.left.to_be_bytes());
            buf[i + 4..i + 8].copy_from_slice(&b.right.to_be_bytes());
            i += 8;
        }
        let data_offset = (TCP_HDR_MIN_LEN + padded) / 4;
        let mut h = TcpHdr {
            src_port: self.local.port, dst_port: self.remote.port,
            seq: self.snd_nxt, ack: self.rcv_nxt,
            data_offset: data_offset as u8, flags: flags::ACK,
            window: self.current_rcv_window(), checksum: 0, urg_ptr: 0,
        };
        h.build_into_ip(self.local.ip, self.remote.ip, &mut buf);
        buf
    }

    /// F179a: peer ACK'd `blocks` selectively — mark every
    /// retx_q segment whose [seq, seq+len) falls fully within
    /// any block as sacked so the retx scanner skips it.
    /// # C: O(retx_q * blocks)
    pub fn apply_sack(&mut self, blocks: &[crate::tcp_hdr::SackBlock]) {
        for s in self.retx_q.iter_mut() {
            if s.sacked { continue; }
            let len = s.payload.len() as u32
                + if (s.flags & (flags::SYN | flags::FIN)) != 0 { 1 } else { 0 };
            let end = s.seq.wrapping_add(len);
            for b in blocks {
                // Within-block check (wrap-safe via wrapping_sub).
                let starts_in = b.right.wrapping_sub(s.seq) != 0
                    && (b.right.wrapping_sub(s.seq) & 0x8000_0000) == 0
                    && s.seq.wrapping_sub(b.left) & 0x8000_0000 == 0;
                let ends_in   = b.right.wrapping_sub(end) & 0x8000_0000 == 0
                    && end.wrapping_sub(b.left) != 0;
                if starts_in && ends_in { s.sacked = true; break; }
            }
        }
    }

    fn build_segment(&mut self, mut flag_bits: u8, payload: &[u8]) -> Vec<u8> {
        // F190: ECN flag stamping. CWR rides the next data segment
        // (cleared once stamped). ECE rides every ACK while we owe
        // the peer a congestion echo (cleared on peer CWR receipt).
        if self.ecn_enabled {
            if self.send_cwr && !payload.is_empty() {
                flag_bits |= flags::CWR;
                self.send_cwr = false;
            }
            if self.send_ece && (flag_bits & flags::ACK) != 0 {
                flag_bits |= flags::ECE;
            }
        }
        let flag_bits = flag_bits;
        use crate::tcp_hdr::opt;
        // F182: when TS is enabled, every segment carries TSopt.
        // Layout: 2 NOPs + 10-byte TS = 12 bytes → data_offset += 3.
        let ts_opt_len = if self.ts_enabled { 12 } else { 0 };
        let data_offset = (5 + ts_opt_len / 4) as u8;
        let total = TCP_HDR_MIN_LEN + ts_opt_len + payload.len();
        let mut buf = alloc::vec![0u8; total];
        if self.ts_enabled {
            let mut i = TCP_HDR_MIN_LEN;
            buf[i] = opt::NOP; i += 1;
            buf[i] = opt::NOP; i += 1;
            buf[i] = opt::TIMESTAMP; buf[i + 1] = 10;
            buf[i + 2..i + 6].copy_from_slice(&tcp_now_ms().to_be_bytes());
            buf[i + 6..i + 10].copy_from_slice(&self.ts_recent.to_be_bytes());
        }
        if !payload.is_empty() {
            buf[TCP_HDR_MIN_LEN + ts_opt_len..].copy_from_slice(payload);
        }
        let mut h = TcpHdr {
            src_port: self.local.port, dst_port: self.remote.port,
            seq: self.snd_nxt, ack: self.rcv_nxt,
            data_offset, flags: flag_bits, window: self.current_rcv_window(),
            checksum: 0, urg_ptr: 0,
        };
        h.build_into_ip(self.local.ip, self.remote.ip, &mut buf);
        buf
    }

    /// F173/F178/F182: build a SYN (or SYN-ACK) with MSS +
    /// WindowScale + Timestamps options. Header total:
    /// 20 fixed + 4 MSS + 1 NOP + 3 WSCALE + 2 NOPs + 10 TS = 40
    /// bytes → data_offset = 10. NOPs align WSCALE and TS onto
    /// 4-byte boundaries for wire-format clarity.
    /// # C: O(1)
    fn build_syn_with_opts(&self, flag_bits: u8) -> Vec<u8> {
        use crate::tcp_hdr::opt;
        const OPTS_LEN: usize = 20;  // MSS(4)+NOP(1)+WSCALE(3)+NOP(1)+NOP(1)+TS(10)
        let total = TCP_HDR_MIN_LEN + OPTS_LEN;
        let mut buf = alloc::vec![0u8; total];
        let mut i = TCP_HDR_MIN_LEN;
        // MSS
        buf[i] = opt::MSS;    buf[i + 1] = 4;
        let mss = if self.own_mss != 0 { self.own_mss } else { OWN_MSS_DEFAULT };
        buf[i + 2..i + 4].copy_from_slice(&mss.to_be_bytes());
        i += 4;
        // NOP + WSCALE
        buf[i] = opt::NOP;    i += 1;
        buf[i] = opt::WSCALE; buf[i + 1] = 3; buf[i + 2] = self.snd_wscale;
        i += 3;
        // NOP + NOP + Timestamps. TSval = our_now, TSecr = ts_recent
        // (echoes the latest peer TSval we accepted; 0 on initial SYN).
        buf[i] = opt::NOP;    i += 1;
        buf[i] = opt::NOP;    i += 1;
        buf[i] = opt::TIMESTAMP; buf[i + 1] = 10;
        buf[i + 2..i + 6].copy_from_slice(&tcp_now_ms().to_be_bytes());
        buf[i + 6..i + 10].copy_from_slice(&self.ts_recent.to_be_bytes());
        let mut h = TcpHdr {
            src_port: self.local.port, dst_port: self.remote.port,
            seq: self.snd_nxt, ack: self.rcv_nxt,
            data_offset: 10, flags: flag_bits, window: self.current_rcv_window(),
            checksum: 0, urg_ptr: 0,
        };
        h.build_into_ip(self.local.ip, self.remote.ip, &mut buf);
        buf
    }
}

/// F182: monotonic millisecond clock for TSval per RFC 7323 §5.4.
/// Kernel-build reads the HAL timer; hosted tests stub to 0 (PAWS
/// stays inert — tests synthesize TSvals explicitly).
/// # C: O(1)
/// F193: monotonic ns clock for keepalive scheduling. Hosted = 0.
/// # C: O(1)
pub fn ka_now_ns() -> u64 {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    { use hal::TimerOps; return hal_x86_64::X86TimerOps::monotonic_ns().0; }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    { use hal::TimerOps; return hal_aarch64::ArmTimerOps::monotonic_ns().0; }
    #[allow(unreachable_code)]
    0
}

/// F182: monotonic ms clock for TSval. Hosted = 0. # C: O(1)
pub fn tcp_now_ms() -> u32 {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    { use hal::TimerOps; return (hal_x86_64::X86TimerOps::monotonic_ns().0 / 1_000_000) as u32; }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    { use hal::TimerOps; return (hal_aarch64::ArmTimerOps::monotonic_ns().0 / 1_000_000) as u32; }
    #[allow(unreachable_code)]
    0
}

/// F173: MSS we advertise. Conservative default; per-iface MTU
/// lookup lands once the bind table tracks iface scope.
pub const OWN_MSS_DEFAULT: u16 = 1460;

/// F186: WSCALE we advertise. 7 matches Linux default; with the
/// 16-bit window field this raises the effective rcv-window cap
/// to 65535 << 7 = 8 MiB, enough for high-BDP paths. Smaller
/// rcvbuf still works — peer scales our actual advertised window.
pub const OWN_WSCALE: u8 = 7;

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(ip: Ipv4Addr, port: u16) -> Endpoint { Endpoint { ip: IpAddr::V4(ip), port } }
    fn lo_ip() -> IpAddr { IpAddr::V4(Ipv4Addr::LOOPBACK) }

    #[test]
    fn three_way_handshake_completes() {
        let lo = Ipv4Addr::LOOPBACK;
        let mut client = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
        let mut server = TcpConn::new_listener(ep(lo, 80));

        let syn = client.active_open().unwrap();
        let synack = server.input(lo_ip(), lo_ip(), &syn).unwrap().expect("SYN-ACK");
        let ack = client.input(lo_ip(), lo_ip(), &synack).unwrap().expect("ACK");
        let resp = server.input(lo_ip(), lo_ip(), &ack).unwrap();
        assert!(resp.is_none());

        assert_eq!(client.state, TcpState::Established);
        assert_eq!(server.state, TcpState::Established);
    }

    #[test]
    fn data_round_trip_after_handshake() {
        let lo = Ipv4Addr::LOOPBACK;
        let mut client = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
        let mut server = TcpConn::new_listener(ep(lo, 80));
        let syn    = client.active_open().unwrap();
        let synack = server.input(lo_ip(), lo_ip(), &syn).unwrap().unwrap();
        let ack    = client.input(lo_ip(), lo_ip(), &synack).unwrap().unwrap();
        let _      = server.input(lo_ip(), lo_ip(), &ack).unwrap();

        client.send(b"oxide-tcp");
        let segs = client.output(1500, true);
        assert_eq!(segs.len(), 1);
        let server_ack = server.input(lo_ip(), lo_ip(), &segs[0]).unwrap().unwrap();
        let _ = client.input(lo_ip(), lo_ip(), &server_ack).unwrap();

        let got = server.recv(64);
        assert_eq!(&got[..], b"oxide-tcp");
    }

    #[test]
    fn graceful_close_local_then_remote() {
        let lo = Ipv4Addr::LOOPBACK;
        let mut client = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
        let mut server = TcpConn::new_listener(ep(lo, 80));
        let syn    = client.active_open().unwrap();
        let synack = server.input(lo_ip(), lo_ip(), &syn).unwrap().unwrap();
        let ack    = client.input(lo_ip(), lo_ip(), &synack).unwrap().unwrap();
        let _      = server.input(lo_ip(), lo_ip(), &ack).unwrap();

        let fin = client.local_close().unwrap();
        assert_eq!(client.state, TcpState::FinWait1);
        let server_ack = server.input(lo_ip(), lo_ip(), &fin).unwrap().unwrap();
        // Server is now in CloseWait. Local close on server emits FIN.
        let server_fin = server.local_close().unwrap();
        assert_eq!(server.state, TcpState::LastAck);
        let client_ack = client.input(lo_ip(), lo_ip(), &server_fin).unwrap().unwrap();
        let _ = server.input(lo_ip(), lo_ip(), &client_ack).unwrap();
        assert_eq!(server.state, TcpState::Closed);
        // Client's transition from FinWait1 takes the FIN+ACK path
        // through Closing → TimeWait.
        let _ = server_ack;
    }

    #[test]
    fn retransmit_due_re_emits_after_rto() {
        let lo = Ipv4Addr::LOOPBACK;
        let mut c = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
        let _ = c.active_open().unwrap();
        // SYN is now in retx_q with last_sent_ns = 0. now=0 with
        // rto=1s shouldn't trigger.
        assert_eq!(c.retransmit_due(0).len(), 0);
        assert_eq!(c.retransmit_due(2_000_000_000).len(), 1, "after 2s, SYN re-emitted");
        // RTO doubled.
        assert!(c.rto_ns >= 2_000_000_000);
    }

    #[test]
    fn ack_clears_retx_queue() {
        let lo = Ipv4Addr::LOOPBACK;
        let mut client = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
        let mut server = TcpConn::new_listener(ep(lo, 80));
        let syn    = client.active_open().unwrap();
        assert_eq!(client.retx_q.len(), 1);
        let synack = server.input(lo_ip(), lo_ip(), &syn).unwrap().unwrap();
        let _ = client.input(lo_ip(), lo_ip(), &synack).unwrap();
        // After receiving SYN+ACK, the SYN should be acked + popped.
        assert_eq!(client.retx_q.len(), 0);
    }

    #[test]
    fn update_rtt_smooths() {
        let lo = Ipv4Addr::LOOPBACK;
        let mut c = TcpConn::new_client(ep(lo, 1), ep(lo, 2), 0);
        c.update_rtt(50_000_000);   // 50 ms
        let r1 = c.rto_ns;
        c.update_rtt(60_000_000);   // 60 ms
        let r2 = c.rto_ns;
        assert!(r1 >= 200_000_000 && r1 <= 60_000_000_000);
        assert!(r2 >= 200_000_000 && r2 <= 60_000_000_000);
        assert!(c.srtt_ns > 0);
    }

    #[test]
    fn rst_jumps_to_closed() {
        let lo = Ipv4Addr::LOOPBACK;
        let mut conn = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
        let _ = conn.active_open().unwrap();
        // Build a RST segment manually and feed it.
        let mut buf = alloc::vec![0u8; TCP_HDR_MIN_LEN];
        let mut h = TcpHdr {
            src_port: 80, dst_port: 5000, seq: 0, ack: 1001,
            data_offset: 5, flags: flags::RST,
            window: 0, checksum: 0, urg_ptr: 0,
        };
        h.build_into(lo, lo, &mut buf);
        let _ = conn.input(lo_ip(), lo_ip(), &buf);
        assert_eq!(conn.state, TcpState::Closed);
    }
}
