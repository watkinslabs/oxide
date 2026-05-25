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
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::addr::Ipv4Addr;
use crate::tcp_hdr::{TcpHdr, TCP_HDR_MIN_LEN, flags};
use crate::tcp_state::{TcpEvent, TcpState, transition};

/// Endpoint = (ip, port).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Endpoint { pub ip: Ipv4Addr, pub port: u16 }

/// One unacked transmission record on the retransmit queue.
/// Tracks the seq the segment occupies + when it was sent so
/// the RTO timer can re-emit it on timeout.
#[derive(Clone, Debug)]
pub struct UnackedSegment {
    pub seq:        u32,
    pub flags:      u8,
    pub payload:    alloc::vec::Vec<u8>,
    pub last_sent_ns: u64,
    pub retries:    u32,
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
    /// F161: monotonic timestamp when the conn entered TimeWait.
    /// Zero before entry. `tcp_retx_tick` removes entries that have
    /// been in TimeWait for >= 2*MSL (Linux tcp_fin_timeout = 60s).
    pub tw_start_ns: u64,
    /// F163: pending async error to surface via SO_ERROR. Set on
    /// abort paths (peer RST → ECONNREFUSED, retry-exhaust →
    /// ETIMEDOUT). Cleared on read. Linux errno value (positive),
    /// not the negated-syscall-return form.
    pub error_eno: i32,
    /// F173: peer-advertised MSS (from their SYN / SYN-ACK MSS
    /// option). `0` = not yet observed — output() falls back to
    /// the local-iface MTU-derived default.
    pub peer_mss: u16,
    /// F178: RFC 7323 Window Scale. `snd_wscale` is what we
    /// advertise (peer left-shifts our window field by this);
    /// `rcv_wscale` is what peer advertised (we left-shift their
    /// window field by this). Both default 0 (no scaling); only
    /// negotiated when BOTH ends include WSCALE in SYN/SYN-ACK.
    pub snd_wscale: u8,
    pub rcv_wscale: u8,
    /// Peer's currently-advertised window size in bytes (after
    /// applying rcv_wscale). Bounds the in-flight byte count
    /// output() will emit.
    pub snd_wnd: u32,
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
        }
    }

    /// Build a brand-new listener TCB. State starts LISTEN.
    /// # C: O(1)
    pub fn new_listener(local: Endpoint) -> Self {
        Self {
            local,
            remote: Endpoint { ip: Ipv4Addr::ANY, port: 0 },
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
        // Two-pass: snapshot expired indices, then build segments.
        let mut expired = alloc::vec::Vec::new();
        for (i, s) in self.retx_q.iter().enumerate() {
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
        }
        out
    }

    fn build_retx(&self, s: &UnackedSegment) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN + s.payload.len()];
        let mut h = TcpHdr {
            src_port: self.local.port, dst_port: self.remote.port,
            seq: s.seq, ack: self.rcv_nxt,
            data_offset: 5, flags: s.flags, window: self.window,
            checksum: 0, urg_ptr: 0,
        };
        if !s.payload.is_empty() {
            buf[crate::tcp_hdr::TCP_HDR_MIN_LEN..].copy_from_slice(&s.payload);
        }
        h.build_into(self.local.ip, self.remote.ip, &mut buf);
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
        let seg = self.build_syn_with_opts(flags::SYN);
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        self.state = new_state;
        // SYN consumes one sequence; track for retransmit.
        self.retx_q.push_back(UnackedSegment {
            seq: seq_start, flags: flags::SYN, payload: alloc::vec::Vec::new(),
            last_sent_ns: 0, retries: 0,
        });
        Ok(seg)
    }

    /// Apply a received segment. Caller (IPv4 demux) supplies the
    /// L3 src/dst addresses so the pseudo-header checksum can be
    /// validated. Drives the state machine, applies payload bytes
    /// to `recv_buf`, possibly emits a response segment.
    /// # C: O(payload size)
    pub fn input(&mut self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, seg: &[u8])
        -> Result<Option<Vec<u8>>, TcpConnError>
    {
        let hdr = TcpHdr::parse(seg, src_ip, dst_ip)
            .map_err(|_| TcpConnError::BadHdr)?;
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
                // F173: latch peer's MSS option if present.
                if let Some(m) = crate::tcp_hdr::parse_mss_option(seg) { self.peer_mss = m; }
                // F178: latch peer's window-scale only if they sent
                // one; otherwise both sides stay at scale 0 per RFC
                // 7323 §1.3 (must be in SYN for either end to use).
                if let Some(s) = crate::tcp_hdr::parse_wscale_option(seg) {
                    self.rcv_wscale = s;
                    self.snd_wscale = OWN_WSCALE;
                }
                // SYN segment carries unscaled window per RFC 7323 §2.2.
                self.snd_wnd = hdr.window as u32;
                self.state = transition(self.state, TcpEvent::RecvSyn)
                    .ok_or(TcpConnError::BadState)?;
                let resp = self.build_syn_with_opts(flags::SYN | flags::ACK);
                self.snd_nxt = self.snd_nxt.wrapping_add(1);
                Ok(Some(resp))
            }
            TcpState::SynSent if (hdr.flags & (flags::SYN | flags::ACK)) == (flags::SYN | flags::ACK) => {
                self.rcv_nxt = hdr.seq.wrapping_add(1);
                self.snd_una = hdr.ack;
                if let Some(m) = crate::tcp_hdr::parse_mss_option(seg) { self.peer_mss = m; }
                if let Some(s) = crate::tcp_hdr::parse_wscale_option(seg) {
                    self.rcv_wscale = s;
                    // We already advertised our own in the active SYN.
                }
                self.snd_wnd = hdr.window as u32;  // SYN: unscaled.
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
                // F178: non-SYN segments carry the scaled window.
                self.snd_wnd = (hdr.window as u32) << self.rcv_wscale;
                // Apply payload bytes (in-order only — no reassembly yet).
                let payload = &seg[hdr.payload_offset()..];
                if !payload.is_empty() && hdr.seq == self.rcv_nxt {
                    self.recv_buf.extend(payload.iter().copied());
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
                }
                if (hdr.flags & flags::ACK) != 0 {
                    // F165: advance snd_una; the actual bytes live in
                    // retx_q (output() drains send_buf into segments),
                    // so the retx_q sweep below is the one that frees
                    // memory. snd_una alone tracks "what peer has".
                    let acked = hdr.ack.wrapping_sub(self.snd_una);
                    if acked > 0 {
                        self.snd_una = hdr.ack;
                    }
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
                    return Ok(Some(self.build_segment(flags::ACK, &[])));
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
        // F178: respect peer's advertised window. Available bytes
        // we may put on the wire = snd_wnd minus already-in-flight
        // (sum of retx_q.payload). Stop when we'd exceed the window.
        let in_flight: u32 = self.retx_q.iter().map(|s| s.payload.len() as u32).sum();
        let mut avail = self.snd_wnd.saturating_sub(in_flight);
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
                payload: chunk, last_sent_ns: 0, retries: 0,
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

    fn build_segment(&self, flag_bits: u8, payload: &[u8]) -> Vec<u8> {
        let mut buf = alloc::vec![0u8; TCP_HDR_MIN_LEN + payload.len()];
        let mut h = TcpHdr {
            src_port: self.local.port, dst_port: self.remote.port,
            seq: self.snd_nxt, ack: self.rcv_nxt,
            data_offset: 5, flags: flag_bits, window: self.window,
            checksum: 0, urg_ptr: 0,
        };
        if !payload.is_empty() {
            buf[TCP_HDR_MIN_LEN..].copy_from_slice(payload);
        }
        h.build_into(self.local.ip, self.remote.ip, &mut buf);
        buf
    }

    /// F173/F178: build a SYN (or SYN-ACK) with MSS + WindowScale
    /// options. Header is 28 bytes (data_offset = 7): 20 fixed + 4
    /// MSS + 3 WSCALE + 1 NOP padding (RFC 9293 wants 32-bit
    /// alignment). NOP at offset 24 so WSCALE lands on a
    /// 4-byte-aligned offset for readability — both arrangements
    /// are wire-legal.
    /// # C: O(1)
    fn build_syn_with_opts(&self, flag_bits: u8) -> Vec<u8> {
        use crate::tcp_hdr::opt;
        const OPTS_LEN: usize = 8;  // MSS(4) + NOP(1) + WSCALE(3)
        let total = TCP_HDR_MIN_LEN + OPTS_LEN;
        let mut buf = alloc::vec![0u8; total];
        let mut i = TCP_HDR_MIN_LEN;
        // MSS option (kind=2, len=4, value=u16 BE).
        buf[i] = opt::MSS;    buf[i + 1] = 4;
        buf[i + 2..i + 4].copy_from_slice(&OWN_MSS_DEFAULT.to_be_bytes());
        i += 4;
        // NOP for alignment.
        buf[i] = opt::NOP;    i += 1;
        // WSCALE option (kind=3, len=3, value=u8 shift).
        buf[i] = opt::WSCALE; buf[i + 1] = 3; buf[i + 2] = self.snd_wscale;
        let mut h = TcpHdr {
            src_port: self.local.port, dst_port: self.remote.port,
            seq: self.snd_nxt, ack: self.rcv_nxt,
            data_offset: 7, flags: flag_bits, window: self.window,
            checksum: 0, urg_ptr: 0,
        };
        h.build_into(self.local.ip, self.remote.ip, &mut buf);
        buf
    }
}

/// F173: MSS we advertise. Conservative default; per-iface MTU
/// lookup lands once the bind table tracks iface scope.
pub const OWN_MSS_DEFAULT: u16 = 1460;

/// F178: shift count we advertise via WSCALE option. `0` keeps
/// us at the unscaled 65535 effective window — adequate for v1
/// where our recv_buf is bounded by SO_RCVBUF=16K anyway. A
/// future expansion (large rcv_buf + autotune) raises this.
pub const OWN_WSCALE: u8 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(ip: Ipv4Addr, port: u16) -> Endpoint { Endpoint { ip, port } }

    #[test]
    fn three_way_handshake_completes() {
        let lo = Ipv4Addr::LOOPBACK;
        let mut client = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
        let mut server = TcpConn::new_listener(ep(lo, 80));

        let syn = client.active_open().unwrap();
        let synack = server.input(lo, lo, &syn).unwrap().expect("SYN-ACK");
        let ack = client.input(lo, lo, &synack).unwrap().expect("ACK");
        let resp = server.input(lo, lo, &ack).unwrap();
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
        let synack = server.input(lo, lo, &syn).unwrap().unwrap();
        let ack    = client.input(lo, lo, &synack).unwrap().unwrap();
        let _      = server.input(lo, lo, &ack).unwrap();

        client.send(b"oxide-tcp");
        let segs = client.output(1500, true);
        assert_eq!(segs.len(), 1);
        let server_ack = server.input(lo, lo, &segs[0]).unwrap().unwrap();
        let _ = client.input(lo, lo, &server_ack).unwrap();

        let got = server.recv(64);
        assert_eq!(&got[..], b"oxide-tcp");
    }

    #[test]
    fn graceful_close_local_then_remote() {
        let lo = Ipv4Addr::LOOPBACK;
        let mut client = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
        let mut server = TcpConn::new_listener(ep(lo, 80));
        let syn    = client.active_open().unwrap();
        let synack = server.input(lo, lo, &syn).unwrap().unwrap();
        let ack    = client.input(lo, lo, &synack).unwrap().unwrap();
        let _      = server.input(lo, lo, &ack).unwrap();

        let fin = client.local_close().unwrap();
        assert_eq!(client.state, TcpState::FinWait1);
        let server_ack = server.input(lo, lo, &fin).unwrap().unwrap();
        // Server is now in CloseWait. Local close on server emits FIN.
        let server_fin = server.local_close().unwrap();
        assert_eq!(server.state, TcpState::LastAck);
        let client_ack = client.input(lo, lo, &server_fin).unwrap().unwrap();
        let _ = server.input(lo, lo, &client_ack).unwrap();
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
        let synack = server.input(lo, lo, &syn).unwrap().unwrap();
        let _ = client.input(lo, lo, &synack).unwrap();
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
        let _ = conn.input(lo, lo, &buf);
        assert_eq!(conn.state, TcpState::Closed);
    }
}
