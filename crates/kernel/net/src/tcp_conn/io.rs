//! Segment input and the core state transitions it drives.
//!
//! Module manifest:
//! - stream.rs : the socket-facing side — queued sends turned into segments,
//!               and the receive buffer handed to readers.

use alloc::vec::Vec;

use crate::tcp_conn::{TcpConn, TcpConnError};
use crate::tcp_state::{TcpEvent, TcpState};
use crate::tcp_hdr::flags;

mod stream;

impl TcpConn {
    fn rst_acceptable(&self, hdr: crate::tcp_hdr::TcpHdr) -> bool {
        match self.state {
            TcpState::SynSent => {
                if (hdr.flags & flags::ACK) == 0 { return false; }
                let outstanding = self.snd_nxt.wrapping_sub(self.snd_una);
                let acknowledged = hdr.ack.wrapping_sub(self.snd_una);
                acknowledged != 0 && acknowledged <= outstanding
            }
            TcpState::SynRecv | TcpState::Established | TcpState::FinWait1
            | TcpState::FinWait2 | TcpState::CloseWait | TcpState::Closing
            | TcpState::LastAck | TcpState::TimeWait => {
                let window = (self.current_rcv_window() as u32) << self.snd_wscale;
                if window == 0 { hdr.seq == self.rcv_nxt }
                else {
                    let offset = hdr.seq.wrapping_sub(self.rcv_nxt);
                    offset < window && (offset & 0x8000_0000) == 0
                }
            }
            TcpState::Listen | TcpState::Closed => false,
        }
    }

    fn append_recv_payload(&mut self, seq: u32, payload: &[u8]) {
        for (index, byte) in payload.iter().copied().enumerate() {
            if self.oob_consumed == Some(seq.wrapping_add(index as u32)) {
                self.oob_consumed = None;
            } else { self.recv_buf.push_back(byte); }
        }
    }

    fn trim_retx_acked(&mut self, ack: u32) {
        while let Some(front) = self.retx_q.front_mut() {
            let len = front.payload.len() as u32 +
                if (front.flags & (flags::SYN | flags::FIN)) != 0 { 1 } else { 0 };
            let acked = ack.wrapping_sub(front.seq);
            if acked == 0 || (acked & 0x8000_0000) != 0 { break; }
            if acked >= len {
                self.retx_q.pop_front();
                continue;
            }
            let mut payload_acked = acked;
            if (front.flags & flags::SYN) != 0 {
                front.flags &= !flags::SYN;
                payload_acked -= 1;
            }
            front.seq = ack;
            let trim = core::cmp::min(payload_acked as usize, front.payload.len());
            front.payload.drain(..trim);
            break;
        }
    }

    /// Client active open: emit a SYN with MSS + WindowScale,
    /// transition to SynSent.
    pub fn active_open(&mut self) -> Result<Vec<u8>, TcpConnError> {
        let new_state = crate::tcp_state::transition(self.state, TcpEvent::ActiveOpen)
            .ok_or(TcpConnError::BadState)?;
        let seq_start = self.snd_nxt;
        self.snd_wscale = crate::tcp_conn::OWN_WSCALE;
        let seg = self.build_syn_with_opts(flags::SYN | flags::ECE | flags::CWR);
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        self.state = new_state;
        self.retx_q.push_back(crate::tcp_conn::UnackedSegment {
            seq: seq_start,
            flags: flags::SYN,
            payload: Vec::new(),
            last_sent_ns: 0,
            retries: 0,
            sacked: false,
        });
        Ok(seg)
    }

    /// Apply a received segment and optionally emit a response segment.
    pub fn input(&mut self, src_ip: crate::addr::IpAddr, dst_ip: crate::addr::IpAddr, seg: &[u8])
        -> Result<Option<Vec<u8>>, TcpConnError>
    {
        let hdr = crate::tcp_hdr::parse_ip(seg, src_ip, dst_ip)
            .map_err(|_| TcpConnError::BadHdr)?;
        self.input_completing_request(src_ip, dst_ip, seg, hdr)
    }

    /// Apply a filter-trimmed segment whose original checksum passed. # C: O(payload)
    pub fn input_prevalidated(&mut self, src_ip: crate::addr::IpAddr,
                              dst_ip: crate::addr::IpAddr, seg: &[u8])
        -> Result<Option<Vec<u8>>, TcpConnError>
    {
        let hdr = crate::tcp_hdr::parse_prevalidated(seg).map_err(|_| TcpConnError::BadHdr)?;
        self.input_completing_request(src_ip, dst_ip, seg, hdr)
    }

    /// The segment that turns a request into a connection is applied twice:
    /// once to complete the handshake, and once against the connection that
    /// now exists, which is the only state that consumes payload. A client
    /// that sends its request on the acknowledgement — and every client of a
    /// listener holding `TCP_DEFER_ACCEPT`, whose bare acknowledgements were
    /// dropped — would otherwise have those bytes discarded with the
    /// handshake. Iterative rather than recursive: the second pass runs in
    /// ESTABLISHED and cannot complete a request again.
    /// # C: O(payload)
    fn input_completing_request(&mut self, src_ip: crate::addr::IpAddr,
                                dst_ip: crate::addr::IpAddr, seg: &[u8],
                                hdr: crate::tcp_hdr::TcpHdr)
        -> Result<Option<Vec<u8>>, TcpConnError>
    {
        let was_request = self.state == TcpState::SynRecv;
        let resp = self.input_with_header(src_ip, dst_ip, seg, hdr)?;
        if !was_request || self.state != TcpState::Established { return Ok(resp); }
        let carries = seg.len() > hdr.payload_offset() || (hdr.flags & flags::FIN) != 0;
        if !carries { return Ok(resp); }
        self.input_with_header(src_ip, dst_ip, seg, hdr)
    }

    fn input_with_header(&mut self, src_ip: crate::addr::IpAddr,
                         dst_ip: crate::addr::IpAddr, seg: &[u8], hdr: crate::tcp_hdr::TcpHdr)
        -> Result<Option<Vec<u8>>, TcpConnError>
    {
        self.last_rx_ns = crate::tcp_conn::ka_now_ns();
        self.ka_count = 0;
        if (hdr.flags & flags::RST) != 0 {
            if !self.rst_acceptable(hdr) { return Ok(None); }
            self.state = TcpState::Closed;
            return Err(TcpConnError::Reset);
        }
        match self.state {
            TcpState::Listen if (hdr.flags & flags::SYN) != 0 => {
                self.remote = crate::tcp_conn::Endpoint { ip: src_ip, port: hdr.src_port };
                self.rcv_nxt = hdr.seq.wrapping_add(1);
                self.rcv_read_seq = self.rcv_nxt;
                // Linux `tcp_v4_init_seq_and_ts_off` keys the passive ISN on the
                // packet's own (daddr, saddr, dest, source) — the wildcard
                // listener's `self.local.ip` may be ANY, so use the delivered
                // destination (`net/ipv4/tcp_ipv4.c`). This opened at 0 before:
                // every inbound connection to any listening service started at
                // sequence 0, so blind injection needed no guess at all.
                let isn = crate::secure_seq::secure_tcp_seq(
                    dst_ip, src_ip, self.local.port, hdr.src_port);
                self.snd_una = isn;
                self.snd_nxt = isn;
                self.ts_off = crate::secure_seq::secure_tcp_ts_off(
                    dst_ip, src_ip, self.local.port, hdr.src_port);
                if let Some(m) = crate::tcp_hdr::parse_mss_option(seg) { self.peer_mss = m; }
                if let Some(s) = crate::tcp_hdr::parse_wscale_option(seg) {
                    self.rcv_wscale = s;
                    self.snd_wscale = crate::tcp_conn::OWN_WSCALE;
                }
                if let Some((tsval, _)) = crate::tcp_hdr::parse_ts_option(seg) {
                    self.ts_enabled = true;
                    self.ts_recent  = tsval;
                }
                self.snd_wnd = hdr.window as u32;
                self.state = crate::tcp_state::transition(self.state, TcpEvent::RecvSyn)
                    .ok_or(TcpConnError::BadState)?;
                let mut sa_flags = flags::SYN | flags::ACK;
                if (hdr.flags & (flags::ECE | flags::CWR)) == (flags::ECE | flags::CWR) {
                    self.ecn_enabled = true;
                    sa_flags |= flags::ECE;
                }
                let resp = self.build_syn_with_opts(sa_flags);
                self.snd_nxt = self.snd_nxt.wrapping_add(1);
                self.retx_q.push_back(crate::tcp_conn::UnackedSegment {
                    seq: self.snd_nxt.wrapping_sub(1),
                    flags: sa_flags,
                    payload: Vec::new(),
                    last_sent_ns: 0,
                    retries: 0,
                    sacked: false,
                });
                // The connection is now a request: its own timer owns the
                // SYN-ACK retransmits and the deferring period, not the data
                // retransmit path.
                self.rsk = crate::tcp_conn::reqsk::ReqSock::default();
                self.rsk.arm(crate::tcp_conn::ka_now_ns(), self.rto_max_ns);
                Ok(Some(resp))
            }
            TcpState::SynSent if (hdr.flags & (flags::SYN | flags::ACK)) == (flags::SYN | flags::ACK) => {
                self.rcv_nxt = hdr.seq.wrapping_add(1);
                self.rcv_read_seq = self.rcv_nxt;
                self.snd_una = hdr.ack;
                if let Some(m) = crate::tcp_hdr::parse_mss_option(seg) { self.peer_mss = m; }
                if let Some(s) = crate::tcp_hdr::parse_wscale_option(seg) {
                    self.rcv_wscale = s;
                }
                if let Some((tsval, _)) = crate::tcp_hdr::parse_ts_option(seg) {
                    self.ts_enabled = true;
                    self.ts_recent  = tsval;
                }
                self.snd_wnd = hdr.window as u32;
                if (hdr.flags & flags::ECE) != 0 && (hdr.flags & flags::CWR) == 0 {
                    self.ecn_enabled = true;
                }
                self.trim_retx_acked(hdr.ack);
                self.state = crate::tcp_state::transition(self.state, TcpEvent::RecvSynAck)
                    .ok_or(TcpConnError::BadState)?;
                let resp = self.build_segment(flags::ACK, &[]);
                Ok(Some(resp))
            }
            TcpState::SynRecv if (hdr.flags & flags::SYN) != 0 => {
                // A lost SYN-ACK causes the peer to retransmit its SYN. Keep
                // the half-open child and retransmit the exact SYN-ACK from
                // its retained sequence number; creating a second child
                // would consume another backlog slot and violate tuple
                // identity.
                let Some(synack) = self.retx_q.front().map(|segment| self.build_retx(segment))
                    else { return Ok(None); };
                Ok(Some(synack))
            }
            TcpState::SynRecv if (hdr.flags & flags::ACK) != 0 => {
                // Linux `tcp_rcv_state_process` (`net/ipv4/tcp_input.c:7200-7253`)
                // runs `tcp_ack` — and therefore `tcp_clean_rtx_queue` — BEFORE
                // the `case TCP_SYN_RECV:` arm, then that arm installs
                // `tp->snd_una` and
                // `tp->snd_wnd = ntohs(th->window) << tp->rx_opt.snd_wscale`.
                // Without the trim the SYN-ACK stays unacked for the life of the
                // connection, so `output`'s Nagle guard holds every sub-MSS write
                // and `tcp_retx_tick` re-sends a segment the peer already ACKed
                // (B1454).
                self.snd_una = hdr.ack;
                self.trim_retx_acked(hdr.ack);
                self.snd_wnd = (hdr.window as u32) << self.rcv_wscale;
                self.state = crate::tcp_state::transition(self.state, TcpEvent::RecvAckEstablish)
                    .ok_or(TcpConnError::BadState)?;
                // The request became a connection; its timer stops here.
                self.rsk = crate::tcp_conn::reqsk::ReqSock::default();
                Ok(None)
            }
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 => {
                if self.ts_enabled {
                    if let Some((tsval, _)) = crate::tcp_hdr::parse_ts_option(seg) {
                        let diff = tsval.wrapping_sub(self.ts_recent);
                        if diff & 0x8000_0000 != 0 {
                            return Ok(None);
                        }
                        if hdr.seq == self.rcv_nxt {
                            self.ts_recent = tsval;
                        }
                    }
                }
                self.snd_wnd = (hdr.window as u32) << self.rcv_wscale;
                let payload = &seg[hdr.payload_offset()..];
                // A segment lying entirely before the receive window is an old
                // duplicate, and RFC 9293 §3.10.7.4 answers it with an
                // acknowledgement rather than silence: that is how a peer
                // answers a keepalive probe, and how it answers the SYN-ACK a
                // listener retransmits to a connection it is still holding at
                // the request stage.
                if payload.is_empty()
                    && (hdr.seq.wrapping_sub(self.rcv_nxt) & 0x8000_0000) != 0
                {
                    return Ok(Some(self.build_ack_with_sack()));
                }
                let urgent = if (hdr.flags & flags::URG) != 0 && hdr.urg_ptr != 0 && !payload.is_empty() {
                    let index = hdr.urg_ptr.saturating_sub(1) as usize;
                    (index < payload.len()).then(|| (hdr.seq.wrapping_add(index as u32), payload[index]))
                } else { None };
                if !payload.is_empty() {
                    if hdr.seq == self.rcv_nxt {
                        self.append_recv_payload(hdr.seq, payload);
                        if let Some(urgent) = urgent {
                            self.urgent = Some(urgent);
                            self.oob_consumed = None;
                        }
                        self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
                        while let Some((&seq, _)) = self.ooo_buf.iter().next() {
                            if seq != self.rcv_nxt { break; }
                            let chunk = self.ooo_buf.remove(&seq).unwrap();
                            let chunk_urgent = self.ooo_urgent.remove(&seq).flatten();
                            let len = chunk.len() as u32;
                            self.append_recv_payload(seq, &chunk);
                            if let Some(urgent) = chunk_urgent {
                                self.urgent = Some(urgent);
                                self.oob_consumed = None;
                            }
                            self.rcv_nxt = self.rcv_nxt.wrapping_add(len);
                        }
                        self.rcv_autotune();
                    } else {
                        let diff = hdr.seq.wrapping_sub(self.rcv_nxt);
                        if (diff & 0x8000_0000) == 0 && diff != 0 {
                            const OOO_CAP: usize = 64 * 1024;
                            let used: usize = self.ooo_buf.values().map(|v| v.len()).sum();
                            if used + payload.len() <= OOO_CAP {
                                if let alloc::collections::btree_map::Entry::Vacant(entry) = self.ooo_buf.entry(hdr.seq) {
                                    entry.insert(payload.to_vec());
                                    self.ooo_urgent.insert(hdr.seq, urgent);
                                }
                            }
                        }
                    }
                }
                if (hdr.flags & flags::ACK) != 0 {
                    let acked = hdr.ack.wrapping_sub(self.snd_una);
                    if acked > 0 {
                        self.snd_una = hdr.ack;
                    }
                    self.cc_on_ack(acked, payload.len() as u32);
                    if self.ecn_enabled && (hdr.flags & flags::ECE) != 0 {
                        crate::tcp_cc::on_ece(self);
                    }
                    if self.ecn_enabled && (hdr.flags & flags::CWR) != 0 {
                        self.send_ece = false;
                    }
                    let blocks = crate::tcp_hdr::parse_sack_option(seg);
                    if !blocks.is_empty() {
                        self.apply_sack(&blocks);
                    }
                    self.trim_retx_acked(hdr.ack);
                }
                let mut emit_fin_ack = None;
                if (hdr.flags & flags::FIN) != 0 {
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                    let evt = match self.state {
                        TcpState::Established => TcpEvent::RecvFin,
                        TcpState::FinWait1 => TcpEvent::RecvFin,
                        TcpState::FinWait2 => TcpEvent::RecvFin,
                        _ => TcpEvent::RecvFin,
                    };
                    self.state = crate::tcp_state::transition(self.state, evt).unwrap_or(self.state);
                    emit_fin_ack = Some(self.build_segment(flags::ACK, &[]));
                }
                if !payload.is_empty() && emit_fin_ack.is_none() {
                    if self.ack_now() {
                        self.rcv_wup = self.rcv_nxt;
                        self.ack_pending = false;
                        self.ack_deadline_ns = 0;
                        return Ok(Some(self.build_ack_with_sack()));
                    }
                    // Ping-pong mode: the acknowledgement waits for either the
                    // reply it can ride on or the delayed-ACK deadline, which
                    // the retransmit scan stamps and enforces.
                    self.ack_pending = true;
                    return Ok(None);
                }
                if emit_fin_ack.is_some() {
                    self.rcv_wup = self.rcv_nxt;
                    self.ack_pending = false;
                    self.ack_deadline_ns = 0;
                }
                Ok(emit_fin_ack)
            }
            TcpState::LastAck if (hdr.flags & flags::ACK) != 0 => {
                self.state = crate::tcp_state::transition(self.state, TcpEvent::RecvFinAck)
                    .ok_or(TcpConnError::BadState)?;
                Ok(None)
            }
            _ => Ok(None),
        }
    }
}
