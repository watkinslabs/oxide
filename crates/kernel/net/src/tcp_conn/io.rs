//! Packet input/output and core state transition handling.

use alloc::vec::Vec;

use crate::tcp_conn::{TcpConn, TcpConnError};
use crate::tcp_state::{TcpEvent, TcpState};
use crate::tcp_hdr::flags;

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
        self.input_with_header(src_ip, dst_ip, seg, hdr)
    }

    /// Apply a filter-trimmed segment whose original checksum passed. # C: O(payload)
    pub fn input_prevalidated(&mut self, src_ip: crate::addr::IpAddr,
                              dst_ip: crate::addr::IpAddr, seg: &[u8])
        -> Result<Option<Vec<u8>>, TcpConnError>
    {
        let hdr = crate::tcp_hdr::parse_prevalidated(seg).map_err(|_| TcpConnError::BadHdr)?;
        self.input_with_header(src_ip, dst_ip, seg, hdr)
    }

    fn input_with_header(&mut self, src_ip: crate::addr::IpAddr,
                         _dst_ip: crate::addr::IpAddr, seg: &[u8], hdr: crate::tcp_hdr::TcpHdr)
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
                self.snd_una = 0;
                self.snd_nxt = 0;
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
                self.snd_una = hdr.ack;
                self.state = crate::tcp_state::transition(self.state, TcpEvent::RecvAckEstablish)
                    .ok_or(TcpConnError::BadState)?;
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
                    return Ok(Some(self.build_ack_with_sack()));
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

    /// Convert queued send_buf into wire segments.
    /// # C: O(send_buf)
    pub fn output(&mut self, mtu: usize, nodelay: bool, cork: bool) -> Vec<Vec<u8>> {
        let configured_mss = if self.own_mss != 0 {
            self.own_mss as usize
        } else {
            crate::tcp_conn::OWN_MSS_DEFAULT as usize
        };
        let local_mss = mtu.saturating_sub(40).min(configured_mss);
        let mss = if self.peer_mss != 0 {
            core::cmp::min(local_mss, self.peer_mss as usize)
        } else {
            local_mss
        };
        let mut out = Vec::new();
        if !self.state.is_established() && self.state != TcpState::CloseWait {
            return out;
        }
        if !nodelay && !self.retx_q.is_empty() && self.send_buf.len() < mss {
            return out;
        }
        if cork && self.send_buf.len() < mss {
            return out;
        }
        let in_flight: u32 = self.retx_q.iter().map(|s| s.payload.len() as u32).sum();
        let effective_wnd = core::cmp::min(self.snd_wnd, self.cwnd);
        let mut avail = effective_wnd.saturating_sub(in_flight);
        while !self.send_buf.is_empty() && avail > 0 {
            let chunk_cap = core::cmp::min(mss as u32, avail) as usize;
            let take = core::cmp::min(chunk_cap, self.send_buf.len());
            if cork && take < mss { break; }
            if take == 0 { break; }
            let mut chunk: Vec<u8> = Vec::with_capacity(take);
            for _ in 0..take {
                chunk.push(self.send_buf.pop_front().unwrap());
            }
            let seg = self.build_segment(flags::PSH | flags::ACK, &chunk);
            self.snd_nxt = self.snd_nxt.wrapping_add(take as u32);
            self.retx_q.push_back(crate::tcp_conn::UnackedSegment {
                seq: self.snd_nxt.wrapping_sub(take as u32),
                flags: flags::PSH | flags::ACK,
                payload: chunk,
                last_sent_ns: 0,
                retries: 0,
                sacked: false,
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

    /// Queue one TCP urgent byte and return its URG segment. # C: O(1)
    pub fn send_urgent(&mut self, byte: u8) -> Vec<u8> {
        let seq = self.snd_nxt;
        let payload = [byte];
        let seg = self.build_urgent_segment(&payload);
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        self.retx_q.push_back(crate::tcp_conn::UnackedSegment {
            seq, flags: crate::tcp_hdr::flags::PSH | crate::tcp_hdr::flags::ACK
                | crate::tcp_hdr::flags::URG, payload: alloc::vec![byte],
            last_sent_ns: 0, retries: 0, sacked: false,
        });
        seg
    }

    /// Return and consume the latest received urgent byte. # C: O(1)
    pub fn take_urgent(&mut self) -> Option<(u32, u8)> {
        let urgent = self.urgent.take()?;
        self.oob_consumed = Some(urgent.0);
        let offset = urgent.0.wrapping_sub(self.rcv_read_seq) as usize;
        if offset < self.recv_buf.len() {
            self.recv_buf.remove(offset);
            self.oob_consumed = None;
        }
        Some(urgent)
    }

    /// Observe the latest received urgent byte without consuming it. # C: O(1)
    pub fn peek_urgent(&self) -> Option<(u32, u8)> { self.urgent }

    /// Observe whether one urgent byte is waiting for OOB delivery. # C: O(1)
    pub fn has_urgent(&self) -> bool { self.urgent.is_some() }

    /// Application drains up to `max` bytes from recv_buf.
    pub fn recv(&mut self, max: usize) -> Vec<u8> {
        let take = core::cmp::min(max, self.recv_buf.len());
        let mut out = Vec::with_capacity(take);
        for _ in 0..take {
            out.push(self.recv_buf.pop_front().unwrap());
        }
        self.rcv_read_seq = self.rcv_read_seq.wrapping_add(take as u32);
        out
    }

    /// Inspect one receive prefix and drain it only after callback success. # C: O(max)
    pub fn recv_with<R, E>(&mut self, max: usize, peek: bool, copy: impl FnOnce(&[u8]) -> Result<(R, usize), E>)
        -> Result<Option<R>, E>
    { self.recv_with_offset(max, peek, 0, copy) }

    /// Inspect a receive range after `offset` without consuming skipped bytes. # C: O(offset + max)
    pub fn recv_with_offset<R, E>(&mut self, max: usize, peek: bool, offset: usize, copy: impl FnOnce(&[u8]) -> Result<(R, usize), E>)
        -> Result<Option<R>, E>
    {
        if offset >= self.recv_buf.len() { return Ok(None); }
        let take = core::cmp::min(max, self.recv_buf.len() - offset);
        let out: Vec<u8> = self.recv_buf.iter().skip(offset).take(take).copied().collect();
        let (copied, commit) = copy(&out)?;
        if !peek {
            let consumed = core::cmp::min(commit, take);
            for _ in 0..consumed { self.recv_buf.pop_front(); }
            self.rcv_read_seq = self.rcv_read_seq.wrapping_add(consumed as u32);
        }
        Ok(Some(copied))
    }

    /// Inspect normal stream data while honoring out-of-line urgent delivery. # C: O(offset + max)
    pub fn recv_with_offset_oob<R, E>(&mut self, max: usize, peek: bool, offset: usize,
        inline: bool, copy: impl FnOnce(&[u8]) -> Result<(R, usize), E>) -> Result<Option<R>, E>
    {
        let mut limit = self.recv_buf.len();
        if !inline {
            if let Some((seq, _)) = self.urgent {
                let mark = seq.wrapping_sub(self.rcv_read_seq) as usize;
                if mark < limit { limit = mark; }
            }
        }
        if offset >= limit { return Ok(None); }
        let take = core::cmp::min(max, limit - offset);
        let out: Vec<u8> = self.recv_buf.iter().skip(offset).take(take).copied().collect();
        let (copied, commit) = copy(&out)?;
        if !peek {
            let consumed = core::cmp::min(commit, take);
            for _ in 0..consumed { self.recv_buf.pop_front(); }
            self.rcv_read_seq = self.rcv_read_seq.wrapping_add(consumed as u32);
            if inline {
                if let Some((seq, _)) = self.urgent {
                    if (seq.wrapping_sub(self.rcv_read_seq) as i32) < 0 {
                        self.urgent = None;
                    }
                }
            }
        }
        Ok(Some(copied))
    }

    /// Report whether the next normal stream byte is the urgent mark. # C: O(1)
    pub fn at_urgent_mark(&self) -> bool {
        self.urgent.map(|(seq, _)| seq == self.rcv_read_seq).unwrap_or(false)
    }
}
