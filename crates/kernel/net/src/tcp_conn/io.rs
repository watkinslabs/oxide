//! Packet input/output and core state transition handling.

use alloc::vec::Vec;

use crate::tcp_conn::{TcpConn, TcpConnError};
use crate::tcp_state::{TcpEvent, TcpState};
use crate::tcp_hdr::flags;
use syscall::errno::Errno;

impl TcpConn {
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
        self.last_rx_ns = crate::tcp_conn::ka_now_ns();
        self.ka_count = 0;
        if (hdr.flags & flags::RST) != 0 {
            if self.error_eno == 0 {
                self.error_eno = if self.state == TcpState::SynSent {
                    Errno::Econnrefused as i32
                } else {
                    Errno::Econnreset as i32
                };
            }
            self.state = TcpState::Closed;
            return Ok(None);
        }
        match self.state {
            TcpState::Listen if (hdr.flags & flags::SYN) != 0 => {
                self.remote = crate::tcp_conn::Endpoint { ip: src_ip, port: hdr.src_port };
                self.rcv_nxt = hdr.seq.wrapping_add(1);
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
                Ok(Some(resp))
            }
            TcpState::SynSent if (hdr.flags & (flags::SYN | flags::ACK)) == (flags::SYN | flags::ACK) => {
                self.rcv_nxt = hdr.seq.wrapping_add(1);
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
                while let Some(front) = self.retx_q.front() {
                    let len = front.payload.len() as u32 +
                        if (front.flags & (flags::SYN | flags::FIN)) != 0 { 1 } else { 0 };
                    let end = front.seq.wrapping_add(len);
                    let diff = end.wrapping_sub(hdr.ack);
                    if (diff & 0x8000_0000) == 0 && diff != 0 { break; }
                    self.retx_q.pop_front();
                }
                self.state = crate::tcp_state::transition(self.state, TcpEvent::RecvSynAck)
                    .ok_or(TcpConnError::BadState)?;
                let resp = self.build_segment(flags::ACK, &[]);
                Ok(Some(resp))
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
                if !payload.is_empty() {
                    if hdr.seq == self.rcv_nxt {
                        self.recv_buf.extend(payload.iter().copied());
                        self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
                        while let Some((&seq, _)) = self.ooo_buf.iter().next() {
                            if seq != self.rcv_nxt { break; }
                            let chunk = self.ooo_buf.remove(&seq).unwrap();
                            let len = chunk.len() as u32;
                            self.recv_buf.extend(chunk.into_iter());
                            self.rcv_nxt = self.rcv_nxt.wrapping_add(len);
                        }
                        self.rcv_autotune();
                    } else {
                        let diff = hdr.seq.wrapping_sub(self.rcv_nxt);
                        if (diff & 0x8000_0000) == 0 && diff != 0 {
                            const OOO_CAP: usize = 64 * 1024;
                            let used: usize = self.ooo_buf.values().map(|v| v.len()).sum();
                            if used + payload.len() <= OOO_CAP {
                                self.ooo_buf.entry(hdr.seq).or_insert_with(|| payload.to_vec());
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
                    while let Some(front) = self.retx_q.front() {
                        let len = front.payload.len() as u32 +
                            if (front.flags & (flags::SYN | flags::FIN)) != 0 { 1 } else { 0 };
                        let end = front.seq.wrapping_add(len);
                        let diff = end.wrapping_sub(hdr.ack);
                        if (diff & 0x8000_0000) == 0 && diff != 0 {
                            break;
                        }
                        self.retx_q.pop_front();
                    }
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
        let local_mss = mtu.saturating_sub(40).min(1460);
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

    /// Application drains up to `max` bytes from recv_buf.
    pub fn recv(&mut self, max: usize) -> Vec<u8> {
        let take = core::cmp::min(max, self.recv_buf.len());
        let mut out = Vec::with_capacity(take);
        for _ in 0..take {
            out.push(self.recv_buf.pop_front().unwrap());
        }
        out
    }
}
