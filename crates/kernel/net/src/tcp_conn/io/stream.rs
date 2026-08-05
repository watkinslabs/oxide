//! The socket-facing side of a connection: queued sends turned into wire
//! segments, urgent data, and the receive buffer handed to readers.

use alloc::vec::Vec;

use crate::tcp_conn::TcpConn;
use crate::tcp_state::TcpState;
use crate::tcp_hdr::flags;

impl TcpConn {
    /// Application bytes accepted but not yet emitted into a TCP segment. # C: O(1)
    pub fn notsent_bytes(&self) -> u32 {
        core::cmp::min(self.send_buf.len(), u32::MAX as usize) as u32
    }

    /// Convert queued send_buf into wire segments.
    /// # C: O(send_buf)
    pub fn output(&mut self, mtu: usize, nodelay: bool, cork: bool) -> Vec<Vec<u8>> {
        self.output_limit(mtu, nodelay, cork, usize::MAX)
    }

    /// Convert at most `limit` queued payload segments into wire segments. # C: O(limit * MSS)
    pub fn output_limit(&mut self, mtu: usize, nodelay: bool, cork: bool, limit: usize)
        -> Vec<Vec<u8>>
    {
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
        while !self.send_buf.is_empty() && avail > 0 && out.len() < limit {
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
                delivered_at_send: 0, delivered_mstamp_ns: 0, first_sent_ns: 0, delivery_app_limited: false,
                retries: 0,
                sacked: false,
            });
            out.push(seg);
            avail = avail.saturating_sub(take as u32);
        }
        out
    }

    /// Refresh cwnd/RTT pacing and return whether output is eligible now. # C: O(1)
    pub fn pacing_ready_at(&mut self, now_ns: u64, max_rate: u64) -> bool {
        let mss = u64::from(if self.own_mss == 0 { crate::tcp_conn::OWN_MSS_DEFAULT } else { self.own_mss });
        let cwnd_rate = u64::from(self.cwnd).saturating_mul(1_000_000_000) / self.srtt_ns.max(1);
        let gain = if self.cwnd < self.ssthresh { 2 } else { 1 };
        self.telemetry.pacing_rate = cwnd_rate.saturating_mul(gain).max(mss);
        if max_rate != u64::MAX { self.telemetry.pacing_rate = self.telemetry.pacing_rate.min(max_rate); }
        if max_rate == u64::MAX { self.telemetry.pacing_next_ns = 0; return true; }
        self.telemetry.pacing_next_ns == 0
            || now_ns == 0 || now_ns >= self.telemetry.pacing_next_ns
    }

    /// Advance the output deadline after one paced payload segment left the TCB. # C: O(1)
    pub fn note_paced_output_at(&mut self, now_ns: u64, bytes: usize, max_rate: u64) {
        if max_rate == u64::MAX || now_ns == 0 || self.telemetry.pacing_rate == 0 { return; }
        let delay = (bytes as u64).saturating_mul(1_000_000_000)
            .saturating_add(self.telemetry.pacing_rate - 1) / self.telemetry.pacing_rate;
        self.telemetry.pacing_next_ns = now_ns.saturating_add(delay.max(1));
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
            delivered_at_send: 0, delivered_mstamp_ns: 0, first_sent_ns: 0, delivery_app_limited: false,
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
            out.push(self.recv_buf.pop_front().unwrap().byte);
        }
        self.rcv_read_seq = self.rcv_read_seq.wrapping_add(take as u32);
        if take != 0 { self.note_rcv_space_at(crate::tcp_conn::ka_now_ns()); }
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
        let out: Vec<u8> = self.recv_buf.iter().skip(offset).take(take).map(|b| b.byte).collect();
        let (copied, commit) = copy(&out)?;
        if !peek {
            let consumed = core::cmp::min(commit, take);
            for _ in 0..consumed { self.recv_buf.pop_front(); }
            self.rcv_read_seq = self.rcv_read_seq.wrapping_add(consumed as u32);
            if consumed != 0 { self.note_rcv_space_at(crate::tcp_conn::ka_now_ns()); }
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
        let out: Vec<u8> = self.recv_buf.iter().skip(offset).take(take).map(|b| b.byte).collect();
        let (copied, commit) = copy(&out)?;
        if !peek {
            let consumed = core::cmp::min(commit, take);
            for _ in 0..consumed { self.recv_buf.pop_front(); }
            self.rcv_read_seq = self.rcv_read_seq.wrapping_add(consumed as u32);
            if consumed != 0 { self.note_rcv_space_at(crate::tcp_conn::ka_now_ns()); }
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

    /// Realtime stamp of the first unread normal-stream byte. # C: O(1)
    pub fn recv_timestamp(&self) -> Option<u64> {
        self.recv_buf.front().map(|b| b.timestamp_ns)
    }
}
