//! Segment construction helpers.

use alloc::vec::Vec;

use crate::tcp_conn::{TcpConn, UnackedSegment};
use crate::tcp_hdr::{TcpHdr, TCP_HDR_MIN_LEN, flags, opt};

impl TcpConn {
    pub(crate) fn build_retx(&self, s: &UnackedSegment) -> alloc::vec::Vec<u8> {
        if s.flags & flags::SYN != 0 {
            return self.build_syn_with_opts_at(s.seq, s.flags);
        }
        let urg_ptr = if s.flags & flags::URG != 0 { 1 } else { 0 };
        self.build_segment_at(s.seq, s.flags, &s.payload, urg_ptr)
    }

    pub fn build_segment(&mut self, mut flag_bits: u8, payload: &[u8]) -> Vec<u8> {
        if self.ecn_enabled {
            if self.send_cwr && !payload.is_empty() {
                flag_bits |= flags::CWR;
                self.send_cwr = false;
            }
            if self.send_ece && (flag_bits & flags::ACK) != 0 {
                flag_bits |= flags::ECE;
            }
        }
        self.build_segment_at(self.snd_nxt, flag_bits, payload, 0)
    }

    pub(crate) fn build_urgent_segment(&mut self, payload: &[u8]) -> Vec<u8> {
        self.build_segment_at(self.snd_nxt, flags::PSH | flags::ACK | flags::URG, payload, 1)
    }

    fn build_segment_at(&self, seq: u32, flag_bits: u8, payload: &[u8], urg_ptr: u16) -> Vec<u8> {
        let ts_opt_len = if self.ts_enabled { 12 } else { 0 };
        let data_offset = (5 + ts_opt_len / 4) as u8;
        let total = TCP_HDR_MIN_LEN + ts_opt_len + payload.len();
        let mut buf = alloc::vec![0u8; total];
        if self.ts_enabled {
            let mut i = TCP_HDR_MIN_LEN;
            buf[i] = opt::NOP;
            i += 1;
            buf[i] = opt::NOP;
            i += 1;
            buf[i] = opt::TIMESTAMP;
            buf[i + 1] = 10;
            buf[i + 2..i + 6].copy_from_slice(&crate::tcp_conn::tcp_now_ms().to_be_bytes());
            buf[i + 6..i + 10].copy_from_slice(&self.ts_recent.to_be_bytes());
        }
        if !payload.is_empty() {
            buf[TCP_HDR_MIN_LEN + ts_opt_len..].copy_from_slice(payload);
        }
        let mut h = TcpHdr {
            src_port: self.local.port,
            dst_port: self.remote.port,
            seq,
            ack: self.rcv_nxt,
            data_offset,
            flags: flag_bits,
            window: self.current_rcv_window(),
            checksum: 0,
            urg_ptr,
        };
        h.build_into_ip(self.local.ip, self.remote.ip, &mut buf);
        buf
    }

    pub(super) fn build_syn_with_opts(&self, flag_bits: u8) -> Vec<u8> {
        self.build_syn_with_opts_at(self.snd_nxt, flag_bits)
    }

    pub(super) fn build_syn_with_opts_at(&self, seq: u32, flag_bits: u8) -> Vec<u8> {
        const OPTS_LEN: usize = 20;
        let total = TCP_HDR_MIN_LEN + OPTS_LEN;
        let mut buf = alloc::vec![0u8; total];
        let mut i = TCP_HDR_MIN_LEN;
        buf[i] = opt::MSS;
        buf[i + 1] = 4;
        let mss = if self.own_mss != 0 { self.own_mss } else { super::OWN_MSS_DEFAULT };
        buf[i + 2..i + 4].copy_from_slice(&mss.to_be_bytes());
        i += 4;
        buf[i] = opt::NOP;
        i += 1;
        buf[i] = opt::WSCALE;
        buf[i + 1] = 3;
        buf[i + 2] = self.snd_wscale;
        i += 3;
        buf[i] = opt::NOP;
        i += 1;
        buf[i] = opt::NOP;
        i += 1;
        buf[i] = opt::TIMESTAMP;
        buf[i + 1] = 10;
        buf[i + 2..i + 6].copy_from_slice(&crate::tcp_conn::tcp_now_ms().to_be_bytes());
        buf[i + 6..i + 10].copy_from_slice(&self.ts_recent.to_be_bytes());
        let mut h = TcpHdr {
            src_port: self.local.port,
            dst_port: self.remote.port,
            seq,
            ack: self.rcv_nxt,
            data_offset: 10,
            flags: flag_bits,
            window: self.current_rcv_window(),
            checksum: 0,
            urg_ptr: 0,
        };
        h.build_into_ip(self.local.ip, self.remote.ip, &mut buf);
        buf
    }
}
