//! SACK support primitives.

use alloc::vec::Vec;

use crate::tcp_conn::TcpConn;
use crate::tcp_hdr::{SackBlock, TCP_HDR_MIN_LEN};
use crate::tcp_hdr::flags;

impl TcpConn {
    /// F179a: collapse `ooo_buf` into RFC 2018 SACK blocks.
    pub fn sack_blocks(&self) -> alloc::vec::Vec<SackBlock> {
        let mut out: alloc::vec::Vec<SackBlock> = alloc::vec::Vec::new();
        let mut iter = self.ooo_buf.iter().peekable();
        while let Some((&seq, segment)) = iter.next() {
            let mut right = seq.wrapping_add(segment.sequence_len());
            while let Some(&(&nseq, next)) = iter.peek() {
                if nseq == right {
                    right = right.wrapping_add(next.sequence_len());
                    iter.next();
                } else {
                    break;
                }
            }
            out.push(SackBlock { left: seq, right });
            if out.len() == 4 {
                break;
            }
        }
        out
    }

    /// Build an ACK segment carrying SACK blocks when present.
    pub fn build_ack_with_sack(&mut self) -> Vec<u8> {
        // Blocks may only be sent to a peer that permitted them on its SYN.
        // Sending them regardless offered a peer that declined the option an
        // extension it never agreed to parse.
        let blocks = if self.sack_ok { self.sack_blocks() } else { Vec::new() };
        if blocks.is_empty() {
            return self.build_segment(flags::ACK, &[]);
        }
        let timestamp = self.ts_enabled.then(|| (
            crate::tcp_conn::tcp_now_ms().wrapping_add(self.ts_off), self.ts_recent));
        let option_len = crate::tcp_conn::segment_opts::SegmentOptions {
            timestamp, sacks: &blocks,
        }.encoded_len();
        let options = crate::tcp_conn::segment_opts::append(timestamp, &blocks, &[]);
        let mut buf = alloc::vec![0u8; TCP_HDR_MIN_LEN + options.len()];
        buf[TCP_HDR_MIN_LEN..].copy_from_slice(&options);
        let mut h = crate::tcp_hdr::TcpHdr {
            src_port: self.local.port,
            dst_port: self.remote.port,
            seq: self.snd_nxt,
            ack: self.rcv_nxt,
            data_offset: (TCP_HDR_MIN_LEN + option_len) as u8 / 4,
            flags: flags::ACK,
            window: self.current_rcv_window(),
            checksum: 0,
            urg_ptr: 0,
        };
        h.build_into_ip(self.local.ip, self.remote.ip, &mut buf);
        buf
    }

    /// Mark retx entries fully inside any SACK block.
    pub fn apply_sack(&mut self, blocks: &[SackBlock]) {
        for s in self.retx_q.iter_mut() {
            if s.sacked {
                continue;
            }
            let len = s.payload.len() as u32
                + if (s.flags & (flags::SYN | flags::FIN)) != 0 { 1 } else { 0 };
            let end = s.seq.wrapping_add(len);
            for b in blocks {
                let starts_in = b.right.wrapping_sub(s.seq) != 0
                    && (b.right.wrapping_sub(s.seq) & 0x8000_0000) == 0
                    && s.seq.wrapping_sub(b.left) & 0x8000_0000 == 0;
                let ends_in   = b.right.wrapping_sub(end) & 0x8000_0000 == 0
                    && end.wrapping_sub(b.left) != 0;
                if starts_in && ends_in {
                    s.sacked = true;
                    break;
                }
            }
        }
    }

}
