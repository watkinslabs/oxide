//! SACK support primitives.

use alloc::vec::Vec;

use crate::tcp_conn::TcpConn;
use crate::tcp_hdr::{opt, SackBlock, TCP_HDR_MIN_LEN};
use crate::tcp_hdr::flags;

impl TcpConn {
    /// F179a: collapse `ooo_buf` into RFC 2018 SACK blocks.
    pub fn sack_blocks(&self) -> alloc::vec::Vec<SackBlock> {
        let mut out: alloc::vec::Vec<SackBlock> = alloc::vec::Vec::new();
        let mut iter = self.ooo_buf.iter().peekable();
        while let Some((&seq, chunk)) = iter.next() {
            let mut right = seq.wrapping_add(chunk.len() as u32);
            while let Some(&(&nseq, nchunk)) = iter.peek() {
                if nseq == right {
                    right = right.wrapping_add(nchunk.len() as u32);
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
        let blocks = self.sack_blocks();
        if blocks.is_empty() {
            return self.build_segment(flags::ACK, &[]);
        }
        let body = 8 * blocks.len();
        let opt_len = 2 + body;
        let padded = (2 + opt_len + 3) & !3;
        let total = TCP_HDR_MIN_LEN + padded;
        let mut buf = alloc::vec![0u8; total];
        let mut i = TCP_HDR_MIN_LEN;
        buf[i] = opt::NOP;
        i += 1;
        buf[i] = opt::NOP;
        i += 1;
        buf[i] = opt::SACK;
        buf[i + 1] = opt_len as u8;
        i += 2;
        for b in &blocks {
            buf[i..i + 4].copy_from_slice(&b.left.to_be_bytes());
            buf[i + 4..i + 8].copy_from_slice(&b.right.to_be_bytes());
            i += 8;
        }
        let data_offset = (TCP_HDR_MIN_LEN + padded) / 4;
        let mut h = crate::tcp_hdr::TcpHdr {
            src_port: self.local.port,
            dst_port: self.remote.port,
            seq: self.snd_nxt,
            ack: self.rcv_nxt,
            data_offset: data_offset as u8,
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
