// TCP header parse + build + checksum per RFC 9293 §3.1. v1
// supports the 20-byte fixed header (data_offset = 5) without
// options. Window scaling / SACK / timestamps land alongside
// the connection state machine.

use crate::addr::Ipv4Addr;
use crate::ipv4::ip_checksum;

pub const TCP_HDR_MIN_LEN: usize = 20;

pub mod flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TcpHdrError { Short, BadDataOffset, BadChecksum, BadLen }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TcpHdr {
    pub src_port:    u16,
    pub dst_port:    u16,
    pub seq:         u32,
    pub ack:         u32,
    pub data_offset: u8,    // header length / 4 — usually 5
    pub flags:       u8,
    pub window:      u16,
    pub checksum:    u16,
    pub urg_ptr:     u16,
}

impl TcpHdr {
    /// Build a 20-byte fixed header into `out`. Caller has already
    /// written the L7 payload after byte 20 of `out`. Computes the
    /// pseudo-header checksum.
    /// # C: O(N) checksum
    pub fn build_into(
        &mut self,
        src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
        out: &mut [u8],
    ) {
        out[ 0.. 2].copy_from_slice(&self.src_port.to_be_bytes());
        out[ 2.. 4].copy_from_slice(&self.dst_port.to_be_bytes());
        out[ 4.. 8].copy_from_slice(&self.seq.to_be_bytes());
        out[ 8..12].copy_from_slice(&self.ack.to_be_bytes());
        out[12]            = self.data_offset << 4;
        out[13]            = self.flags;
        out[14..16].copy_from_slice(&self.window.to_be_bytes());
        out[16..18].copy_from_slice(&0u16.to_be_bytes());
        out[18..20].copy_from_slice(&self.urg_ptr.to_be_bytes());
        let total_len = out.len();
        let cs = compute_tcp_checksum(out, src_ip, dst_ip, total_len, true);
        self.checksum = cs;
        out[16..18].copy_from_slice(&cs.to_be_bytes());
    }

    /// Parse a TCP header from `buf` (= the L4 segment). Validates
    /// pseudo-header checksum.
    /// # C: O(N)
    pub fn parse(buf: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Result<Self, TcpHdrError> {
        if buf.len() < TCP_HDR_MIN_LEN { return Err(TcpHdrError::Short); }
        let data_offset = buf[12] >> 4;
        if data_offset < 5 { return Err(TcpHdrError::BadDataOffset); }
        let hdr_len = data_offset as usize * 4;
        if buf.len() < hdr_len { return Err(TcpHdrError::BadLen); }
        if !tcp_checksum_ok(buf, src_ip, dst_ip) {
            return Err(TcpHdrError::BadChecksum);
        }
        Ok(Self {
            src_port:    u16::from_be_bytes([buf[0], buf[1]]),
            dst_port:    u16::from_be_bytes([buf[2], buf[3]]),
            seq:         u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            ack:         u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            data_offset,
            flags:       buf[13],
            window:      u16::from_be_bytes([buf[14], buf[15]]),
            checksum:    u16::from_be_bytes([buf[16], buf[17]]),
            urg_ptr:     u16::from_be_bytes([buf[18], buf[19]]),
        })
    }

    /// # C: O(1)
    pub fn payload_offset(&self) -> usize { self.data_offset as usize * 4 }
}

/// Validate a TCP segment's checksum against the IPv4 pseudo-header.
/// `buf` is the entire TCP segment (header + payload).
/// # C: O(N)
pub fn tcp_checksum_ok(buf: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> bool {
    compute_tcp_checksum(buf, src_ip, dst_ip, buf.len(), false) == 0
}

fn compute_tcp_checksum(
    buf: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
    tcp_len: usize, zero_field: bool,
) -> u16 {
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip.octets());
    pseudo[4..8].copy_from_slice(&dst_ip.octets());
    pseudo[8] = 0;
    pseudo[9] = 6;  // IpProto::Tcp
    pseudo[10..12].copy_from_slice(&(tcp_len as u16).to_be_bytes());
    let mut all = alloc::vec::Vec::with_capacity(12 + buf.len());
    all.extend_from_slice(&pseudo);
    all.extend_from_slice(buf);
    if zero_field && all.len() >= 12 + 18 {
        all[12 + 16] = 0;
        all[12 + 17] = 0;
    }
    ip_checksum(&all)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_then_parse_syn() {
        let src = Ipv4Addr::new(127, 0, 0, 1);
        let dst = Ipv4Addr::new(127, 0, 0, 1);
        let mut out = alloc::vec![0u8; TCP_HDR_MIN_LEN];
        let mut h = TcpHdr {
            src_port: 5000, dst_port: 80,
            seq: 0x1234_5678, ack: 0,
            data_offset: 5, flags: flags::SYN, window: 65535,
            checksum: 0, urg_ptr: 0,
        };
        h.build_into(src, dst, &mut out);
        let parsed = TcpHdr::parse(&out, src, dst).unwrap();
        assert_eq!(parsed.src_port, 5000);
        assert_eq!(parsed.flags, flags::SYN);
        assert_eq!(parsed.seq, 0x1234_5678);
    }

    #[test]
    fn rejects_bad_checksum() {
        let src = Ipv4Addr::new(127, 0, 0, 1);
        let mut out = alloc::vec![0u8; TCP_HDR_MIN_LEN + 4];
        let mut h = TcpHdr {
            src_port: 1, dst_port: 2, seq: 0, ack: 0,
            data_offset: 5, flags: flags::ACK, window: 1024, checksum: 0, urg_ptr: 0,
        };
        h.build_into(src, src, &mut out);
        out[20] ^= 0xFF;  // corrupt payload
        assert_eq!(TcpHdr::parse(&out, src, src).err().unwrap(), TcpHdrError::BadChecksum);
    }

    #[test]
    fn rejects_short() {
        let buf = [0u8; 10];
        assert_eq!(TcpHdr::parse(&buf, Ipv4Addr::ANY, Ipv4Addr::ANY).err().unwrap(),
                   TcpHdrError::Short);
    }

    #[test]
    fn rejects_bad_data_offset() {
        let mut buf = alloc::vec![0u8; TCP_HDR_MIN_LEN];
        buf[12] = 0x40;  // data_offset = 4 < 5
        assert_eq!(TcpHdr::parse(&buf, Ipv4Addr::ANY, Ipv4Addr::ANY).err().unwrap(),
                   TcpHdrError::BadDataOffset);
    }
}
