// IPv6 fixed header per RFC 8200 §3. 40-byte fixed shape; no
// extension headers in v1 (caller surfaces UnsupportedExtHdr if
// `next_header` ∉ {ICMPv6, UDP, TCP}). Each field is big-endian.
//
// Layout:
//   [0]    bits 0..4: version (=6); 4..12: traffic_class; 12..32: flow_label
//   [4..6]  payload_length (excludes hdr; covers ext-hdrs + L4)
//   [6]     next_header
//   [7]     hop_limit
//   [8..24] src
//   [24..40] dst

use crate::addr::{IpProto, Ipv6Addr};
use crate::pkt::Pkt;

pub const IPV6_HDR_LEN: usize = 40;
pub const IPV6_DEFAULT_HOP_LIMIT: u8 = 64;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Ipv6Error { Short, BadVersion, BadLen }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ipv6Hdr {
    pub flow_label:     u32,
    pub traffic_class:  u8,
    pub payload_length: u16,
    pub next_header:    u8,
    pub hop_limit:      u8,
    pub src:            Ipv6Addr,
    pub dst:            Ipv6Addr,
}

impl Ipv6Hdr {
    /// Parse a 40-byte IPv6 header out of `buf`.
    /// # C: O(1)
    pub fn parse(buf: &[u8]) -> Result<Self, Ipv6Error> {
        if buf.len() < IPV6_HDR_LEN { return Err(Ipv6Error::Short); }
        let v_tc_fl = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let version = (v_tc_fl >> 28) as u8;
        if version != 6 { return Err(Ipv6Error::BadVersion); }
        let traffic_class = ((v_tc_fl >> 20) & 0xFF) as u8;
        let flow_label    = v_tc_fl & 0x000F_FFFF;
        let payload_length = u16::from_be_bytes([buf[4], buf[5]]);
        let next_header    = buf[6];
        let hop_limit      = buf[7];
        let mut src = [0u8; 16]; src.copy_from_slice(&buf[8..24]);
        let mut dst = [0u8; 16]; dst.copy_from_slice(&buf[24..40]);
        Ok(Self {
            flow_label, traffic_class, payload_length, next_header, hop_limit,
            src: Ipv6Addr(src), dst: Ipv6Addr(dst),
        })
    }

    /// Build a 40-byte header for a packet whose payload follows.
    /// Computes no checksum (IPv6 has none).
    /// # C: O(1)
    pub fn build(src: Ipv6Addr, dst: Ipv6Addr, proto: IpProto, payload_len: u16) -> Self {
        Self {
            flow_label: 0, traffic_class: 0, payload_length: payload_len,
            next_header: proto as u8, hop_limit: IPV6_DEFAULT_HOP_LIMIT,
            src, dst,
        }
    }

    /// Serialize 40 bytes into `buf`.
    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        let v_tc_fl: u32 = (6u32 << 28)
            | ((self.traffic_class as u32) << 20)
            | (self.flow_label & 0x000F_FFFF);
        buf[0..4].copy_from_slice(&v_tc_fl.to_be_bytes());
        buf[4..6].copy_from_slice(&self.payload_length.to_be_bytes());
        buf[6] = self.next_header;
        buf[7] = self.hop_limit;
        buf[8..24].copy_from_slice(&self.src.0);
        buf[24..40].copy_from_slice(&self.dst.0);
    }
}

/// Push a 40-byte IPv6 header in front of the current packet
/// payload. Caller has already populated `pkt.data..tail` with
/// the L4 segment.
/// # C: O(1)
pub fn push_ipv6_header(
    pkt: &mut Pkt, src: Ipv6Addr, dst: Ipv6Addr, proto: IpProto
) -> Result<(), crate::pkt::PktError> {
    let payload_len = pkt.len() as u16;
    let hdr = Ipv6Hdr::build(src, dst, proto, payload_len);
    let slot = pkt.push(IPV6_HDR_LEN)?;
    hdr.write_to(slot);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let src = Ipv6Addr::from_segments([0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = src;
        let h = Ipv6Hdr::build(src, dst, IpProto::Udp, 100);
        let mut buf = [0u8; IPV6_HDR_LEN];
        h.write_to(&mut buf);
        let p = Ipv6Hdr::parse(&buf).unwrap();
        assert_eq!(p.next_header, IpProto::Udp as u8);
        assert_eq!(p.payload_length, 100);
        assert_eq!(p.src, src);
        assert_eq!(p.dst, dst);
    }

    #[test]
    fn rejects_bad_version() {
        let mut buf = [0u8; IPV6_HDR_LEN];
        buf[0] = 0x40;  // version 4
        assert_eq!(Ipv6Hdr::parse(&buf).err().unwrap(), Ipv6Error::BadVersion);
    }

    #[test]
    fn rejects_short() {
        let buf = [0u8; 20];
        assert_eq!(Ipv6Hdr::parse(&buf).err().unwrap(), Ipv6Error::Short);
    }

    #[test]
    fn push_header_before_payload() {
        let mut p = Pkt::with_capacity(IPV6_HDR_LEN, 1024);
        p.put(8).unwrap().copy_from_slice(b"AAAAAAAA");
        push_ipv6_header(&mut p, Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK, IpProto::Udp).unwrap();
        let h = Ipv6Hdr::parse(p.data()).unwrap();
        assert_eq!(h.payload_length, 8);
        assert_eq!(h.next_header, IpProto::Udp as u8);
    }
}
