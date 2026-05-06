// IPv4 header parse + build + checksum per RFC 791. v1 only does
// fixed-IHL (5 = 20-byte header, no options); fragmentation is
// out of scope (DF bit forced).

use crate::addr::{IpProto, Ipv4Addr};
use crate::pkt::Pkt;

pub const IPV4_HDR_LEN: usize = 20;
pub const IPV4_VERSION: u8    = 4;
pub const IPV4_DEFAULT_TTL: u8 = 64;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Ipv4Error {
    Short,
    BadVersion,
    BadIhl,
    BadChecksum,
    BadLen,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ipv4Hdr {
    pub version_ihl:    u8,    // 0x45 for v4 + 5*4=20 hdr len
    pub tos:            u8,
    pub total_len:      u16,
    pub id:             u16,
    pub flags_frag:     u16,
    pub ttl:            u8,
    pub proto:          u8,
    pub checksum:       u16,
    pub src:            Ipv4Addr,
    pub dst:            Ipv4Addr,
}

impl Ipv4Hdr {
    /// Build a 20-byte header for a packet whose payload follows
    /// it. Computes the checksum.
    /// # C: O(1)
    pub fn build(src: Ipv4Addr, dst: Ipv4Addr, proto: IpProto, payload_len: u16, id: u16) -> Self {
        let total = IPV4_HDR_LEN as u16 + payload_len;
        let mut h = Self {
            version_ihl: 0x45,
            tos:         0,
            total_len:   total,
            id,
            flags_frag:  0x4000,  // DF set
            ttl:         IPV4_DEFAULT_TTL,
            proto:       proto as u8,
            checksum:    0,
            src, dst,
        };
        let mut buf = [0u8; IPV4_HDR_LEN];
        h.write_to(&mut buf);
        h.checksum = ip_checksum(&buf);
        h
    }

    /// Serialize 20 bytes into `buf` (must be ≥20 long).
    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[ 0]            = self.version_ihl;
        buf[ 1]            = self.tos;
        buf[ 2.. 4].copy_from_slice(&self.total_len.to_be_bytes());
        buf[ 4.. 6].copy_from_slice(&self.id.to_be_bytes());
        buf[ 6.. 8].copy_from_slice(&self.flags_frag.to_be_bytes());
        buf[ 8]            = self.ttl;
        buf[ 9]            = self.proto;
        buf[10..12].copy_from_slice(&self.checksum.to_be_bytes());
        buf[12..16].copy_from_slice(&self.src.octets());
        buf[16..20].copy_from_slice(&self.dst.octets());
    }

    /// Parse from a buffer starting with the IP header. Validates
    /// version, IHL=5, and checksum.
    /// # C: O(1)
    pub fn parse(buf: &[u8]) -> Result<Self, Ipv4Error> {
        if buf.len() < IPV4_HDR_LEN { return Err(Ipv4Error::Short); }
        let v_ihl = buf[0];
        if (v_ihl >> 4) != IPV4_VERSION { return Err(Ipv4Error::BadVersion); }
        if (v_ihl & 0x0F) != 5 { return Err(Ipv4Error::BadIhl); }
        if ip_checksum(&buf[..IPV4_HDR_LEN]) != 0 {
            return Err(Ipv4Error::BadChecksum);
        }
        let total_len = u16::from_be_bytes([buf[2], buf[3]]);
        if (total_len as usize) < IPV4_HDR_LEN { return Err(Ipv4Error::BadLen); }
        Ok(Self {
            version_ihl: v_ihl,
            tos:         buf[1],
            total_len,
            id:          u16::from_be_bytes([buf[4], buf[5]]),
            flags_frag:  u16::from_be_bytes([buf[6], buf[7]]),
            ttl:         buf[8],
            proto:       buf[9],
            checksum:    u16::from_be_bytes([buf[10], buf[11]]),
            src: Ipv4Addr::from_u32(u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]])),
            dst: Ipv4Addr::from_u32(u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]])),
        })
    }

    /// Header length in bytes (always 20 for IHL=5).
    /// # C: O(1)
    pub fn ihl_bytes(&self) -> usize { ((self.version_ihl & 0x0F) as usize) * 4 }
}

/// 1's-complement Internet checksum per RFC 1071. Returns 0 when
/// the buffer (with checksum field already populated) is valid.
/// # C: O(N)
pub fn ip_checksum(buf: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < buf.len() {
        sum += u16::from_be_bytes([buf[i], buf[i+1]]) as u32;
        i += 2;
    }
    if i < buf.len() {
        sum += (buf[i] as u32) << 8;
    }
    while (sum >> 16) != 0 { sum = (sum & 0xFFFF) + (sum >> 16); }
    !(sum as u16)
}

/// Push a 20-byte IPv4 header in front of the current packet
/// payload. Caller has already populated `pkt` with the L4 payload
/// in its `data..tail` window. `proto` is the L4 ipproto.
/// # C: O(payload_len) for the checksum
pub fn push_ipv4_header(
    pkt: &mut Pkt, src: Ipv4Addr, dst: Ipv4Addr, proto: IpProto, id: u16
) -> Result<(), crate::pkt::PktError> {
    let payload_len = pkt.len() as u16;
    let hdr = Ipv4Hdr::build(src, dst, proto, payload_len, id);
    let slot = pkt.push(IPV4_HDR_LEN)?;
    hdr.write_to(slot);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_round_trip() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let h = Ipv4Hdr::build(src, dst, IpProto::Udp, 64, 0x1234);
        let mut buf = [0u8; IPV4_HDR_LEN];
        h.write_to(&mut buf);
        let h2 = Ipv4Hdr::parse(&buf).unwrap();
        assert_eq!(h2.src, src);
        assert_eq!(h2.dst, dst);
        assert_eq!(h2.proto, IpProto::Udp as u8);
        assert_eq!(h2.total_len, IPV4_HDR_LEN as u16 + 64);
    }

    #[test]
    fn rejects_bad_version() {
        let mut buf = [0u8; IPV4_HDR_LEN];
        buf[0] = 0x65;  // version=6
        assert_eq!(Ipv4Hdr::parse(&buf).err().unwrap(), Ipv4Error::BadVersion);
    }

    #[test]
    fn rejects_options_ihl() {
        let mut buf = [0u8; IPV4_HDR_LEN];
        buf[0] = 0x46;  // ihl=6 (24 bytes — has options; v1 doesn't support)
        assert_eq!(Ipv4Hdr::parse(&buf).err().unwrap(), Ipv4Error::BadIhl);
    }

    #[test]
    fn rejects_short() {
        let buf = [0u8; 8];
        assert_eq!(Ipv4Hdr::parse(&buf).err().unwrap(), Ipv4Error::Short);
    }

    #[test]
    fn checksum_known_value() {
        // RFC 1071 example: header bytes producing 0xb1e6.
        let buf: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
            0x40, 0x11, 0x00, 0x00,  // checksum slot zeroed
            0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        // Computing checksum over a header with the slot zeroed
        // should yield 0xb861.
        let cs = ip_checksum(&buf);
        assert_eq!(cs, 0xb861);
    }

    #[test]
    fn push_header_before_payload() {
        let mut p = Pkt::with_capacity(IPV4_HDR_LEN, 1024);
        p.put(8).unwrap().copy_from_slice(b"AAAAAAAA");
        push_ipv4_header(&mut p, Ipv4Addr::new(10,0,0,1), Ipv4Addr::new(10,0,0,2), IpProto::Udp, 1).unwrap();
        assert_eq!(p.len(), IPV4_HDR_LEN + 8);
        let h = Ipv4Hdr::parse(p.data()).unwrap();
        assert_eq!(h.proto, IpProto::Udp as u8);
        assert_eq!(h.total_len, (IPV4_HDR_LEN + 8) as u16);
        // Verify checksum validates.
        assert_eq!(ip_checksum(&p.data()[..IPV4_HDR_LEN]), 0);
    }
}
