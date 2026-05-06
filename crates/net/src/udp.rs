// UDP — RFC 768. Header is 8 bytes: src_port + dst_port + length
// + checksum. Checksum is computed over the IPv4 pseudo-header
// (src + dst + zero + proto=17 + udp_length) plus the UDP header
// + payload. v1 honors checksum (sender computes; receiver
// validates).

use crate::addr::Ipv4Addr;
use crate::ipv4::ip_checksum;

pub const UDP_HDR_LEN: usize = 8;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UdpError { Short, BadChecksum, BadLen }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct UdpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub length:   u16,
    pub checksum: u16,
}

impl UdpHdr {
    /// Parse a UDP header out of `buf` (the L4 payload of an
    /// IPv4 packet). Validates checksum against the IPv4 pseudo-
    /// header. `buf.len()` must equal `length`.
    /// # C: O(N)
    pub fn parse(buf: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Result<Self, UdpError> {
        if buf.len() < UDP_HDR_LEN { return Err(UdpError::Short); }
        let length = u16::from_be_bytes([buf[4], buf[5]]);
        if (length as usize) != buf.len() { return Err(UdpError::BadLen); }
        let checksum = u16::from_be_bytes([buf[6], buf[7]]);
        // Per RFC 768, checksum=0 means "skipped". Otherwise verify.
        if checksum != 0 {
            if !udp_checksum_ok(buf, src_ip, dst_ip) {
                return Err(UdpError::BadChecksum);
            }
        }
        Ok(Self {
            src_port: u16::from_be_bytes([buf[0], buf[1]]),
            dst_port: u16::from_be_bytes([buf[2], buf[3]]),
            length,
            checksum,
        })
    }

    /// Build a UDP datagram (header + payload) into `out`.
    /// `out.len()` ≥ `UDP_HDR_LEN + payload.len()`. Computes the
    /// checksum over the IPv4 pseudo-header + UDP message.
    /// # C: O(N)
    pub fn build_into(
        src_port: u16, dst_port: u16,
        src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
        payload: &[u8], out: &mut [u8],
    ) {
        let length = (UDP_HDR_LEN + payload.len()) as u16;
        out[0..2].copy_from_slice(&src_port.to_be_bytes());
        out[2..4].copy_from_slice(&dst_port.to_be_bytes());
        out[4..6].copy_from_slice(&length.to_be_bytes());
        out[6..8].copy_from_slice(&0u16.to_be_bytes());
        out[8 .. 8 + payload.len()].copy_from_slice(payload);
        let cs = compute_udp_checksum(&out[..length as usize], src_ip, dst_ip);
        // Per RFC 768: a computed checksum of 0 must be transmitted
        // as 0xFFFF (since 0 means "skipped" on the wire).
        let cs = if cs == 0 { 0xFFFF } else { cs };
        out[6..8].copy_from_slice(&cs.to_be_bytes());
    }
}

/// Validate a UDP message's checksum against the IPv4 pseudo-header.
/// `buf` is the entire UDP message (header + payload).
/// # C: O(N)
pub fn udp_checksum_ok(buf: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> bool {
    compute_udp_checksum_with_field(buf, src_ip, dst_ip, true) == 0
}

/// Compute the UDP checksum (with the checksum field zeroed for
/// the calculation) — used by `build_into`.
/// # C: O(N)
pub fn compute_udp_checksum(buf: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> u16 {
    compute_udp_checksum_with_field(buf, src_ip, dst_ip, false)
}

fn compute_udp_checksum_with_field(
    buf: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr, include_field: bool,
) -> u16 {
    // Pseudo-header: src(4) + dst(4) + zero(1) + proto(1) + udp_len(2)
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip.octets());
    pseudo[4..8].copy_from_slice(&dst_ip.octets());
    pseudo[8] = 0;
    pseudo[9] = 17;  // IpProto::Udp
    pseudo[10..12].copy_from_slice(&(buf.len() as u16).to_be_bytes());
    let mut all = alloc::vec::Vec::with_capacity(12 + buf.len());
    all.extend_from_slice(&pseudo);
    all.extend_from_slice(buf);
    if !include_field && all.len() >= 12 + 8 {
        all[12 + 6] = 0;
        all[12 + 7] = 0;
    }
    ip_checksum(&all)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_then_parse() {
        let src = Ipv4Addr::new(127, 0, 0, 1);
        let dst = Ipv4Addr::new(127, 0, 0, 1);
        let payload = b"hello-udp";
        let mut buf = alloc::vec![0u8; UDP_HDR_LEN + payload.len()];
        UdpHdr::build_into(1234, 5678, src, dst, payload, &mut buf);
        let h = UdpHdr::parse(&buf, src, dst).unwrap();
        assert_eq!(h.src_port, 1234);
        assert_eq!(h.dst_port, 5678);
        assert_eq!(h.length as usize, UDP_HDR_LEN + payload.len());
        assert_eq!(&buf[UDP_HDR_LEN..], payload);
    }

    #[test]
    fn rejects_corrupted_checksum() {
        let src = Ipv4Addr::new(127, 0, 0, 1);
        let dst = Ipv4Addr::new(127, 0, 0, 1);
        let mut buf = alloc::vec![0u8; UDP_HDR_LEN + 4];
        UdpHdr::build_into(1, 2, src, dst, b"abcd", &mut buf);
        buf[8] ^= 0xFF;  // corrupt payload
        assert_eq!(UdpHdr::parse(&buf, src, dst).err().unwrap(), UdpError::BadChecksum);
    }

    #[test]
    fn checksum_zero_skipped() {
        let src = Ipv4Addr::new(127, 0, 0, 1);
        let dst = Ipv4Addr::new(127, 0, 0, 1);
        let mut buf = alloc::vec![0u8; UDP_HDR_LEN + 4];
        UdpHdr::build_into(1, 2, src, dst, b"abcd", &mut buf);
        // Force checksum=0 on the wire (legal "skip").
        buf[6] = 0; buf[7] = 0;
        let h = UdpHdr::parse(&buf, src, dst).unwrap();
        assert_eq!(h.checksum, 0);
    }

    #[test]
    fn rejects_bad_length_field() {
        let src = Ipv4Addr::new(127, 0, 0, 1);
        let mut buf = alloc::vec![0u8; UDP_HDR_LEN + 4];
        UdpHdr::build_into(1, 2, src, src, b"abcd", &mut buf);
        buf[4] = 0xFF;  // claim much larger length than buffer
        assert_eq!(UdpHdr::parse(&buf, src, src).err().unwrap(), UdpError::BadLen);
    }
}
