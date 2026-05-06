// ICMPv6 — RFC 4443. ECHO_REQUEST=128, ECHO_REPLY=129. Header
// + body checksum is computed over the IPv6 pseudo-header
// (src + dst + upper-layer-len + zeros + next-header=58) plus
// the entire ICMPv6 message.

use crate::addr::Ipv6Addr;
use crate::ipv4::ip_checksum;

pub const ICMPV6_HDR_LEN: usize = 8;
pub const ICMPV6_TYPE_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_TYPE_ECHO_REPLY:   u8 = 129;
pub const IPPROTO_ICMPV6:          u8 = 58;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Icmp6Error { Short, BadChecksum, BadType }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Icmp6Echo {
    pub typ:      u8,
    pub code:     u8,
    pub checksum: u16,
    pub id:       u16,
    pub seq:      u16,
}

impl Icmp6Echo {
    pub fn build_into(&mut self, src: Ipv6Addr, dst: Ipv6Addr,
                       payload: &[u8], out: &mut [u8])
    {
        out[0] = self.typ;
        out[1] = self.code;
        out[2] = 0; out[3] = 0;
        out[4..6].copy_from_slice(&self.id.to_be_bytes());
        out[6..8].copy_from_slice(&self.seq.to_be_bytes());
        out[8..8 + payload.len()].copy_from_slice(payload);
        let cs = compute_icmp6_checksum(out, src, dst);
        self.checksum = cs;
        out[2..4].copy_from_slice(&cs.to_be_bytes());
    }

    pub fn parse(buf: &[u8], src: Ipv6Addr, dst: Ipv6Addr) -> Result<Self, Icmp6Error> {
        if buf.len() < ICMPV6_HDR_LEN { return Err(Icmp6Error::Short); }
        if compute_icmp6_checksum_with_field(buf, src, dst, true) != 0 {
            return Err(Icmp6Error::BadChecksum);
        }
        Ok(Self {
            typ:      buf[0],
            code:     buf[1],
            checksum: u16::from_be_bytes([buf[2], buf[3]]),
            id:       u16::from_be_bytes([buf[4], buf[5]]),
            seq:      u16::from_be_bytes([buf[6], buf[7]]),
        })
    }
}

/// Build an Echo Reply for a received Echo Request.
pub fn build_echo_reply(src: Ipv6Addr, dst: Ipv6Addr, request: &[u8])
    -> Result<alloc::vec::Vec<u8>, Icmp6Error>
{
    let req = Icmp6Echo::parse(request, src, dst)?;
    if req.typ != ICMPV6_TYPE_ECHO_REQUEST { return Err(Icmp6Error::BadType); }
    let payload = &request[ICMPV6_HDR_LEN..];
    let mut out = alloc::vec![0u8; ICMPV6_HDR_LEN + payload.len()];
    let mut reply = Icmp6Echo {
        typ: ICMPV6_TYPE_ECHO_REPLY, code: 0, checksum: 0,
        id: req.id, seq: req.seq,
    };
    // Reply src/dst are flipped relative to the request.
    reply.build_into(dst, src, payload, &mut out);
    Ok(out)
}

fn compute_icmp6_checksum(buf: &[u8], src: Ipv6Addr, dst: Ipv6Addr) -> u16 {
    compute_icmp6_checksum_with_field(buf, src, dst, false)
}

fn compute_icmp6_checksum_with_field(
    buf: &[u8], src: Ipv6Addr, dst: Ipv6Addr, include_field: bool,
) -> u16 {
    // Pseudo-header: src(16) + dst(16) + upper_len(4) + zeros(3) + next_hdr(1)
    let mut pseudo = [0u8; 40];
    pseudo[0..16].copy_from_slice(&src.0);
    pseudo[16..32].copy_from_slice(&dst.0);
    pseudo[32..36].copy_from_slice(&(buf.len() as u32).to_be_bytes());
    pseudo[39] = IPPROTO_ICMPV6;
    let mut all = alloc::vec::Vec::with_capacity(40 + buf.len());
    all.extend_from_slice(&pseudo);
    all.extend_from_slice(buf);
    if !include_field && all.len() >= 40 + 4 {
        all[40 + 2] = 0;
        all[40 + 3] = 0;
    }
    ip_checksum(&all)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_round_trip() {
        let src = Ipv6Addr::LOOPBACK;
        let dst = Ipv6Addr::LOOPBACK;
        let payload = b"icmpv6";
        let mut req = alloc::vec![0u8; ICMPV6_HDR_LEN + payload.len()];
        let mut h = Icmp6Echo {
            typ: ICMPV6_TYPE_ECHO_REQUEST, code: 0, checksum: 0,
            id: 0xCAFE, seq: 1,
        };
        h.build_into(src, dst, payload, &mut req);
        let parsed = Icmp6Echo::parse(&req, src, dst).unwrap();
        assert_eq!(parsed.typ, ICMPV6_TYPE_ECHO_REQUEST);
        let reply = build_echo_reply(src, dst, &req).unwrap();
        let p = Icmp6Echo::parse(&reply, dst, src).unwrap();
        assert_eq!(p.typ, ICMPV6_TYPE_ECHO_REPLY);
        assert_eq!(p.id, 0xCAFE);
    }

    #[test]
    fn rejects_bad_checksum() {
        let src = Ipv6Addr::LOOPBACK;
        let payload = b"x";
        let mut buf = alloc::vec![0u8; ICMPV6_HDR_LEN + payload.len()];
        let mut h = Icmp6Echo { typ: ICMPV6_TYPE_ECHO_REQUEST, code: 0,
                                 checksum: 0, id: 1, seq: 1 };
        h.build_into(src, src, payload, &mut buf);
        buf[5] ^= 0xFF;
        assert_eq!(Icmp6Echo::parse(&buf, src, src).err().unwrap(), Icmp6Error::BadChecksum);
    }
}
