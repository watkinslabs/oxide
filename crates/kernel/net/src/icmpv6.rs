// ICMPv6 — RFC 4443. ECHO_REQUEST=128, ECHO_REPLY=129. Header
// + body checksum is computed over the IPv6 pseudo-header
// (src + dst + upper-layer-len + zeros + next-header=58) plus
// the entire ICMPv6 message.

use crate::addr::Ipv6Addr;
use crate::ipv4::ip_checksum;

pub const ICMPV6_HDR_LEN: usize = 8;
pub const ICMPV6_TYPE_PACKET_TOO_BIG: u8 = 2;
pub const ICMPV6_TYPE_ECHO_REQUEST:   u8 = 128;
pub const ICMPV6_TYPE_ECHO_REPLY:     u8 = 129;
pub const ICMPV6_TYPE_MLD_QUERY:      u8 = 130;
pub const ICMPV6_TYPE_MLD_REPORT:     u8 = 131;
pub const ICMPV6_TYPE_MLD_DONE:       u8 = 132;
pub const ICMPV6_TYPE_MLDV2_REPORT:   u8 = 143;
pub const IPPROTO_ICMPV6:          u8 = 58;
pub const MLDV2_RECORD_MODE_IS_INCLUDE: u8 = 1;
pub const MLDV2_RECORD_MODE_IS_EXCLUDE: u8 = 2;
pub const MLDV2_RECORD_CHANGE_TO_INCLUDE: u8 = 3;
pub const MLDV2_RECORD_CHANGE_TO_EXCLUDE: u8 = 4;
pub const IPV6_MLDV2_ROUTERS: Ipv6Addr = Ipv6Addr([
    0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16,
]);

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
    /// # C: O(1)
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

    /// # C: O(N)
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mldv1Query {
    pub max_resp_delay: u16,
    pub group:          Ipv6Addr,
    pub sources:        alloc::vec::Vec<Ipv6Addr>,
}

impl Mldv1Query {
    /// Parse an MLDv1/v2 Listener Query. # C: O(N)
    pub fn parse(buf: &[u8], src: Ipv6Addr, dst: Ipv6Addr) -> Result<Self, Icmp6Error> {
        if buf.len() < 24 { return Err(Icmp6Error::Short); }
        if buf.len() != 24 && buf.len() < 28 { return Err(Icmp6Error::Short); }
        if compute_icmp6_checksum_with_field(buf, src, dst, true) != 0 {
            return Err(Icmp6Error::BadChecksum);
        }
        if buf[0] != ICMPV6_TYPE_MLD_QUERY || buf[1] != 0 {
            return Err(Icmp6Error::BadType);
        }
        let mut group = [0u8; 16];
        group.copy_from_slice(&buf[8..24]);
        let mut sources = alloc::vec::Vec::new();
        if buf.len() >= 28 {
            let nsrc = u16::from_be_bytes([buf[26], buf[27]]) as usize;
            let need = 28 + 16 * nsrc;
            if buf.len() < need { return Err(Icmp6Error::Short); }
            sources.reserve(nsrc);
            for chunk in buf[28..need].chunks_exact(16) {
                let mut addr = [0u8; 16];
                addr.copy_from_slice(chunk);
                sources.push(Ipv6Addr(addr));
            }
        }
        Ok(Self {
            max_resp_delay: u16::from_be_bytes([buf[4], buf[5]]),
            group: Ipv6Addr(group),
            sources,
        })
    }
}

/// Build an Echo Reply for a received Echo Request.
/// # C: O(1)
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

/// Build an MLDv1 Listener Report for `group`. # C: O(1)
pub fn build_mldv1_report(src: Ipv6Addr, group: Ipv6Addr) -> alloc::vec::Vec<u8> {
    build_mldv1(ICMPV6_TYPE_MLD_REPORT, src, group, group)
}

/// Build an MLDv1 Done message for `group`. # C: O(1)
pub fn build_mldv1_done(src: Ipv6Addr, group: Ipv6Addr) -> alloc::vec::Vec<u8> {
    build_mldv1(ICMPV6_TYPE_MLD_DONE, src, crate::ndp::IPV6_ALL_ROUTERS, group)
}

/// Build a single-record MLDv2 Listener Report. # C: O(N sources)
pub fn build_mldv2_report(
    src: Ipv6Addr,
    record_type: u8,
    group: Ipv6Addr,
    sources: &[Ipv6Addr],
) -> alloc::vec::Vec<u8> {
    let nsrc = sources.len().min(u16::MAX as usize);
    let mut out = alloc::vec![0u8; 8 + 20 + 16 * nsrc];
    out[0] = ICMPV6_TYPE_MLDV2_REPORT;
    out[6..8].copy_from_slice(&1u16.to_be_bytes());
    out[8] = record_type;
    out[10..12].copy_from_slice(&(nsrc as u16).to_be_bytes());
    out[12..28].copy_from_slice(&group.0);
    for (i, s) in sources.iter().take(nsrc).enumerate() {
        out[28 + 16 * i..44 + 16 * i].copy_from_slice(&s.0);
    }
    let cs = compute_icmp6_checksum(&out, src, IPV6_MLDV2_ROUTERS);
    out[2..4].copy_from_slice(&cs.to_be_bytes());
    out
}

/// Build an MLDv1 Listener Query. # C: O(1)
pub fn build_mldv1_query(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    group: Ipv6Addr,
    max_resp_delay: u16,
) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec![0u8; 24];
    out[0] = ICMPV6_TYPE_MLD_QUERY;
    out[4..6].copy_from_slice(&max_resp_delay.to_be_bytes());
    out[8..24].copy_from_slice(&group.0);
    let cs = compute_icmp6_checksum(&out, src, dst);
    out[2..4].copy_from_slice(&cs.to_be_bytes());
    out
}

/// Build an MLDv2 Listener Query. # C: O(N sources)
pub fn build_mldv2_query(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    group: Ipv6Addr,
    max_resp_delay: u16,
    sources: &[Ipv6Addr],
) -> alloc::vec::Vec<u8> {
    let nsrc = sources.len().min(u16::MAX as usize);
    let mut out = alloc::vec![0u8; 28 + 16 * nsrc];
    out[0] = ICMPV6_TYPE_MLD_QUERY;
    out[4..6].copy_from_slice(&max_resp_delay.to_be_bytes());
    out[8..24].copy_from_slice(&group.0);
    out[26..28].copy_from_slice(&(nsrc as u16).to_be_bytes());
    for (i, s) in sources.iter().take(nsrc).enumerate() {
        out[28 + 16 * i..44 + 16 * i].copy_from_slice(&s.0);
    }
    let cs = compute_icmp6_checksum(&out, src, dst);
    out[2..4].copy_from_slice(&cs.to_be_bytes());
    out
}

fn build_mldv1(typ: u8, src: Ipv6Addr, dst: Ipv6Addr, group: Ipv6Addr)
    -> alloc::vec::Vec<u8>
{
    let mut out = alloc::vec![0u8; 24];
    out[0] = typ;
    out[8..24].copy_from_slice(&group.0);
    let cs = compute_icmp6_checksum(&out, src, dst);
    out[2..4].copy_from_slice(&cs.to_be_bytes());
    out
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

    #[test]
    fn mld_query_round_trip() {
        let src = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
        let dst = crate::ndp::IPV6_ALL_NODES;
        let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x1234]);
        let query = build_mldv1_query(src, dst, group, 1000);
        let parsed = Mldv1Query::parse(&query, src, dst).unwrap();
        assert_eq!(parsed.max_resp_delay, 1000);
        assert_eq!(parsed.group, group);
    }

    #[test]
    fn mldv2_report_layout_and_checksum() {
        let src = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
        let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x1234]);
        let source = Ipv6Addr::from_segments([0x2001,0xdb8,0,0,0,0,0,1]);
        let r = build_mldv2_report(src, MLDV2_RECORD_MODE_IS_INCLUDE, group, &[source]);
        assert_eq!(r[0], ICMPV6_TYPE_MLDV2_REPORT);
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1);
        assert_eq!(r[8], MLDV2_RECORD_MODE_IS_INCLUDE);
        assert_eq!(u16::from_be_bytes([r[10], r[11]]), 1);
        assert_eq!(&r[12..28], &group.0);
        assert_eq!(&r[28..44], &source.0);
        assert_eq!(compute_icmp6_checksum_with_field(&r, src, IPV6_MLDV2_ROUTERS, true), 0);
    }
}
