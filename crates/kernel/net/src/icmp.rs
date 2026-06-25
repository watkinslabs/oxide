// ICMPv4 — RFC 792 echo request/reply plus router-generated errors.

use crate::ipv4::ip_checksum;

pub const ICMP_HDR_LEN: usize = 8;

pub const ICMP_TYPE_ECHO_REPLY:   u8 = 0;
pub const ICMP_TYPE_DEST_UNREACH: u8 = 3;
pub const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
pub const ICMP_TYPE_TIME_EXC:     u8 = 11;

/// F174: RFC 792 code subfields for ICMP_TYPE_DEST_UNREACH.
pub mod unreach_code {
    pub const NET:        u8 = 0;
    pub const HOST:       u8 = 1;
    pub const PROTOCOL:   u8 = 2;
    pub const PORT:       u8 = 3;
    pub const FRAG:       u8 = 4;
    pub const SRC_ROUTE:  u8 = 5;
}

/// RFC 792 code subfields for ICMP_TYPE_TIME_EXC.
pub mod time_exceeded_code {
    pub const TTL:      u8 = 0;
    pub const REASSEMB: u8 = 1;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IcmpError { Short, BadChecksum, BadType }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IcmpEcho {
    pub typ:     u8,
    pub code:    u8,
    pub checksum: u16,
    pub id:      u16,
    pub seq:     u16,
}

impl IcmpEcho {
    /// Build an Echo request/reply with the given id/seq + payload.
    /// `out` ≥ 8 + payload.len(); writes header into `out[..8]`,
    /// caller wrote payload into `out[8..]` first.
    /// # C: O(N) checksum
    pub fn build_into(&mut self, payload: &[u8], out: &mut [u8]) {
        out[0] = self.typ;
        out[1] = self.code;
        out[2] = 0; out[3] = 0;
        out[4..6].copy_from_slice(&self.id.to_be_bytes());
        out[6..8].copy_from_slice(&self.seq.to_be_bytes());
        out[8 .. 8 + payload.len()].copy_from_slice(payload);
        let cs = ip_checksum(&out[..8 + payload.len()]);
        self.checksum = cs;
        out[2..4].copy_from_slice(&cs.to_be_bytes());
    }

    /// Parse the 8-byte header out of `buf`. Validates checksum
    /// over the full ICMP message (`buf` must be the whole ICMP
    /// payload — header + data — or the checksum will be wrong).
    /// # C: O(N) checksum
    pub fn parse(buf: &[u8]) -> Result<Self, IcmpError> {
        if buf.len() < ICMP_HDR_LEN { return Err(IcmpError::Short); }
        if ip_checksum(buf) != 0 { return Err(IcmpError::BadChecksum); }
        Ok(Self {
            typ:      buf[0],
            code:     buf[1],
            checksum: u16::from_be_bytes([buf[2], buf[3]]),
            id:       u16::from_be_bytes([buf[4], buf[5]]),
            seq:      u16::from_be_bytes([buf[6], buf[7]]),
        })
    }
}

/// Build an Echo Reply for a received Echo Request. Returns the
/// reply bytes (header + payload) ready to ship under an IPv4
/// header. v1 echoes the entire request payload verbatim.
/// # C: O(N)
pub fn build_echo_reply(request: &[u8]) -> Result<alloc::vec::Vec<u8>, IcmpError> {
    let req = IcmpEcho::parse(request)?;
    if req.typ != ICMP_TYPE_ECHO_REQUEST { return Err(IcmpError::BadType); }
    let payload = &request[ICMP_HDR_LEN..];
    let mut out = alloc::vec![0u8; ICMP_HDR_LEN + payload.len()];
    let mut reply = IcmpEcho {
        typ: ICMP_TYPE_ECHO_REPLY,
        code: 0,
        checksum: 0,
        id: req.id,
        seq: req.seq,
    };
    reply.build_into(payload, &mut out);
    Ok(out)
}

/// Build an ICMP error body quoting the invoking IPv4 header and first 8
/// payload bytes. `invoking` starts at the original IPv4 header. # C: O(N)
pub fn build_ipv4_error(typ: u8, code: u8, invoking: &[u8]) -> Result<alloc::vec::Vec<u8>, IcmpError> {
    if invoking.len() < crate::ipv4::IPV4_HDR_LEN { return Err(IcmpError::Short); }
    let total = u16::from_be_bytes([invoking[2], invoking[3]]) as usize;
    if total < crate::ipv4::IPV4_HDR_LEN { return Err(IcmpError::Short); }
    let quote_len = core::cmp::min(total, invoking.len()).min(crate::ipv4::IPV4_HDR_LEN + 8);
    let mut out = alloc::vec![0u8; ICMP_HDR_LEN + quote_len];
    out[0] = typ;
    out[1] = code;
    out[4..8].copy_from_slice(&[0, 0, 0, 0]);
    out[ICMP_HDR_LEN..].copy_from_slice(&invoking[..quote_len]);
    let cs = ip_checksum(&out);
    out[2..4].copy_from_slice(&cs.to_be_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_round_trip() {
        let payload = b"hello-icmp";
        let mut req_buf = alloc::vec![0u8; ICMP_HDR_LEN + payload.len()];
        let mut req = IcmpEcho { typ: ICMP_TYPE_ECHO_REQUEST, code: 0, checksum: 0, id: 0x1234, seq: 1 };
        req.build_into(payload, &mut req_buf);
        let parsed = IcmpEcho::parse(&req_buf).unwrap();
        assert_eq!(parsed.typ, ICMP_TYPE_ECHO_REQUEST);
        assert_eq!(parsed.id, 0x1234);
    }

    #[test]
    fn build_reply_echoes_payload() {
        let payload = b"oxide-pings";
        let mut req_buf = alloc::vec![0u8; ICMP_HDR_LEN + payload.len()];
        let mut req = IcmpEcho { typ: ICMP_TYPE_ECHO_REQUEST, code: 0, checksum: 0, id: 0x5678, seq: 7 };
        req.build_into(payload, &mut req_buf);
        let reply_buf = build_echo_reply(&req_buf).unwrap();
        let reply = IcmpEcho::parse(&reply_buf).unwrap();
        assert_eq!(reply.typ, ICMP_TYPE_ECHO_REPLY);
        assert_eq!(reply.id, 0x5678);
        assert_eq!(reply.seq, 7);
        assert_eq!(&reply_buf[ICMP_HDR_LEN..], payload);
    }

    #[test]
    fn rejects_bad_checksum() {
        let payload = b"x";
        let mut buf = alloc::vec![0u8; ICMP_HDR_LEN + payload.len()];
        let mut req = IcmpEcho { typ: ICMP_TYPE_ECHO_REQUEST, code: 0, checksum: 0, id: 1, seq: 1 };
        req.build_into(payload, &mut buf);
        buf[5] ^= 0xFF;  // corrupt id high byte
        assert_eq!(IcmpEcho::parse(&buf).err().unwrap(), IcmpError::BadChecksum);
    }

    #[test]
    fn rejects_short() {
        let buf = [0u8; 4];
        assert_eq!(IcmpEcho::parse(&buf).err().unwrap(), IcmpError::Short);
    }

    #[test]
    fn build_reply_rejects_non_request() {
        let payload = b"x";
        let mut buf = alloc::vec![0u8; ICMP_HDR_LEN + payload.len()];
        let mut hdr = IcmpEcho { typ: ICMP_TYPE_ECHO_REPLY, code: 0, checksum: 0, id: 1, seq: 1 };
        hdr.build_into(payload, &mut buf);
        assert_eq!(build_echo_reply(&buf).err().unwrap(), IcmpError::BadType);
    }

    #[test]
    fn ipv4_error_quotes_header_and_eight_bytes() {
        let mut invoking = [0u8; crate::ipv4::IPV4_HDR_LEN + 12];
        let hdr = crate::ipv4::Ipv4Hdr::build(
            crate::Ipv4Addr::new(192, 0, 2, 1),
            crate::Ipv4Addr::new(198, 51, 100, 1),
            crate::IpProto::Udp,
            12,
            99,
        );
        hdr.write_to(&mut invoking[..crate::ipv4::IPV4_HDR_LEN]);
        invoking[crate::ipv4::IPV4_HDR_LEN..].copy_from_slice(b"abcdefghijkl");

        let out = build_ipv4_error(ICMP_TYPE_TIME_EXC, time_exceeded_code::TTL, &invoking).unwrap();
        assert_eq!(out[0], ICMP_TYPE_TIME_EXC);
        assert_eq!(out[1], time_exceeded_code::TTL);
        assert_eq!(ip_checksum(&out), 0);
        assert_eq!(&out[ICMP_HDR_LEN..], &invoking[..crate::ipv4::IPV4_HDR_LEN + 8]);
    }
}
