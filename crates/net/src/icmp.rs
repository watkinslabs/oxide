// ICMPv4 — RFC 792. v1 implements ECHO request/reply only;
// DEST_UNREACH and TIME_EXCEEDED are short-fuse follow-ups
// (kernel needs them when a route lookup misses or TTL=0 on rx).

use crate::ipv4::ip_checksum;

pub const ICMP_HDR_LEN: usize = 8;

pub const ICMP_TYPE_ECHO_REPLY:   u8 = 0;
pub const ICMP_TYPE_DEST_UNREACH: u8 = 3;
pub const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
pub const ICMP_TYPE_TIME_EXC:     u8 = 11;

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
}
