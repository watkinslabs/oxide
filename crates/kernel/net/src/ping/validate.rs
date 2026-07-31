// Echo-only message admission for ICMP datagram endpoints. An endpoint of this
// kind may originate exactly the echo probes its protocol defines — it can
// never forge an arbitrary ICMP type the way a raw endpoint can. Ungated so the
// ordering is covered by `cargo test -p net` on the host.

use crate::netdev::NetError;

pub const ICMP_TYPE_EXT_ECHO_REQUEST: u8 = 42;
pub const ICMP_TYPE_EXT_ECHO_REPLY: u8 = 43;
pub const ICMPV6_TYPE_EXT_ECHO_REQUEST: u8 = 160;
pub const ICMPV6_TYPE_EXT_ECHO_REPLY: u8 = 161;

/// The message header this endpoint class carries, in wire order.
pub const HEADER_LEN: usize = 8;
/// Largest message the endpoint accepts; the length operand is a 16-bit field
/// on the wire.
pub const MAX_MESSAGE: usize = u16::MAX as usize;

/// The two address families that register an ICMP datagram endpoint.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PingFamily { V4, V6 }

/// The echo probe fields the sender supplies. The identifier is deliberately
/// absent: it is owned by the kernel, never by the caller.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct EchoHeader {
    pub typ: u8,
    pub code: u8,
    pub sequence: u16,
}

/// Whether one type/code pair is an echo probe this family can originate. The
/// same predicate selects the quoted probe an ICMP error may report. # C: O(1)
pub fn supported(family: PingFamily, typ: u8, code: u8) -> bool {
    if code != 0 { return false; }
    match family {
        PingFamily::V4 => typ == crate::icmp::ICMP_TYPE_ECHO_REQUEST
            || typ == ICMP_TYPE_EXT_ECHO_REQUEST,
        PingFamily::V6 => typ == crate::icmpv6::ICMPV6_TYPE_ECHO_REQUEST
            || typ == ICMPV6_TYPE_EXT_ECHO_REQUEST,
    }
}

/// Whether a received type is a reply this endpoint class demultiplexes. # C: O(1)
pub fn is_reply(family: PingFamily, typ: u8) -> bool {
    match family {
        PingFamily::V4 => typ == crate::icmp::ICMP_TYPE_ECHO_REPLY
            || typ == ICMP_TYPE_EXT_ECHO_REPLY,
        PingFamily::V6 => typ == crate::icmpv6::ICMPV6_TYPE_ECHO_REPLY
            || typ == ICMPV6_TYPE_EXT_ECHO_REPLY,
    }
}

/// Screen one outbound message before any address or route work runs: length
/// window first, then the out-of-band flag, then the echo-only type/code gate.
/// # C: O(1)
pub fn admit_send(family: PingFamily, message: &[u8], oob: bool) -> Result<EchoHeader, NetError> {
    if message.len() > MAX_MESSAGE { return Err(NetError::Emsgsize); }
    if message.len() < HEADER_LEN { return Err(NetError::Einval); }
    if oob { return Err(NetError::Eopnotsupp); }
    let header = EchoHeader {
        typ: message[0],
        code: message[1],
        sequence: u16::from_be_bytes([message[6], message[7]]),
    };
    if !supported(family, header.typ, header.code) { return Err(NetError::Einval); }
    Ok(header)
}

/// The identifier field of a message already known to carry the header. # C: O(1)
pub fn identifier(message: &[u8]) -> u16 {
    u16::from_be_bytes([message[4], message[5]])
}

/// Rewrite one caller-supplied message with the kernel-owned identifier,
/// preserving the sequence and body the caller chose. The checksum field is
/// zeroed; the transmit path owns the final value. # C: O(len)
pub fn stamp_identifier(message: &[u8], ident: u16) -> alloc::vec::Vec<u8> {
    let mut out = message.to_vec();
    out[2] = 0;
    out[3] = 0;
    out[4..6].copy_from_slice(&ident.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo(typ: u8, code: u8) -> alloc::vec::Vec<u8> {
        alloc::vec![typ, code, 0xff, 0xff, 0xde, 0xad, 0x00, 0x07, 1, 2, 3, 4]
    }

    #[test]
    fn only_echo_probes_may_be_originated() {
        assert!(admit_send(PingFamily::V4, &echo(8, 0), false).is_ok());
        assert!(admit_send(PingFamily::V4, &echo(42, 0), false).is_ok());
        assert!(admit_send(PingFamily::V6, &echo(128, 0), false).is_ok());
        assert!(admit_send(PingFamily::V6, &echo(160, 0), false).is_ok());
        // Forging a router-generated error, a redirect, or a neighbour message
        // is exactly what this endpoint class exists to prevent.
        for typ in [0u8, 3, 5, 11, 13, 17, 128] {
            assert_eq!(admit_send(PingFamily::V4, &echo(typ, 0), false), Err(NetError::Einval),
                "v4 type {typ} must not be originable");
        }
        for typ in [1u8, 2, 3, 4, 129, 133, 134, 135, 136, 137, 8] {
            assert_eq!(admit_send(PingFamily::V6, &echo(typ, 0), false), Err(NetError::Einval),
                "v6 type {typ} must not be originable");
        }
        // A nonzero code is not an echo probe even with the right type.
        assert_eq!(admit_send(PingFamily::V4, &echo(8, 1), false), Err(NetError::Einval));
        assert_eq!(admit_send(PingFamily::V6, &echo(128, 3), false), Err(NetError::Einval));
    }

    #[test]
    fn length_window_outranks_the_out_of_band_flag_and_the_type_gate() {
        let oversize = alloc::vec![8u8; MAX_MESSAGE + 1];
        assert_eq!(admit_send(PingFamily::V4, &oversize, true), Err(NetError::Emsgsize));
        assert_eq!(admit_send(PingFamily::V4, &[8, 0, 0, 0, 0, 0, 0], true), Err(NetError::Einval));
        assert_eq!(admit_send(PingFamily::V4, &[], false), Err(NetError::Einval));
        // A full header of a forbidden type still reports the out-of-band flag
        // first, because the flag screen precedes the type lookup.
        assert_eq!(admit_send(PingFamily::V4, &echo(3, 0), true), Err(NetError::Eopnotsupp));
        assert_eq!(admit_send(PingFamily::V4, &echo(8, 0), true), Err(NetError::Eopnotsupp));
        // Exactly the header and nothing else is a valid zero-body probe.
        assert!(admit_send(PingFamily::V4, &[8, 0, 0, 0, 0, 0, 0, 1], false).is_ok());
    }

    #[test]
    fn sequence_survives_and_the_caller_identifier_is_discarded() {
        let message = echo(8, 0);
        assert_eq!(identifier(&message), 0xdead);
        let header = admit_send(PingFamily::V4, &message, false).unwrap();
        assert_eq!(header.sequence, 7);
        let stamped = stamp_identifier(&message, 0x1234);
        assert_eq!(identifier(&stamped), 0x1234);
        assert_eq!(&stamped[6..8], &[0x00, 0x07], "sequence must survive the rewrite");
        assert_eq!(&stamped[8..], &[1, 2, 3, 4], "body must survive the rewrite");
        assert_eq!(&stamped[2..4], &[0, 0], "checksum field must be cleared for recomputation");
    }

    #[test]
    fn replies_are_the_only_demultiplexed_receive_types() {
        assert!(is_reply(PingFamily::V4, 0));
        assert!(is_reply(PingFamily::V4, 43));
        assert!(!is_reply(PingFamily::V4, 8));
        assert!(!is_reply(PingFamily::V4, 3));
        assert!(is_reply(PingFamily::V6, 129));
        assert!(is_reply(PingFamily::V6, 161));
        assert!(!is_reply(PingFamily::V6, 128));
        assert!(!is_reply(PingFamily::V6, 1));
    }
}
