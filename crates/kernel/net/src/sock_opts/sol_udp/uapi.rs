// Level-17 ABI numbers. Values only — every decision that reads them lives in
// `table`, `cork`, or `segment`.

/// `SOL_UDP` / `IPPROTO_UDP`.
pub const SOL_UDP: u64 = 17;

pub const UDP_CORK: u64 = 1;
pub const UDP_ENCAP: u64 = 100;
pub const UDP_NO_CHECK6_TX: u64 = 101;
pub const UDP_NO_CHECK6_RX: u64 = 102;
pub const UDP_SEGMENT: u64 = 103;
pub const UDP_GRO: u64 = 104;

/// The two option numbers UDP-Lite once claimed at this level. They are
/// reserved-and-unhandled: level 17 answers `ENOPROTOOPT` for both, exactly
/// like any other unknown option number.
pub const UDPLITE_SEND_CSCOV: u64 = 10;
pub const UDPLITE_RECV_CSCOV: u64 = 11;

/// `IPPROTO_UDPLITE`. Reaching `setsockopt`/`getsockopt` with this level on a
/// UDP socket is an unrecognized level, not a UDP-Lite request.
pub const IPPROTO_UDPLITE: u64 = 136;

// `UDP_ENCAP` values. Only the three below are accepted; every other value is
// `ENOPROTOOPT` because no protocol claims it as an encapsulation identity.
pub const UDP_ENCAP_NONE: i32 = 0;
pub const UDP_ENCAP_ESPINUDP_NON_IKE: i32 = 1;
pub const UDP_ENCAP_ESPINUDP: i32 = 2;
pub const UDP_ENCAP_L2TPINUDP: i32 = 3;
pub const UDP_ENCAP_GTP0: i32 = 4;
pub const UDP_ENCAP_GTP1U: i32 = 5;
pub const UDP_ENCAP_RXRPC: i32 = 6;
pub const TCP_ENCAP_ESPINTCP: i32 = 7;
pub const UDP_ENCAP_OVPNINUDP: i32 = 8;

/// Largest `UDP_SEGMENT` size the option accepts (`USHRT_MAX`).
pub const UDP_SEGMENT_MAX: i32 = u16::MAX as i32;

/// Largest number of segments one segmented send may produce.
pub const UDP_MAX_SEGMENTS: usize = 1 << 7;

/// Bytes of IPv4 + UDP header a segmented IPv4 datagram carries.
pub const UDP4_SEGMENT_HDR_LEN: usize = crate::ipv4::IPV4_HDR_LEN + crate::udp::UDP_HDR_LEN;

/// Bytes of IPv6 + UDP header a segmented IPv6 datagram carries.
pub const UDP6_SEGMENT_HDR_LEN: usize = crate::ipv6::IPV6_HDR_LEN + crate::udp::UDP_HDR_LEN;
