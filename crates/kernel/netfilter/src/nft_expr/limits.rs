//! Sizes, counts and defaults the expression set is bounded by.

use crate::nft_expr::uapi::{NFT_REG_MAX, NFT_REG_SIZE};

/// Byte span of the addressable register file: five 16-byte slots, the
/// verdict slot included so register numbering and offsets agree.
pub const REG_BYTES: usize = NFT_REG_SIZE * (NFT_REG_MAX as usize + 1);

/// Interface-name field width — the width every name-valued key writes.
pub const IFNAMSIZ: usize = 16;

/// Conntrack helper-name field width.
pub const NF_CT_HELPER_NAME_LEN: usize = 16;

/// Conntrack connmark-label area width.
pub const NF_CT_LABELS_MAX_SIZE: usize = 16;

/// Hardware-address width the bridge ingress key writes.
pub const ETH_ALEN: usize = 6;

/// Fingerprint genre-string width the `osf` key writes.
pub const NFT_OSF_MAXGENRELEN: usize = 16;

/// Longest table / object / chain name an expression may reference.
pub const NFT_NAME_MAXLEN: usize = 256;

/// Packet-rate burst a `limit` uses when the rule names none.
pub const NFT_LIMIT_PKT_BURST_DEFAULT: u32 = 5;

/// Nanoseconds per second — the unit a limit's rate window is scaled by.
pub const NSEC_PER_SEC: u64 = 1_000_000_000;

/// Seconds in a day, the modulus the local-time-of-day key reduces by.
pub const SECS_PER_DAY: u64 = 86_400;

/// Fixed IPv6 main-header length, before any extension header.
pub const IPV6_FIXED_HDR: usize = 40;

/// Minimum TCP header length, before any option.
pub const TCP_MIN_HDR: usize = 20;

/// Widest option area a TCP header may carry.
pub const MAX_TCP_OPTION_SPACE: usize = 40;

/// L4 protocol numbers the transport-header base and the trackers key on.
pub const IPPROTO_ICMP:   u8 = 1;
pub const IPPROTO_TCP:    u8 = 6;
pub const IPPROTO_UDP:    u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const IPPROTO_SCTP:   u8 = 132;
pub const IPPROTO_DCCP:   u8 = 33;

/// Ethertypes the link-layer and neighbour paths check.
pub const ETH_P_IP:   u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86dd;

/// TCP option kinds the exthdr walker treats specially.
pub const TCPOPT_EOL:  u8 = 0;
pub const TCPOPT_NOP:  u8 = 1;
pub const TCPOPT_MSS:  u8 = 2;

/// IPv4 options the exthdr walker will report.
pub const IPOPT_LSRR: u8 = 131;
pub const IPOPT_SSRR: u8 = 137;
pub const IPOPT_RR:   u8 = 7;
pub const IPOPT_RA:   u8 = 148;

/// ICMP destination-unreachable codes an ICMPX reject maps onto.
pub const ICMP_NET_UNREACH:  u8 = 0;
pub const ICMP_HOST_UNREACH: u8 = 1;
pub const ICMP_PORT_UNREACH: u8 = 3;
pub const ICMP_PKT_FILTERED: u8 = 13;

/// ICMPv6 destination-unreachable codes an ICMPX reject maps onto.
pub const ICMPV6_NOROUTE:        u8 = 0;
pub const ICMPV6_ADM_PROHIBITED: u8 = 1;
pub const ICMPV6_ADDR_UNREACH:   u8 = 3;
pub const ICMPV6_PORT_UNREACH:   u8 = 4;
