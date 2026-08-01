// `IPPROTO_IP` ABI numbers. UAPI only — no policy, no dispatch.
//
// The header option area's own ABI — the option kinds, the timestamp flag
// nibble and the widest area an IPv4 header can carry — is owned by
// `ipv4_options::uapi`, which is ungated because the option-area decisions are.
// Re-exported here so one option level names one set of numbers.

pub use crate::ipv4_options::uapi::*;

pub const SOL_IP: u64 = 0;

pub const IP_TOS: u64 = 1;
pub const IP_TTL: u64 = 2;
pub const IP_HDRINCL: u64 = 3;
pub const IP_OPTIONS: u64 = 4;
pub const IP_ROUTER_ALERT: u64 = 5;
pub const IP_RECVOPTS: u64 = 6;
pub const IP_RETOPTS: u64 = 7;
pub const IP_PKTINFO: u64 = 8;
pub const IP_PKTOPTIONS: u64 = 9;
pub const IP_MTU_DISCOVER: u64 = 10;
pub const IP_RECVERR: u64 = 11;
pub const IP_RECVTTL: u64 = 12;
pub const IP_RECVTOS: u64 = 13;
pub const IP_MTU: u64 = 14;
pub const IP_FREEBIND: u64 = 15;
pub const IP_IPSEC_POLICY: u64 = 16;
pub const IP_XFRM_POLICY: u64 = 17;
pub const IP_PASSSEC: u64 = 18;
pub const IP_TRANSPARENT: u64 = 19;
pub const IP_RECVORIGDSTADDR: u64 = 20;
pub const IP_MINTTL: u64 = 21;
pub const IP_NODEFRAG: u64 = 22;
pub const IP_CHECKSUM: u64 = 23;
pub const IP_BIND_ADDRESS_NO_PORT: u64 = 24;
pub const IP_RECVFRAGSIZE: u64 = 25;
pub const IP_RECVERR_RFC4884: u64 = 26;

pub const IP_MULTICAST_IF: u64 = 32;
pub const IP_MULTICAST_TTL: u64 = 33;
pub const IP_MULTICAST_LOOP: u64 = 34;
pub const IP_ADD_MEMBERSHIP: u64 = 35;
pub const IP_DROP_MEMBERSHIP: u64 = 36;
pub const IP_UNBLOCK_SOURCE: u64 = 37;
pub const IP_BLOCK_SOURCE: u64 = 38;
pub const IP_ADD_SOURCE_MEMBERSHIP: u64 = 39;
pub const IP_DROP_SOURCE_MEMBERSHIP: u64 = 40;
pub const IP_MSFILTER: u64 = 41;
pub const MCAST_JOIN_GROUP: u64 = 42;
pub const MCAST_BLOCK_SOURCE: u64 = 43;
pub const MCAST_UNBLOCK_SOURCE: u64 = 44;
pub const MCAST_LEAVE_GROUP: u64 = 45;
pub const MCAST_JOIN_SOURCE_GROUP: u64 = 46;
pub const MCAST_LEAVE_SOURCE_GROUP: u64 = 47;
pub const MCAST_MSFILTER: u64 = 48;
pub const IP_MULTICAST_ALL: u64 = 49;
pub const IP_UNICAST_IF: u64 = 50;
pub const IP_LOCAL_PORT_RANGE: u64 = 51;
pub const IP_PROTOCOL: u64 = 52;

/// `MRT_BASE ..= MRT_MAX` — the multicast-routing option window, which the
/// option table never reaches: without a multicast router these numbers
/// answer `ENOPROTOOPT` like any other unknown option.
pub const MRT_BASE: u64 = 200;
pub const MRT_MAX: u64 = MRT_BASE + 10;

/// `IP_MTU_DISCOVER` value window.
pub const IP_PMTUDISC_DONT: i32 = 0;
pub const IP_PMTUDISC_WANT: i32 = 1;
pub const IP_PMTUDISC_DO: i32 = 2;
pub const IP_PMTUDISC_PROBE: i32 = 3;
pub const IP_PMTUDISC_INTERFACE: i32 = 4;
pub const IP_PMTUDISC_OMIT: i32 = 5;

/// Hop-limit window shared by `IP_TTL`, `IP_MINTTL` and `IP_MULTICAST_TTL`.
pub const TTL_MAX: i32 = 255;
/// `IP_TTL`'s "keep the route-selected hop limit" sentinel.
pub const TTL_ROUTE_DEFAULT: i32 = -1;
/// Outbound multicast hop limit when `IP_MULTICAST_TTL` is unset.
pub const DEFAULT_MULTICAST_TTL: i32 = 1;

/// `IPPROTO_RAW`: a socket opened on it cannot join the router-alert chain.
pub const IPPROTO_RAW: u8 = 255;
