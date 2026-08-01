// `IPPROTO_IPV6` ABI numbers. UAPI only — no policy, no dispatch.

pub const SOL_IPV6: u64 = 41;

pub const IPV6_ADDRFORM: u64 = 1;
pub const IPV6_2292PKTINFO: u64 = 2;
pub const IPV6_2292HOPOPTS: u64 = 3;
pub const IPV6_2292DSTOPTS: u64 = 4;
pub const IPV6_2292RTHDR: u64 = 5;
pub const IPV6_2292PKTOPTIONS: u64 = 6;
pub const IPV6_CHECKSUM: u64 = 7;
pub const IPV6_2292HOPLIMIT: u64 = 8;
pub const IPV6_NEXTHOP: u64 = 9;
pub const IPV6_AUTHHDR: u64 = 10;
pub const IPV6_FLOWINFO: u64 = 11;

pub const IPV6_UNICAST_HOPS: u64 = 16;
pub const IPV6_MULTICAST_IF: u64 = 17;
pub const IPV6_MULTICAST_HOPS: u64 = 18;
pub const IPV6_MULTICAST_LOOP: u64 = 19;
pub const IPV6_ADD_MEMBERSHIP: u64 = 20;
pub const IPV6_DROP_MEMBERSHIP: u64 = 21;
pub const IPV6_ROUTER_ALERT: u64 = 22;
pub const IPV6_MTU_DISCOVER: u64 = 23;
pub const IPV6_MTU: u64 = 24;
pub const IPV6_RECVERR: u64 = 25;
pub const IPV6_V6ONLY: u64 = 26;
pub const IPV6_JOIN_ANYCAST: u64 = 27;
pub const IPV6_LEAVE_ANYCAST: u64 = 28;
pub const IPV6_MULTICAST_ALL: u64 = 29;
pub const IPV6_ROUTER_ALERT_ISOLATE: u64 = 30;
pub const IPV6_RECVERR_RFC4884: u64 = 31;
pub const IPV6_FLOWLABEL_MGR: u64 = 32;
pub const IPV6_FLOWINFO_SEND: u64 = 33;
pub const IPV6_IPSEC_POLICY: u64 = 34;
pub const IPV6_XFRM_POLICY: u64 = 35;
pub const IPV6_HDRINCL: u64 = 36;

pub const MCAST_JOIN_GROUP: u64 = 42;
pub const MCAST_BLOCK_SOURCE: u64 = 43;
pub const MCAST_UNBLOCK_SOURCE: u64 = 44;
pub const MCAST_LEAVE_GROUP: u64 = 45;
pub const MCAST_JOIN_SOURCE_GROUP: u64 = 46;
pub const MCAST_LEAVE_SOURCE_GROUP: u64 = 47;
pub const MCAST_MSFILTER: u64 = 48;

pub const IPV6_RECVPKTINFO: u64 = 49;
pub const IPV6_PKTINFO: u64 = 50;
pub const IPV6_RECVHOPLIMIT: u64 = 51;
pub const IPV6_HOPLIMIT: u64 = 52;
pub const IPV6_RECVHOPOPTS: u64 = 53;
pub const IPV6_HOPOPTS: u64 = 54;
pub const IPV6_RTHDRDSTOPTS: u64 = 55;
pub const IPV6_RECVRTHDR: u64 = 56;
pub const IPV6_RTHDR: u64 = 57;
pub const IPV6_RECVDSTOPTS: u64 = 58;
pub const IPV6_DSTOPTS: u64 = 59;
pub const IPV6_RECVPATHMTU: u64 = 60;
pub const IPV6_PATHMTU: u64 = 61;
pub const IPV6_DONTFRAG: u64 = 62;
pub const IPV6_USE_MIN_MTU: u64 = 63;
pub const IPV6_RECVTCLASS: u64 = 66;
pub const IPV6_TCLASS: u64 = 67;
pub const IPV6_AUTOFLOWLABEL: u64 = 70;
pub const IPV6_ADDR_PREFERENCES: u64 = 72;
pub const IPV6_MINHOPCOUNT: u64 = 73;
pub const IPV6_RECVORIGDSTADDR: u64 = 74;
pub const IPV6_TRANSPARENT: u64 = 75;
pub const IPV6_UNICAST_IF: u64 = 76;
pub const IPV6_RECVFRAGSIZE: u64 = 77;
pub const IPV6_FREEBIND: u64 = 78;

/// `MRT6_BASE ..= MRT6_MAX` — the multicast-routing window, which answers
/// `ENOPROTOOPT` without a multicast router.
pub const MRT6_BASE: u64 = 200;
pub const MRT6_MAX: u64 = MRT6_BASE + 10;

/// `IPV6_MTU_DISCOVER` value window.
pub const IPV6_PMTUDISC_DONT: i32 = 0;
pub const IPV6_PMTUDISC_WANT: i32 = 1;
pub const IPV6_PMTUDISC_DO: i32 = 2;
pub const IPV6_PMTUDISC_PROBE: i32 = 3;
pub const IPV6_PMTUDISC_INTERFACE: i32 = 4;
pub const IPV6_PMTUDISC_OMIT: i32 = 5;

/// The smallest link MTU IPv6 permits, and therefore the floor `IPV6_MTU`
/// accepts for a caller-named fragmentation size.
pub const IPV6_MIN_MTU: i32 = 1280;

pub const HOP_LIMIT_MAX: i32 = 255;
/// "Derive the per-route hop limit" sentinel.
pub const HOP_LIMIT_ROUTE: i32 = -1;
pub const IPV6_DEFAULT_MCASTHOPS: i32 = 1;
pub const IPV6_DEFAULT_HOPLIMIT: i32 = 64;

/// `IPV6_ADDR_PREFERENCES` source-selection bits.
pub const IPV6_PREFER_SRC_TMP: i32 = 0x0001;
pub const IPV6_PREFER_SRC_PUBLIC: i32 = 0x0002;
pub const IPV6_PREFER_SRC_PUBTMP_DEFAULT: i32 = 0x0100;
pub const IPV6_PREFER_SRC_COA: i32 = 0x0004;
pub const IPV6_PREFER_SRC_HOME: i32 = 0x0400;
pub const IPV6_PREFER_SRC_CGA: i32 = 0x0008;
pub const IPV6_PREFER_SRC_NONCGA: i32 = 0x0800;
/// Every bit `IPV6_ADDR_PREFERENCES` owns.
pub const IPV6_PREFER_SRC_MASK: i32 = IPV6_PREFER_SRC_TMP | IPV6_PREFER_SRC_PUBLIC
    | IPV6_PREFER_SRC_PUBTMP_DEFAULT | IPV6_PREFER_SRC_COA | IPV6_PREFER_SRC_HOME
    | IPV6_PREFER_SRC_CGA | IPV6_PREFER_SRC_NONCGA;

/// `struct in6_pktinfo` — a 16-byte address then a 4-byte interface index.
pub const IN6_PKTINFO_SIZE: usize = 20;
/// `struct ipv6_mreq` — a 16-byte address then a 4-byte interface index.
pub const IPV6_MREQ_SIZE: usize = 20;
/// `struct ip6_mtuinfo` — a 28-byte socket address then the MTU, padded.
pub const IP6_MTUINFO_SIZE: usize = 32;
/// `struct in6_flowlabel_req`.
pub const IN6_FLOWLABEL_REQ_SIZE: usize = 32;

/// `struct ipv6_opt_hdr` header, and the option area's alignment and ceiling.
pub const IPV6_OPT_HDR_SIZE: usize = 8;
pub const IPV6_OPT_MAX: usize = 8 * 255;

/// Routing header types with a socket-visible sticky form.
pub const IPV6_SRCRT_TYPE_0: u8 = 0;
pub const IPV6_SRCRT_TYPE_2: u8 = 2;
pub const IPV6_SRCRT_TYPE_4: u8 = 4;

pub const IPV6_FLOWINFO_FLOWLABEL: u32 = 0x000f_ffff;
pub const IPV6_FLOWINFO_PRIORITY: u32 = 0x0ff0_0000;
/// The stateless half of the label space.
pub const IPV6_FLOWLABEL_STATELESS_FLAG: u32 = 0x0008_0000;

pub const IPV6_FL_A_GET: u8 = 0;
pub const IPV6_FL_A_PUT: u8 = 1;
pub const IPV6_FL_A_RENEW: u8 = 2;

pub const IPV6_FL_F_CREATE: u16 = 1;
pub const IPV6_FL_F_EXCL: u16 = 2;
pub const IPV6_FL_F_REFLECT: u16 = 4;
pub const IPV6_FL_F_REMOTE: u16 = 8;

pub const IPV6_FL_S_NONE: u8 = 0;
pub const IPV6_FL_S_EXCL: u8 = 1;
pub const IPV6_FL_S_PROCESS: u8 = 2;
pub const IPV6_FL_S_USER: u8 = 3;
pub const IPV6_FL_S_ANY: u8 = 255;

/// The address family `IPV6_ADDRFORM` converts a socket to.
pub const PF_INET: i32 = 2;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_RAW: u8 = 255;
