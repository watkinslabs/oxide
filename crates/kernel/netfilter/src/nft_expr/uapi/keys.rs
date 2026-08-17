//! Key, base, operation and type enumerations selecting what an expression
//! reads or does. Values are the Linux UAPI ones.

// --- cmp / range operations ---

pub const NFT_CMP_EQ:  u32 = 0;
pub const NFT_CMP_NEQ: u32 = 1;
pub const NFT_CMP_LT:  u32 = 2;
pub const NFT_CMP_LTE: u32 = 3;
pub const NFT_CMP_GT:  u32 = 4;
pub const NFT_CMP_GTE: u32 = 5;

pub const NFT_RANGE_EQ:  u32 = 0;
pub const NFT_RANGE_NEQ: u32 = 1;

// --- byteorder operations ---

pub const NFT_BYTEORDER_NTOH: u32 = 0;
pub const NFT_BYTEORDER_HTON: u32 = 1;

// --- payload bases and checksum types ---

pub const NFT_PAYLOAD_LL_HEADER:        u32 = 0;
pub const NFT_PAYLOAD_NETWORK_HEADER:   u32 = 1;
pub const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;
pub const NFT_PAYLOAD_INNER_HEADER:     u32 = 3;
pub const NFT_PAYLOAD_TUN_HEADER:       u32 = 4;

pub const NFT_PAYLOAD_CSUM_NONE: u32 = 0;
pub const NFT_PAYLOAD_CSUM_INET: u32 = 1;
pub const NFT_PAYLOAD_CSUM_SCTP: u32 = 2;

// --- meta keys ---

pub const NFT_META_LEN:           u32 = 0;
pub const NFT_META_PROTOCOL:      u32 = 1;
pub const NFT_META_PRIORITY:      u32 = 2;
pub const NFT_META_MARK:          u32 = 3;
pub const NFT_META_IIF:           u32 = 4;
pub const NFT_META_OIF:           u32 = 5;
pub const NFT_META_IIFNAME:       u32 = 6;
pub const NFT_META_OIFNAME:       u32 = 7;
pub const NFT_META_IIFTYPE:       u32 = 8;
pub const NFT_META_OIFTYPE:       u32 = 9;
pub const NFT_META_SKUID:         u32 = 10;
pub const NFT_META_SKGID:         u32 = 11;
pub const NFT_META_NFTRACE:       u32 = 12;
pub const NFT_META_RTCLASSID:     u32 = 13;
pub const NFT_META_SECMARK:       u32 = 14;
pub const NFT_META_NFPROTO:       u32 = 15;
pub const NFT_META_L4PROTO:       u32 = 16;
pub const NFT_META_BRI_IIFNAME:   u32 = 17;
pub const NFT_META_BRI_OIFNAME:   u32 = 18;
pub const NFT_META_PKTTYPE:       u32 = 19;
pub const NFT_META_CPU:           u32 = 20;
pub const NFT_META_IIFGROUP:      u32 = 21;
pub const NFT_META_OIFGROUP:      u32 = 22;
pub const NFT_META_CGROUP:        u32 = 23;
pub const NFT_META_PRANDOM:       u32 = 24;
pub const NFT_META_SECPATH:       u32 = 25;
pub const NFT_META_IIFKIND:       u32 = 26;
pub const NFT_META_OIFKIND:       u32 = 27;
pub const NFT_META_BRI_IIFPVID:   u32 = 28;
pub const NFT_META_BRI_IIFVPROTO: u32 = 29;
pub const NFT_META_TIME_NS:       u32 = 30;
pub const NFT_META_TIME_DAY:      u32 = 31;
pub const NFT_META_TIME_HOUR:     u32 = 32;
pub const NFT_META_SDIF:          u32 = 33;
pub const NFT_META_SDIFNAME:      u32 = 34;
pub const NFT_META_BRI_BROUTE:    u32 = 35;
pub const NFT_META_BRI_IIFHWADDR: u32 = 37;

// --- ct keys ---

pub const NFT_CT_STATE:       u32 = 0;
pub const NFT_CT_DIRECTION:   u32 = 1;
pub const NFT_CT_STATUS:      u32 = 2;
pub const NFT_CT_MARK:        u32 = 3;
pub const NFT_CT_SECMARK:     u32 = 4;
pub const NFT_CT_EXPIRATION:  u32 = 5;
pub const NFT_CT_HELPER:      u32 = 6;
pub const NFT_CT_L3PROTOCOL:  u32 = 7;
pub const NFT_CT_SRC:         u32 = 8;
pub const NFT_CT_DST:         u32 = 9;
pub const NFT_CT_PROTOCOL:    u32 = 10;
pub const NFT_CT_PROTO_SRC:   u32 = 11;
pub const NFT_CT_PROTO_DST:   u32 = 12;
pub const NFT_CT_LABELS:      u32 = 13;
pub const NFT_CT_PKTS:        u32 = 14;
pub const NFT_CT_BYTES:       u32 = 15;
pub const NFT_CT_AVGPKT:      u32 = 16;
pub const NFT_CT_ZONE:        u32 = 17;
pub const NFT_CT_EVENTMASK:   u32 = 18;
pub const NFT_CT_SRC_IP:      u32 = 19;
pub const NFT_CT_DST_IP:      u32 = 20;
pub const NFT_CT_SRC_IP6:     u32 = 21;
pub const NFT_CT_DST_IP6:     u32 = 22;
pub const NFT_CT_ID:          u32 = 23;
pub const NFT_CT_MAX:         u32 = 23;

/// Conntrack state bits the `state` key writes — one bit per conntrack-info
/// class plus the two synthetic classes for packets carrying no entry.
pub const NF_CT_STATE_INVALID_BIT:   u32 = 1;
pub const NF_CT_STATE_UNTRACKED_BIT: u32 = 1 << 6;

// --- nat / reject / queue / hash / numgen types ---

pub const NFT_NAT_SNAT: u32 = 0;
pub const NFT_NAT_DNAT: u32 = 1;

pub const NFT_REJECT_ICMP_UNREACH:  u32 = 0;
pub const NFT_REJECT_TCP_RST:       u32 = 1;
pub const NFT_REJECT_ICMPX_UNREACH: u32 = 2;

pub const NFT_REJECT_ICMPX_NO_ROUTE:         u8 = 0;
pub const NFT_REJECT_ICMPX_PORT_UNREACH:     u8 = 1;
pub const NFT_REJECT_ICMPX_HOST_UNREACH:     u8 = 2;
pub const NFT_REJECT_ICMPX_ADMIN_PROHIBITED: u8 = 3;
pub const NFT_REJECT_ICMPX_MAX:              u8 = 3;

pub const NFT_HASH_JENKINS: u32 = 0;
pub const NFT_HASH_SYM:     u32 = 1;

pub const NFT_NG_INCREMENTAL: u32 = 0;
pub const NFT_NG_RANDOM:      u32 = 1;

pub const NFT_LIMIT_PKTS:      u32 = 0;
pub const NFT_LIMIT_PKT_BYTES: u32 = 1;

// --- exthdr / rt / fib / socket / xfrm / tunnel ---

pub const NFT_EXTHDR_OP_IPV6:   u32 = 0;
pub const NFT_EXTHDR_OP_TCPOPT: u32 = 1;
pub const NFT_EXTHDR_OP_IPV4:   u32 = 2;
pub const NFT_EXTHDR_OP_SCTP:   u32 = 3;
pub const NFT_EXTHDR_OP_DCCP:   u32 = 4;
pub const NFT_EXTHDR_OP_MAX:    u32 = 4;

pub const NFT_RT_CLASSID:  u32 = 0;
pub const NFT_RT_NEXTHOP4: u32 = 1;
pub const NFT_RT_NEXTHOP6: u32 = 2;
pub const NFT_RT_TCPMSS:   u32 = 3;
pub const NFT_RT_XFRM:     u32 = 4;

pub const NFT_FIB_RESULT_UNSPEC:   u32 = 0;
pub const NFT_FIB_RESULT_OIF:      u32 = 1;
pub const NFT_FIB_RESULT_OIFNAME:  u32 = 2;
pub const NFT_FIB_RESULT_ADDRTYPE: u32 = 3;

pub const NFT_SOCKET_TRANSPARENT: u32 = 0;
pub const NFT_SOCKET_MARK:        u32 = 1;
pub const NFT_SOCKET_WILDCARD:    u32 = 2;
pub const NFT_SOCKET_CGROUPV2:    u32 = 3;

pub const NFT_XFRM_KEY_UNSPEC:    u32 = 0;
pub const NFT_XFRM_KEY_DADDR_IP4: u32 = 1;
pub const NFT_XFRM_KEY_DADDR_IP6: u32 = 2;
pub const NFT_XFRM_KEY_SADDR_IP4: u32 = 3;
pub const NFT_XFRM_KEY_SADDR_IP6: u32 = 4;
pub const NFT_XFRM_KEY_REQID:     u32 = 5;
pub const NFT_XFRM_KEY_SPI:       u32 = 6;

pub const XFRM_POLICY_IN:  u32 = 0;
pub const XFRM_POLICY_OUT: u32 = 1;

pub const NFT_TUNNEL_PATH: u32 = 0;
pub const NFT_TUNNEL_ID:   u32 = 1;

pub const NFT_TUNNEL_MODE_NONE: u32 = 0;
pub const NFT_TUNNEL_MODE_RX:   u32 = 1;
pub const NFT_TUNNEL_MODE_TX:   u32 = 2;
pub const NFT_TUNNEL_MODE_MAX:  u32 = 2;

// --- object types an objref may reference ---

pub const NFT_OBJECT_COUNTER:   u32 = 1;
pub const NFT_OBJECT_QUOTA:     u32 = 2;
pub const NFT_OBJECT_CT_HELPER: u32 = 3;
pub const NFT_OBJECT_LIMIT:     u32 = 4;
pub const NFT_OBJECT_CONNLIMIT: u32 = 5;
pub const NFT_OBJECT_TUNNEL:    u32 = 6;
pub const NFT_OBJECT_CT_TIMEOUT: u32 = 7;
pub const NFT_OBJECT_SECMARK:   u32 = 8;
pub const NFT_OBJECT_CT_EXPECT: u32 = 9;
pub const NFT_OBJECT_SYNPROXY:  u32 = 10;
