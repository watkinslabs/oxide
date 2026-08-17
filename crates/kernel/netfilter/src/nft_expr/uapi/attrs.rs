//! nftables per-expression netlink attribute numbers. One block per
//! expression, each ending in the `_MAX` the reference policy bounds on.

// --- expression envelope ---

pub const NFTA_LIST_ELEM: u16 = 1;

pub const NFTA_EXPR_NAME: u16 = 1;
pub const NFTA_EXPR_DATA: u16 = 2;

pub const NFTA_DATA_VALUE:   u16 = 1;
pub const NFTA_DATA_VERDICT: u16 = 2;

pub const NFTA_VERDICT_CODE:  u16 = 1;
pub const NFTA_VERDICT_CHAIN: u16 = 2;

// --- payload ---

pub const NFTA_PAYLOAD_DREG:        u16 = 1;
pub const NFTA_PAYLOAD_BASE:        u16 = 2;
pub const NFTA_PAYLOAD_OFFSET:      u16 = 3;
pub const NFTA_PAYLOAD_LEN:         u16 = 4;
pub const NFTA_PAYLOAD_SREG:        u16 = 5;
pub const NFTA_PAYLOAD_CSUM_TYPE:   u16 = 6;
pub const NFTA_PAYLOAD_CSUM_OFFSET: u16 = 7;
pub const NFTA_PAYLOAD_CSUM_FLAGS:  u16 = 8;
pub const NFTA_PAYLOAD_MAX:         u16 = 8;

// --- cmp / immediate / bitwise / byteorder ---

pub const NFTA_CMP_SREG: u16 = 1;
pub const NFTA_CMP_OP:   u16 = 2;
pub const NFTA_CMP_DATA: u16 = 3;
pub const NFTA_CMP_MAX:  u16 = 3;

pub const NFTA_IMMEDIATE_DREG: u16 = 1;
pub const NFTA_IMMEDIATE_DATA: u16 = 2;
pub const NFTA_IMMEDIATE_MAX:  u16 = 2;

pub const NFTA_BITWISE_SREG: u16 = 1;
pub const NFTA_BITWISE_DREG: u16 = 2;
pub const NFTA_BITWISE_LEN:  u16 = 3;
pub const NFTA_BITWISE_MASK: u16 = 4;
pub const NFTA_BITWISE_XOR:  u16 = 5;
pub const NFTA_BITWISE_MAX:  u16 = 5;

pub const NFTA_BYTEORDER_SREG: u16 = 1;
pub const NFTA_BYTEORDER_DREG: u16 = 2;
pub const NFTA_BYTEORDER_OP:   u16 = 3;
pub const NFTA_BYTEORDER_LEN:  u16 = 4;
pub const NFTA_BYTEORDER_SIZE: u16 = 5;
pub const NFTA_BYTEORDER_MAX:  u16 = 5;

// --- counter / lookup / meta ---

pub const NFTA_COUNTER_BYTES:   u16 = 1;
pub const NFTA_COUNTER_PACKETS: u16 = 2;
pub const NFTA_COUNTER_MAX:     u16 = 2;

pub const NFTA_LOOKUP_SET:   u16 = 1;
pub const NFTA_LOOKUP_SREG:  u16 = 2;
pub const NFTA_LOOKUP_DREG:  u16 = 3;
pub const NFTA_LOOKUP_FLAGS: u16 = 4;
pub const NFTA_LOOKUP_MAX:   u16 = 4;

pub const NFTA_META_DREG: u16 = 1;
pub const NFTA_META_KEY:  u16 = 2;
pub const NFTA_META_SREG: u16 = 3;
pub const NFTA_META_MAX:  u16 = 3;

// --- ct ---

pub const NFTA_CT_DREG:      u16 = 1;
pub const NFTA_CT_KEY:       u16 = 2;
pub const NFTA_CT_DIRECTION: u16 = 3;
pub const NFTA_CT_SREG:      u16 = 4;
pub const NFTA_CT_MAX:       u16 = 4;

// --- nat / masq / redir ---

pub const NFTA_NAT_TYPE:           u16 = 1;
pub const NFTA_NAT_FAMILY:         u16 = 2;
pub const NFTA_NAT_REG_ADDR_MIN:   u16 = 3;
pub const NFTA_NAT_REG_ADDR_MAX:   u16 = 4;
pub const NFTA_NAT_REG_PROTO_MIN:  u16 = 5;
pub const NFTA_NAT_REG_PROTO_MAX:  u16 = 6;
pub const NFTA_NAT_FLAGS:          u16 = 7;
pub const NFTA_NAT_MAX:            u16 = 7;

pub const NFTA_MASQ_FLAGS:          u16 = 1;
pub const NFTA_MASQ_REG_PROTO_MIN:  u16 = 2;
pub const NFTA_MASQ_REG_PROTO_MAX:  u16 = 3;
pub const NFTA_MASQ_MAX:            u16 = 3;

pub const NFTA_REDIR_REG_PROTO_MIN: u16 = 1;
pub const NFTA_REDIR_REG_PROTO_MAX: u16 = 2;
pub const NFTA_REDIR_FLAGS:         u16 = 3;
pub const NFTA_REDIR_MAX:           u16 = 3;

// --- dup / fwd ---

pub const NFTA_DUP_SREG_ADDR: u16 = 1;
pub const NFTA_DUP_SREG_DEV:  u16 = 2;
pub const NFTA_DUP_MAX:       u16 = 2;

pub const NFTA_FWD_SREG_DEV:  u16 = 1;
pub const NFTA_FWD_SREG_ADDR: u16 = 2;
pub const NFTA_FWD_NFPROTO:   u16 = 3;
pub const NFTA_FWD_MAX:       u16 = 3;

// --- limit / log / queue / quota ---

pub const NFTA_LIMIT_RATE:  u16 = 1;
pub const NFTA_LIMIT_UNIT:  u16 = 2;
pub const NFTA_LIMIT_BURST: u16 = 3;
pub const NFTA_LIMIT_TYPE:  u16 = 4;
pub const NFTA_LIMIT_FLAGS: u16 = 5;
pub const NFTA_LIMIT_PAD:   u16 = 6;
pub const NFTA_LIMIT_MAX:   u16 = 6;

pub const NFTA_LOG_GROUP:      u16 = 1;
pub const NFTA_LOG_PREFIX:     u16 = 2;
pub const NFTA_LOG_SNAPLEN:    u16 = 3;
pub const NFTA_LOG_QTHRESHOLD: u16 = 4;
pub const NFTA_LOG_LEVEL:      u16 = 5;
pub const NFTA_LOG_FLAGS:      u16 = 6;
pub const NFTA_LOG_MAX:        u16 = 6;

pub const NFTA_QUEUE_NUM:       u16 = 1;
pub const NFTA_QUEUE_TOTAL:     u16 = 2;
pub const NFTA_QUEUE_FLAGS:     u16 = 3;
pub const NFTA_QUEUE_SREG_QNUM: u16 = 4;
pub const NFTA_QUEUE_MAX:       u16 = 4;

pub const NFTA_QUOTA_BYTES:    u16 = 1;
pub const NFTA_QUOTA_FLAGS:    u16 = 2;
pub const NFTA_QUOTA_PAD:      u16 = 3;
pub const NFTA_QUOTA_CONSUMED: u16 = 4;
pub const NFTA_QUOTA_MAX:      u16 = 4;

// --- reject / hash / numgen / range / objref ---

pub const NFTA_REJECT_TYPE:      u16 = 1;
pub const NFTA_REJECT_ICMP_CODE: u16 = 2;
pub const NFTA_REJECT_MAX:       u16 = 2;

pub const NFTA_HASH_SREG:    u16 = 1;
pub const NFTA_HASH_DREG:    u16 = 2;
pub const NFTA_HASH_LEN:     u16 = 3;
pub const NFTA_HASH_MODULUS: u16 = 4;
pub const NFTA_HASH_SEED:    u16 = 5;
pub const NFTA_HASH_OFFSET:  u16 = 6;
pub const NFTA_HASH_TYPE:    u16 = 7;
pub const NFTA_HASH_SET_NAME: u16 = 8;
pub const NFTA_HASH_SET_ID:  u16 = 9;
pub const NFTA_HASH_MAX:     u16 = 9;

pub const NFTA_NG_DREG:    u16 = 1;
pub const NFTA_NG_MODULUS: u16 = 2;
pub const NFTA_NG_TYPE:    u16 = 3;
pub const NFTA_NG_OFFSET:  u16 = 4;
pub const NFTA_NG_SET_NAME: u16 = 5;
pub const NFTA_NG_SET_ID:  u16 = 6;
pub const NFTA_NG_MAX:     u16 = 6;

pub const NFTA_RANGE_SREG:      u16 = 1;
pub const NFTA_RANGE_OP:        u16 = 2;
pub const NFTA_RANGE_FROM_DATA: u16 = 3;
pub const NFTA_RANGE_TO_DATA:   u16 = 4;
pub const NFTA_RANGE_MAX:       u16 = 4;

pub const NFTA_OBJREF_IMM_TYPE: u16 = 1;
pub const NFTA_OBJREF_IMM_NAME: u16 = 2;
pub const NFTA_OBJREF_SET_SREG: u16 = 3;
pub const NFTA_OBJREF_SET_NAME: u16 = 4;
pub const NFTA_OBJREF_SET_ID:   u16 = 5;
pub const NFTA_OBJREF_MAX:      u16 = 5;

// --- exthdr / rt / fib / socket / osf ---

pub const NFTA_EXTHDR_DREG:   u16 = 1;
pub const NFTA_EXTHDR_TYPE:   u16 = 2;
pub const NFTA_EXTHDR_OFFSET: u16 = 3;
pub const NFTA_EXTHDR_LEN:    u16 = 4;
pub const NFTA_EXTHDR_FLAGS:  u16 = 5;
pub const NFTA_EXTHDR_OP:     u16 = 6;
pub const NFTA_EXTHDR_SREG:   u16 = 7;
pub const NFTA_EXTHDR_MAX:    u16 = 7;

pub const NFTA_RT_DREG: u16 = 1;
pub const NFTA_RT_KEY:  u16 = 2;
pub const NFTA_RT_MAX:  u16 = 2;

pub const NFTA_FIB_DREG:   u16 = 1;
pub const NFTA_FIB_RESULT: u16 = 2;
pub const NFTA_FIB_FLAGS:  u16 = 3;
pub const NFTA_FIB_MAX:    u16 = 3;

pub const NFTA_SOCKET_KEY:   u16 = 1;
pub const NFTA_SOCKET_DREG:  u16 = 2;
pub const NFTA_SOCKET_LEVEL: u16 = 3;
pub const NFTA_SOCKET_MAX:   u16 = 3;

pub const NFTA_OSF_DREG:  u16 = 1;
pub const NFTA_OSF_TTL:   u16 = 2;
pub const NFTA_OSF_FLAGS: u16 = 3;
pub const NFTA_OSF_MAX:   u16 = 3;

// --- tproxy / synproxy / connlimit / flow_offload / xfrm / last / tunnel ---

pub const NFTA_TPROXY_FAMILY:   u16 = 1;
pub const NFTA_TPROXY_REG_ADDR: u16 = 2;
pub const NFTA_TPROXY_REG_PORT: u16 = 3;
pub const NFTA_TPROXY_MAX:      u16 = 3;

pub const NFTA_SYNPROXY_MSS:    u16 = 1;
pub const NFTA_SYNPROXY_WSCALE: u16 = 2;
pub const NFTA_SYNPROXY_FLAGS:  u16 = 3;
pub const NFTA_SYNPROXY_MAX:    u16 = 3;

pub const NFTA_CONNLIMIT_COUNT: u16 = 1;
pub const NFTA_CONNLIMIT_FLAGS: u16 = 2;
pub const NFTA_CONNLIMIT_MAX:   u16 = 2;

pub const NFTA_FLOW_TABLE_NAME: u16 = 1;
pub const NFTA_FLOW_MAX:        u16 = 1;

pub const NFTA_XFRM_DREG:  u16 = 1;
pub const NFTA_XFRM_KEY:   u16 = 2;
pub const NFTA_XFRM_DIR:   u16 = 3;
pub const NFTA_XFRM_SPNUM: u16 = 4;
pub const NFTA_XFRM_MAX:   u16 = 4;

pub const NFTA_LAST_SET:   u16 = 1;
pub const NFTA_LAST_MSECS: u16 = 2;
pub const NFTA_LAST_PAD:   u16 = 3;
pub const NFTA_LAST_MAX:   u16 = 3;

pub const NFTA_TUNNEL_KEY:  u16 = 1;
pub const NFTA_TUNNEL_DREG: u16 = 2;
pub const NFTA_TUNNEL_MODE: u16 = 3;
pub const NFTA_TUNNEL_MAX:  u16 = 3;
