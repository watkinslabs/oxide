//! Connection-tracking ABI numbers. Status bits, conntrack-info values,
//! direction indices, and the L4 protocol numbers the trackers key on.
//! Values are the Linux UAPI ones; nothing here is policy.

// --- direction ---

/// Packet flows the way the connection was opened.
pub const IP_CT_DIR_ORIGINAL: u8 = 0;
/// Packet flows the other way.
pub const IP_CT_DIR_REPLY:    u8 = 1;
pub const IP_CT_DIR_MAX:      usize = 2;

// --- conntrack info (skb->nfctinfo) ---

pub const IP_CT_ESTABLISHED:       u8 = 0;
pub const IP_CT_RELATED:           u8 = 1;
pub const IP_CT_NEW:               u8 = 2;
pub const IP_CT_IS_REPLY:          u8 = 3;
pub const IP_CT_ESTABLISHED_REPLY: u8 = IP_CT_ESTABLISHED + IP_CT_IS_REPLY;
pub const IP_CT_RELATED_REPLY:     u8 = IP_CT_RELATED + IP_CT_IS_REPLY;
pub const IP_CT_UNTRACKED:         u8 = 7;

/// Direction implied by a conntrack-info value — Linux `CTINFO2DIR`.
/// # C: O(1)
pub const fn ctinfo2dir(ctinfo: u8) -> u8 {
    if ctinfo >= IP_CT_IS_REPLY { IP_CT_DIR_REPLY } else { IP_CT_DIR_ORIGINAL }
}

// --- status bits (IPS_*) ---

pub const IPS_EXPECTED_BIT:      u32 = 0;
pub const IPS_EXPECTED:          u32 = 1 << IPS_EXPECTED_BIT;
pub const IPS_SEEN_REPLY_BIT:    u32 = 1;
pub const IPS_SEEN_REPLY:        u32 = 1 << IPS_SEEN_REPLY_BIT;
pub const IPS_ASSURED_BIT:       u32 = 2;
pub const IPS_ASSURED:           u32 = 1 << IPS_ASSURED_BIT;
pub const IPS_CONFIRMED_BIT:     u32 = 3;
pub const IPS_CONFIRMED:         u32 = 1 << IPS_CONFIRMED_BIT;
pub const IPS_SRC_NAT_BIT:       u32 = 4;
pub const IPS_SRC_NAT:           u32 = 1 << IPS_SRC_NAT_BIT;
pub const IPS_DST_NAT_BIT:       u32 = 5;
pub const IPS_DST_NAT:           u32 = 1 << IPS_DST_NAT_BIT;
pub const IPS_NAT_MASK:          u32 = IPS_SRC_NAT | IPS_DST_NAT;
pub const IPS_SEQ_ADJUST_BIT:    u32 = 6;
pub const IPS_SEQ_ADJUST:        u32 = 1 << IPS_SEQ_ADJUST_BIT;
pub const IPS_SRC_NAT_DONE_BIT:  u32 = 7;
pub const IPS_SRC_NAT_DONE:      u32 = 1 << IPS_SRC_NAT_DONE_BIT;
pub const IPS_DST_NAT_DONE_BIT:  u32 = 8;
pub const IPS_DST_NAT_DONE:      u32 = 1 << IPS_DST_NAT_DONE_BIT;
pub const IPS_NAT_DONE_MASK:     u32 = IPS_SRC_NAT_DONE | IPS_DST_NAT_DONE;
pub const IPS_DYING_BIT:         u32 = 9;
pub const IPS_DYING:             u32 = 1 << IPS_DYING_BIT;
pub const IPS_FIXED_TIMEOUT_BIT: u32 = 10;
pub const IPS_FIXED_TIMEOUT:     u32 = 1 << IPS_FIXED_TIMEOUT_BIT;
pub const IPS_TEMPLATE_BIT:      u32 = 11;
pub const IPS_TEMPLATE:          u32 = 1 << IPS_TEMPLATE_BIT;
pub const IPS_UNTRACKED_BIT:     u32 = 12;
pub const IPS_UNTRACKED:         u32 = 1 << IPS_UNTRACKED_BIT;
pub const IPS_HELPER_BIT:        u32 = 13;
pub const IPS_HELPER:            u32 = 1 << IPS_HELPER_BIT;
pub const IPS_OFFLOAD_BIT:       u32 = 14;
pub const IPS_OFFLOAD:           u32 = 1 << IPS_OFFLOAD_BIT;
pub const IPS_HW_OFFLOAD_BIT:    u32 = 15;
pub const IPS_HW_OFFLOAD:        u32 = 1 << IPS_HW_OFFLOAD_BIT;

/// Bits userspace may never set through ctnetlink — Linux `IPS_UNCHANGEABLE_MASK`.
pub const IPS_UNCHANGEABLE_MASK: u32 = IPS_NAT_DONE_MASK | IPS_NAT_MASK
    | IPS_EXPECTED | IPS_CONFIRMED | IPS_DYING | IPS_SEQ_ADJUST
    | IPS_TEMPLATE | IPS_UNTRACKED | IPS_OFFLOAD | IPS_HW_OFFLOAD;

// --- verdicts returned by a tracker ---

pub const NF_DROP:   i32 = 0;
pub const NF_ACCEPT: i32 = 1;
pub const NF_STOLEN:  i32 = 2;
pub const NF_QUEUE:   i32 = 3;
pub const NF_REPEAT:  i32 = 4;

// --- L4 protocol numbers the trackers key on ---

pub const IPPROTO_ICMP:   u8 = 1;
pub const IPPROTO_TCP:    u8 = 6;
pub const IPPROTO_UDP:    u8 = 17;
pub const IPPROTO_GRE:    u8 = 47;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const IPPROTO_SCTP:   u8 = 132;
pub const IPPROTO_UDPLITE: u8 = 136;

// --- L3 families ---

pub const NFPROTO_IPV4: u8 = 2;
pub const NFPROTO_IPV6: u8 = 10;

// --- event bits (`IPCT_*`, ctnetlink event cache) ---

pub const IPCT_NEW:        u32 = 1 << 0;
pub const IPCT_RELATED:    u32 = 1 << 1;
pub const IPCT_DESTROY:    u32 = 1 << 2;
pub const IPCT_REPLY:      u32 = 1 << 3;
pub const IPCT_ASSURED:    u32 = 1 << 4;
pub const IPCT_PROTOINFO:  u32 = 1 << 5;
pub const IPCT_HELPER:     u32 = 1 << 6;
pub const IPCT_MARK:       u32 = 1 << 7;
pub const IPCT_SEQADJ:     u32 = 1 << 8;
pub const IPCT_SECMARK:    u32 = 1 << 9;
pub const IPCT_LABEL:      u32 = 1 << 10;
pub const IPCT_SYNPROXY:   u32 = 1 << 11;

/// Expectation-event bits.
pub const IPEXP_NEW:     u32 = 1 << 0;
pub const IPEXP_DESTROY: u32 = 1 << 1;

// --- ctnetlink message types (NFNL_SUBSYS_CTNETLINK) ---

pub const IPCTNL_MSG_CT_NEW:          u8 = 0;
pub const IPCTNL_MSG_CT_GET:          u8 = 1;
pub const IPCTNL_MSG_CT_DELETE:       u8 = 2;
pub const IPCTNL_MSG_CT_GET_CTRZERO:  u8 = 3;
pub const IPCTNL_MSG_CT_GET_STATS_CPU: u8 = 4;
pub const IPCTNL_MSG_CT_GET_STATS:    u8 = 5;
pub const IPCTNL_MSG_CT_GET_DYING:    u8 = 6;
pub const IPCTNL_MSG_CT_GET_UNCONFIRMED: u8 = 7;

// --- ctnetlink attributes (CTA_*) ---

pub const CTA_TUPLE_ORIG:   u16 = 1;
pub const CTA_TUPLE_REPLY:  u16 = 2;
pub const CTA_STATUS:       u16 = 3;
pub const CTA_PROTOINFO:    u16 = 4;
pub const CTA_HELP:         u16 = 5;
pub const CTA_NAT_SRC:      u16 = 6;
pub const CTA_TIMEOUT:      u16 = 7;
pub const CTA_MARK:         u16 = 8;
pub const CTA_COUNTERS_ORIG: u16 = 9;
pub const CTA_COUNTERS_REPLY: u16 = 10;
pub const CTA_USE:          u16 = 11;
pub const CTA_ID:           u16 = 12;
pub const CTA_NAT_DST:      u16 = 13;
pub const CTA_ZONE:         u16 = 18;
pub const CTA_MARK_MASK:    u16 = 21;
pub const CTA_STATUS_MASK:  u16 = 26;

pub const CTA_TUPLE_IP:     u16 = 1;
pub const CTA_TUPLE_PROTO:  u16 = 2;

pub const CTA_IP_V4_SRC:    u16 = 1;
pub const CTA_IP_V4_DST:    u16 = 2;
pub const CTA_IP_V6_SRC:    u16 = 3;
pub const CTA_IP_V6_DST:    u16 = 4;

pub const CTA_PROTO_NUM:        u16 = 1;
pub const CTA_PROTO_SRC_PORT:   u16 = 2;
pub const CTA_PROTO_DST_PORT:   u16 = 3;
pub const CTA_PROTO_ICMP_ID:    u16 = 4;
pub const CTA_PROTO_ICMP_TYPE:  u16 = 5;
pub const CTA_PROTO_ICMP_CODE:  u16 = 6;
pub const CTA_PROTO_ICMPV6_ID:   u16 = 7;
pub const CTA_PROTO_ICMPV6_TYPE: u16 = 8;
pub const CTA_PROTO_ICMPV6_CODE: u16 = 9;

pub const CTA_PROTOINFO_TCP:            u16 = 1;
pub const CTA_PROTOINFO_TCP_STATE:      u16 = 1;
pub const CTA_PROTOINFO_TCP_WSCALE_ORIGINAL: u16 = 2;
pub const CTA_PROTOINFO_TCP_WSCALE_REPLY:    u16 = 3;
pub const CTA_PROTOINFO_TCP_FLAGS_ORIGINAL:  u16 = 4;
pub const CTA_PROTOINFO_TCP_FLAGS_REPLY:     u16 = 5;

pub const CTA_COUNTERS_PACKETS: u16 = 1;
pub const CTA_COUNTERS_BYTES:   u16 = 2;
