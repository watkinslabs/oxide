//! NAT ABI numbers: range flags, manipulation types, and the hook priorities
//! that make destination translation happen before filtering and source
//! translation after it.

/// Rewrite the address, not just the port.
pub const NF_NAT_RANGE_MAP_IPS:            u32 = 1 << 0;
/// The port/id range in the request is meaningful.
pub const NF_NAT_RANGE_PROTO_SPECIFIED:    u32 = 1 << 1;
/// Start the port search from a random offset.
pub const NF_NAT_RANGE_PROTO_RANDOM:       u32 = 1 << 2;
/// Choose the mapped address from the source alone, so one client always maps
/// to one address regardless of where it is talking to.
pub const NF_NAT_RANGE_PERSISTENT:         u32 = 1 << 3;
/// Fully randomise the port, refusing even to reuse a prior mapping.
pub const NF_NAT_RANGE_PROTO_RANDOM_FULLY: u32 = 1 << 4;
/// Offset the port by a fixed base rather than searching.
pub const NF_NAT_RANGE_PROTO_OFFSET:       u32 = 1 << 5;
/// Map the whole prefix one-to-one instead of onto a single address.
pub const NF_NAT_RANGE_NETMAP:             u32 = 1 << 6;

pub const NF_NAT_RANGE_PROTO_RANDOM_ALL: u32 =
    NF_NAT_RANGE_PROTO_RANDOM | NF_NAT_RANGE_PROTO_RANDOM_FULLY;

pub const NF_NAT_RANGE_MASK: u32 = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED
    | NF_NAT_RANGE_PROTO_RANDOM | NF_NAT_RANGE_PERSISTENT
    | NF_NAT_RANGE_PROTO_RANDOM_FULLY | NF_NAT_RANGE_PROTO_OFFSET | NF_NAT_RANGE_NETMAP;

/// Which end of the tuple a binding rewrites.
pub const NF_NAT_MANIP_SRC: u8 = 0;
pub const NF_NAT_MANIP_DST: u8 = 1;

// Netfilter inet hook numbers.
pub const NF_INET_PRE_ROUTING:  u8 = 0;
pub const NF_INET_LOCAL_IN:     u8 = 1;
pub const NF_INET_FORWARD:      u8 = 2;
pub const NF_INET_LOCAL_OUT:    u8 = 3;
pub const NF_INET_POST_ROUTING: u8 = 4;

/// Destination translation runs early so packet filters see the real target.
pub const NF_IP_PRI_NAT_DST: i32 = -100;
/// Source translation runs late so filtering decisions are made on the real
/// source.
pub const NF_IP_PRI_NAT_SRC: i32 = 100;

/// Manipulation a hook performs. Post-routing and local-in rewrite the source;
/// every other hook rewrites the destination.
/// # C: O(1)
pub const fn hook_to_manip(hook: u8) -> u8 {
    if hook == NF_INET_POST_ROUTING || hook == NF_INET_LOCAL_IN {
        NF_NAT_MANIP_SRC
    } else {
        NF_NAT_MANIP_DST
    }
}

/// Priority a NAT hook registers at for one manipulation. # C: O(1)
pub const fn hook_priority(manip: u8) -> i32 {
    if manip == NF_NAT_MANIP_SRC { NF_IP_PRI_NAT_SRC } else { NF_IP_PRI_NAT_DST }
}
