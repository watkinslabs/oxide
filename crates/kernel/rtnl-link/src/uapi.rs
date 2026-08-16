//! Link-message ABI numbers this crate reads. The kind-specific numbers below
//! `IFLA_INFO_DATA` belong to the kind, not here.

/// Outer link attributes.
pub const IFLA_UNSPEC:   u16 = 0;
pub const IFLA_ADDRESS:  u16 = 1;
pub const IFLA_IFNAME:   u16 = 3;
pub const IFLA_MTU:      u16 = 4;
pub const IFLA_LINK:     u16 = 5;
pub const IFLA_MASTER:   u16 = 10;
pub const IFLA_LINKINFO: u16 = 18;
pub const IFLA_NET_NS_PID: u16 = 19;
pub const IFLA_IFALIAS:  u16 = 20;
pub const IFLA_NET_NS_FD: u16 = 28;
pub const IFLA_GROUP:    u16 = 27;

/// Nested attributes inside `IFLA_LINKINFO`.
pub const IFLA_INFO_UNSPEC:    u16 = 0;
pub const IFLA_INFO_KIND:      u16 = 1;
pub const IFLA_INFO_DATA:      u16 = 2;
pub const IFLA_INFO_XSTATS:    u16 = 3;
pub const IFLA_INFO_SLAVE_KIND: u16 = 4;
pub const IFLA_INFO_SLAVE_DATA: u16 = 5;
pub const IFLA_INFO_MAX:       u16 = 5;

/// Netlink attribute header geometry.
pub const NLA_HDR_LEN:  usize = 4;
pub const NLA_ALIGNTO:  usize = 4;
pub const NLA_F_NESTED: u16 = 1 << 15;
pub const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
/// Bits that are flags, not part of the attribute number.
pub const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

/// Longest kind string a link type may register.
pub const MODULE_NAME_LEN: usize = 16;

/// Longest interface name, including the terminator.
pub const IFNAMSIZ: usize = 16;

/// `struct ifinfomsg` field offsets from the start of the message body.
pub const IFI_FAMILY_OFF: usize = 0;
pub const IFI_TYPE_OFF:   usize = 2;
pub const IFI_INDEX_OFF:  usize = 4;
pub const IFI_FLAGS_OFF:  usize = 8;
pub const IFI_CHANGE_OFF: usize = 12;
pub const IFINFOMSG_LEN:  usize = 16;
