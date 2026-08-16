// 802.1Q / 802.1ad wire numbers and the rtnetlink `vlan` link-kind ABI.
// Numbers only: dispatch, validation and state live in the sibling modules.

/// Customer VLAN tag protocol identifier (802.1Q).
pub const ETH_P_8021Q: u16 = 0x8100;
/// Service VLAN tag protocol identifier (802.1ad, "QinQ" outer tag).
pub const ETH_P_8021AD: u16 = 0x88a8;

/// Bytes a tag adds to a frame: 2 TPID + 2 TCI. The TPID overwrites nothing —
/// the encapsulated ethertype moves 4 bytes further out.
pub const VLAN_HLEN: usize = 4;
/// Untagged Ethernet header width.
pub const ETH_HLEN: usize = 14;
/// Ethernet address width.
pub const ETH_ALEN: usize = 6;
/// Tagged Ethernet header width (`ETH_HLEN` + `VLAN_HLEN`).
pub const VLAN_ETH_HLEN: usize = 18;
/// Minimum tagged frame on the wire, excluding FCS.
pub const VLAN_ETH_ZLEN: usize = 64;
/// Largest payload a tagged frame carries at the default MTU.
pub const VLAN_ETH_DATA_LEN: usize = 1500;
/// Largest tagged frame at the default MTU, excluding FCS.
pub const VLAN_ETH_FRAME_LEN: usize = 1518;

/// One past the highest representable VLAN identifier.
pub const VLAN_N_VID: u16 = 4096;
/// TCI bits 0..11 — the VLAN identifier. Also the first RESERVED id: an
/// interface may not be created with this value.
pub const VLAN_VID_MASK: u16 = 0x0fff;
/// TCI bits 13..15 — the priority code point, in place.
pub const VLAN_PRIO_MASK: u16 = 0xe000;
/// Distance the priority code point sits above bit 0.
pub const VLAN_PRIO_SHIFT: u32 = 13;
/// TCI bit 12 — drop eligible / canonical format indicator.
pub const VLAN_CFI_MASK: u16 = 0x1000;
/// One past the highest priority code point.
pub const VLAN_N_PRIO: u32 = 8;

/// Link kind string carried in the rtnetlink `IFLA_INFO_KIND` attribute.
pub const VLAN_LINK_KIND: &str = "vlan";

/// Nested attribute numbers under `IFLA_INFO_DATA` for the `vlan` link kind.
pub const IFLA_VLAN_UNSPEC: u16 = 0;
pub const IFLA_VLAN_ID: u16 = 1;
pub const IFLA_VLAN_FLAGS: u16 = 2;
pub const IFLA_VLAN_EGRESS_QOS: u16 = 3;
pub const IFLA_VLAN_INGRESS_QOS: u16 = 4;
pub const IFLA_VLAN_PROTOCOL: u16 = 5;
/// Highest attribute number the kind understands. Higher numbers are ignored.
pub const IFLA_VLAN_MAX: u16 = 5;

/// Attribute numbers nested inside an ingress or egress QoS map.
pub const IFLA_VLAN_QOS_UNSPEC: u16 = 0;
pub const IFLA_VLAN_QOS_MAPPING: u16 = 1;
pub const IFLA_VLAN_QOS_MAX: u16 = 1;

/// `struct ifla_vlan_flags { u32 flags; u32 mask; }`.
pub const IFLA_VLAN_FLAGS_LEN: usize = 8;
/// `struct ifla_vlan_qos_mapping { u32 from; u32 to; }`.
pub const IFLA_VLAN_QOS_MAPPING_LEN: usize = 8;
/// Payload width of a `u16` attribute.
pub const NLA_U16_LEN: usize = 2;

/// Outer `IFLA_*` attribute numbers this kind reads from the link message.
pub const IFLA_ADDRESS: u16 = 1;
pub const IFLA_MTU: u16 = 4;
pub const IFLA_LINK: u16 = 5;

/// `struct nlattr` header width, and the boundary every attribute is padded to.
pub const NLA_HDR_LEN: usize = 4;
pub const NLA_ALIGNTO: usize = 4;
/// Nesting marker bit in `nla_type`; masked off to read the real number.
pub const NLA_F_NESTED: u16 = 1 << 15;
/// Bits of `nla_type` that carry the attribute number.
pub const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | (1 << 14));

/// Ethernet hardware type. A VLAN interface may only sit on this. # C: O(1)
pub const ARPHRD_ETHER: u16 = 1;

/// Round an attribute length up to the netlink alignment boundary. # C: O(1)
pub const fn nla_align(len: usize) -> usize {
    (len + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
}
