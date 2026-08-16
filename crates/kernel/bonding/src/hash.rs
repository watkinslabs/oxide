// Transmit-hash computation. Pure over `FlowKeys`: no device, no packet, no
// lock — the reduction to a slave index is a plain modulo at the caller.

use crate::uapi::{
    BOND_XMIT_POLICY_ENCAP23, BOND_XMIT_POLICY_ENCAP34, BOND_XMIT_POLICY_LAYER2,
    BOND_XMIT_POLICY_LAYER23, BOND_XMIT_POLICY_LAYER34, BOND_XMIT_POLICY_VLAN_SRCMAC,
};

/// Everything the hash policies read out of one frame, already dissected.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct FlowKeys {
    /// Outer Ethernet destination.
    pub dst_mac: [u8; 6],
    /// Outer Ethernet source.
    pub src_mac: [u8; 6],
    /// Ethertype in host order.
    pub eth_proto: u16,
    /// VLAN tag, zero when the frame carries none.
    pub vlan: u16,
    /// Dissected L3 source, as the flow dissector's 32-bit fold.
    pub l3_src: u32,
    /// Dissected L3 destination, as the flow dissector's 32-bit fold.
    pub l3_dst: u32,
    /// The two L4 port numbers packed into one word, as they sit on the wire.
    pub ports: u32,
    /// ICMP identifier word; non-zero replaces `ports` when present.
    pub icmp_id: u32,
    /// Whether the flow dissector produced L3/L4 keys at all.
    pub dissected: bool,
    /// A hardware/stack-supplied L4 hash, when one is already attached.
    pub l4_hash: Option<u32>,
}

/// Fold of the low destination/source address octets with the ethertype.
/// # C: O(1)
pub fn eth_hash(flow: &FlowKeys) -> u32 {
    (flow.dst_mac[5] as u32) ^ (flow.src_mac[5] as u32) ^ (flow.eth_proto as u32)
}

/// VLAN tag folded with the two halves of the source address.
/// # C: O(1)
pub fn vlan_srcmac_hash(flow: &FlowKeys) -> u32 {
    let mut vendor: u32 = 0;
    for b in &flow.src_mac[..3] { vendor = (vendor << 8) | (*b as u32); }
    let mut dev: u32 = 0;
    for b in &flow.src_mac[3..] { dev = (dev << 8) | (*b as u32); }
    (flow.vlan as u32) ^ vendor ^ dev
}

/// Mix the L3 addresses into a seed and avalanche it; the layer-3+4 policies
/// discard the low bit so the common even-port pattern still spreads.
/// # C: O(1)
pub fn ip_hash(seed: u32, flow: &FlowKeys, policy: u8) -> u32 {
    let mut hash = seed ^ flow.l3_dst ^ flow.l3_src;
    hash ^= hash >> 16;
    hash ^= hash >> 8;
    if policy == BOND_XMIT_POLICY_LAYER34 || policy == BOND_XMIT_POLICY_ENCAP34 {
        return hash >> 1;
    }
    hash
}

/// Policy-selected transmit hash for one frame.
/// # C: O(1)
pub fn bond_xmit_hash(policy: u8, flow: &FlowKeys) -> u32 {
    if policy == BOND_XMIT_POLICY_ENCAP34 {
        if let Some(h) = flow.l4_hash { return h; }
    }
    if policy == BOND_XMIT_POLICY_VLAN_SRCMAC { return vlan_srcmac_hash(flow); }
    if policy == BOND_XMIT_POLICY_LAYER2 || !flow.dissected { return eth_hash(flow); }

    let seed = if policy == BOND_XMIT_POLICY_LAYER23 || policy == BOND_XMIT_POLICY_ENCAP23 {
        eth_hash(flow)
    } else if flow.icmp_id != 0 {
        flow.icmp_id
    } else {
        flow.ports
    };
    ip_hash(seed, flow, policy)
}

/// Ethernet header length before any VLAN tag.
const ETH_HLEN: usize = 14;
/// Length of one VLAN tag control block.
const VLAN_HLEN: usize = 4;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88a8;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_SCTP: u8 = 132;
const IPPROTO_ICMP: u8 = 1;
/// Offset of the protocol octet inside an IPv4 header.
const IPV4_PROTO_OFF: usize = 9;
/// Offset of the source address inside an IPv4 header.
const IPV4_SRC_OFF: usize = 12;
/// Offset of the next-header octet inside an IPv6 header.
const IPV6_NEXT_HDR_OFF: usize = 6;
/// Offset of the source address inside an IPv6 header.
const IPV6_SRC_OFF: usize = 8;
const IPV6_HLEN: usize = 40;
/// Offset of the identifier field inside an ICMP header.
const ICMP_ID_OFF: usize = 4;

fn word_at(buf: &[u8], off: usize) -> u32 {
    if off + 4 > buf.len() { return 0; }
    u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn fold_v6(buf: &[u8], off: usize) -> u32 {
    let mut acc = 0u32;
    for i in 0..4 { acc ^= word_at(buf, off + i * 4); }
    acc
}

/// Read the hash inputs out of one complete link frame. A frame the dissector
/// cannot walk to layer 3 comes back with `dissected` clear, which sends every
/// policy down the link-layer fold.
/// # C: O(header bytes)
pub fn dissect(frame: &[u8]) -> FlowKeys {
    let mut fk = FlowKeys::default();
    if frame.len() < ETH_HLEN { return fk; }
    fk.dst_mac.copy_from_slice(&frame[0..6]);
    fk.src_mac.copy_from_slice(&frame[6..12]);
    let mut proto = u16::from_be_bytes([frame[12], frame[13]]);
    let mut off = ETH_HLEN;
    while (proto == ETH_P_8021Q || proto == ETH_P_8021AD) && off + VLAN_HLEN <= frame.len() {
        fk.vlan = u16::from_be_bytes([frame[off], frame[off + 1]]) & 0x0fff;
        proto = u16::from_be_bytes([frame[off + 2], frame[off + 3]]);
        off += VLAN_HLEN;
    }
    fk.eth_proto = proto;

    let (l4_off, l4_proto) = match proto {
        ETH_P_IP => {
            if off + 20 > frame.len() { return fk; }
            let ihl = ((frame[off] & 0x0f) as usize) * 4;
            if ihl < 20 || off + ihl > frame.len() { return fk; }
            fk.l3_src = word_at(frame, off + IPV4_SRC_OFF);
            fk.l3_dst = word_at(frame, off + IPV4_SRC_OFF + 4);
            (off + ihl, frame[off + IPV4_PROTO_OFF])
        }
        ETH_P_IPV6 => {
            if off + IPV6_HLEN > frame.len() { return fk; }
            fk.l3_src = fold_v6(frame, off + IPV6_SRC_OFF);
            fk.l3_dst = fold_v6(frame, off + IPV6_SRC_OFF + 16);
            (off + IPV6_HLEN, frame[off + IPV6_NEXT_HDR_OFF])
        }
        _ => return fk,
    };
    fk.dissected = true;
    match l4_proto {
        IPPROTO_TCP | IPPROTO_UDP | IPPROTO_SCTP => fk.ports = word_at(frame, l4_off),
        IPPROTO_ICMP => fk.icmp_id = word_at(frame, l4_off + ICMP_ID_OFF),
        _ => {}
    }
    fk
}

/// Whether the frame carries a group-membership report, which round-robin
/// pins to one interface.
/// # C: O(header bytes)
pub fn is_igmp(frame: &[u8]) -> bool {
    /// Group-management protocol number inside IPv4.
    const IPPROTO_IGMP: u8 = 2;
    if frame.len() < ETH_HLEN + 20 { return false; }
    if u16::from_be_bytes([frame[12], frame[13]]) != ETH_P_IP { return false; }
    frame[ETH_HLEN + IPV4_PROTO_OFF] == IPPROTO_IGMP
}

/// Slave index the hash lands on for a candidate array of `count` entries.
/// # C: O(1)
pub fn hash_to_index(hash: u32, count: usize) -> Option<usize> {
    if count == 0 { return None; }
    Some((hash as usize) % count)
}
