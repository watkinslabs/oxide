//! Conntrack tuple: the (src, dst, l3num, protonum) key both directions of a
//! flow hash on. A tuple and its inverse identify the same connection; the
//! table stores both halves so a reply finds the entry its original created.

use crate::uapi::{IPPROTO_ICMP, IPPROTO_ICMPV6, NFPROTO_IPV4, NFPROTO_IPV6};

/// L3 address, wide enough for both families. IPv4 occupies the first word.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct InetAddr(pub [u8; 16]);

impl InetAddr {
    /// # C: O(1)
    pub const fn v4(a: [u8; 4]) -> Self {
        Self([a[0], a[1], a[2], a[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }
    /// # C: O(1)
    pub const fn v6(a: [u8; 16]) -> Self { Self(a) }
    /// Big-endian IPv4 word. # C: O(1)
    pub const fn as_v4_u32(&self) -> u32 {
        u32::from_be_bytes([self.0[0], self.0[1], self.0[2], self.0[3]])
    }
    /// # C: O(1)
    pub const fn from_v4_u32(v: u32) -> Self { Self::v4(v.to_be_bytes()) }
    /// Address words in network order — the unit both the NAT range walk and
    /// the hash consume. IPv4 uses word 0 only. # C: O(1)
    pub fn words(&self, l3num: u8) -> &[u8] {
        match l3num { NFPROTO_IPV6 => &self.0[..], _ => &self.0[..4] }
    }
}

/// Per-protocol port/id half of one tuple end. Linux keeps a union here; the
/// discriminant is the tuple's `protonum`, so one 16-bit slot plus the ICMP
/// type/code covers every tracker.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ProtoPart {
    /// TCP/UDP/SCTP port, ICMP id, or GRE call-id, host order.
    pub port: u16,
    /// ICMP/ICMPv6 message type. Zero for port protocols.
    pub icmp_type: u8,
    /// ICMP/ICMPv6 message code. Zero for port protocols.
    pub icmp_code: u8,
}

impl ProtoPart {
    /// # C: O(1)
    pub const fn port(port: u16) -> Self { Self { port, icmp_type: 0, icmp_code: 0 } }
    /// # C: O(1)
    pub const fn icmp(id: u16, icmp_type: u8, icmp_code: u8) -> Self {
        Self { port: id, icmp_type, icmp_code }
    }
}

/// One end of a tuple.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct TupleEnd { pub addr: InetAddr, pub proto: ProtoPart }

/// Full conntrack tuple.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Tuple {
    pub src: TupleEnd,
    pub dst: TupleEnd,
    /// `NFPROTO_IPV4` / `NFPROTO_IPV6`.
    pub l3num: u8,
    /// L4 protocol number.
    pub protonum: u8,
    /// Conntrack zone id. Zone 0 is the default zone.
    pub zone: u16,
}

/// ICMP type inversion — Linux's `invmap`, encoded as request/reply pairs so
/// an unlisted type has no inverse and cannot open a connection.
const ICMP_INVMAP: &[(u8, u8)] = &[
    (0, 8),   // echo reply       <-> echo request
    (8, 0),
    (13, 14), // timestamp        <-> timestamp reply
    (14, 13),
    (15, 16), // information req  <-> information reply
    (16, 15),
    (17, 18), // address mask req <-> address mask reply
    (18, 17),
];

/// ICMPv6 type inversion — the echo and node-information pairs.
const ICMPV6_INVMAP: &[(u8, u8)] = &[
    (128, 129), // echo request <-> echo reply
    (129, 128),
    (139, 140), // NI query     <-> NI reply
    (140, 139),
];

/// ICMP types that may open a new tracked connection.
const ICMP_VALID_NEW: &[u8] = &[8, 13, 15, 17];
/// ICMPv6 types that may open a new tracked connection.
const ICMPV6_VALID_NEW: &[u8] = &[128, 139];

/// Inverse of one ICMP type, or `None` when the type has no reply form.
/// # C: O(1)
pub fn icmp_invert_type(l3num: u8, icmp_type: u8) -> Option<u8> {
    let map = if l3num == NFPROTO_IPV6 { ICMPV6_INVMAP } else { ICMP_INVMAP };
    map.iter().find(|(t, _)| *t == icmp_type).map(|(_, r)| *r)
}

/// Whether an ICMP type may start a tracked flow. # C: O(1)
pub fn icmp_valid_new(l3num: u8, icmp_type: u8) -> bool {
    let set = if l3num == NFPROTO_IPV6 { ICMPV6_VALID_NEW } else { ICMP_VALID_NEW };
    set.contains(&icmp_type)
}

impl Tuple {
    /// Whether this tuple's protocol is one of the ICMP trackers. # C: O(1)
    pub fn is_icmp(&self) -> bool {
        matches!((self.l3num, self.protonum),
            (NFPROTO_IPV4, IPPROTO_ICMP) | (NFPROTO_IPV6, IPPROTO_ICMPV6))
    }

    /// The tuple a reply to this one carries. `None` when the protocol has no
    /// invertible form for this message — an ICMP type with no reply cannot
    /// open a flow, so the caller must refuse it rather than track one half.
    /// # C: O(1)
    pub fn invert(&self) -> Option<Tuple> {
        if self.is_icmp() {
            let reply_type = icmp_invert_type(self.l3num, self.dst.proto.icmp_type)?;
            return Some(Tuple {
                src: TupleEnd { addr: self.dst.addr,
                    proto: ProtoPart::icmp(self.src.proto.port, 0, 0) },
                dst: TupleEnd { addr: self.src.addr,
                    proto: ProtoPart::icmp(0, reply_type, self.dst.proto.icmp_code) },
                l3num: self.l3num, protonum: self.protonum, zone: self.zone,
            });
        }
        Some(Tuple {
            src: TupleEnd { addr: self.dst.addr, proto: self.dst.proto },
            dst: TupleEnd { addr: self.src.addr, proto: self.src.proto },
            l3num: self.l3num, protonum: self.protonum, zone: self.zone,
        })
    }

    /// Same source end, same protocol — the test `find_appropriate_src` runs
    /// when reusing an existing source mapping. # C: O(1)
    pub fn same_src(&self, other: &Tuple) -> bool {
        self.l3num == other.l3num && self.protonum == other.protonum
            && self.zone == other.zone && self.src == other.src
    }

    /// Table hash. Both directions of a flow hash independently: the entry is
    /// inserted under both its original and its reply tuple, so a reply packet
    /// finds it directly rather than by inverting and searching again.
    /// # C: O(1)
    pub fn hash(&self, seed: u32) -> u32 { crate::hash::tuple_hash(self, seed) }
}

/// Byte width of one address for a family. # C: O(1)
pub const fn addr_len(l3num: u8) -> usize {
    if l3num == NFPROTO_IPV6 { 16 } else { 4 }
}
