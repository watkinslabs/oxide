//! The requested translation. A range says which addresses and ports a flow
//! may be mapped onto; everything the allocator does is bounded by it.

use conntrack::hash::{jhash2, reciprocal_scale};
use conntrack::tuple::{InetAddr, Tuple, addr_len};
use conntrack::uapi::{IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_SCTP, IPPROTO_TCP,
                      IPPROTO_UDP, IPPROTO_UDPLITE, NFPROTO_IPV6};

use crate::uapi::*;

/// One requested translation.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct NatRange {
    pub flags: u32,
    pub min_addr: InetAddr,
    pub max_addr: InetAddr,
    /// Port or ICMP id, host order.
    pub min_proto: u16,
    pub max_proto: u16,
    /// Base the offset mode counts from.
    pub base_proto: u16,
}

impl NatRange {
    /// A range that maps onto exactly one address and leaves the port free —
    /// the shape masquerade, redirect and the null binding all build.
    /// # C: O(1)
    pub fn single_addr(addr: InetAddr, flags: u32) -> Self {
        Self { flags: flags | NF_NAT_RANGE_MAP_IPS, min_addr: addr, max_addr: addr,
               min_proto: 0, max_proto: 0, base_proto: 0 }
    }

    /// # C: O(1)
    pub fn maps_addr(&self) -> bool { self.flags & NF_NAT_RANGE_MAP_IPS != 0 }
    /// # C: O(1)
    pub fn proto_specified(&self) -> bool {
        self.flags & NF_NAT_RANGE_PROTO_SPECIFIED != 0
    }
    /// # C: O(1)
    pub fn random(&self) -> bool { self.flags & NF_NAT_RANGE_PROTO_RANDOM_ALL != 0 }
    /// # C: O(1)
    pub fn persistent(&self) -> bool { self.flags & NF_NAT_RANGE_PERSISTENT != 0 }

    /// Ordered port bounds. A caller may hand them over reversed; silently
    /// swapping is what the reference does, and treating `max < min` as an
    /// empty range instead would make every allocation fail.
    /// # C: O(1)
    pub fn ordered_ports(&self) -> (u16, u16) {
        if self.max_proto < self.min_proto { (self.max_proto, self.min_proto) }
        else { (self.min_proto, self.max_proto) }
    }
}

/// Which tuple half a manipulation reads and writes. # C: O(1)
pub fn manip_addr(t: &Tuple, manip: u8) -> InetAddr {
    if manip == NF_NAT_MANIP_SRC { t.src.addr } else { t.dst.addr }
}

/// Port or id the manipulation acts on. ICMP has one id shared by both ends,
/// so both manipulations read the same field. # C: O(1)
pub fn manip_port(t: &Tuple, manip: u8) -> u16 {
    if t.is_icmp() { return t.src.proto.port; }
    if manip == NF_NAT_MANIP_SRC { t.src.proto.port } else { t.dst.proto.port }
}

/// Write the address the manipulation owns. # C: O(1)
pub fn set_manip_addr(t: &mut Tuple, manip: u8, a: InetAddr) {
    if manip == NF_NAT_MANIP_SRC { t.src.addr = a; } else { t.dst.addr = a; }
}

/// Write the port or id the manipulation owns. # C: O(1)
pub fn set_manip_port(t: &mut Tuple, manip: u8, p: u16) {
    if t.is_icmp() { t.src.proto.port = p; return; }
    if manip == NF_NAT_MANIP_SRC { t.src.proto.port = p; } else { t.dst.proto.port = p; }
}

/// Whether the tuple's manipulated address falls inside the range. A range
/// that does not map addresses constrains nothing, so every address is in it.
/// # C: O(addr len)
pub fn addr_in_range(t: &Tuple, r: &NatRange, manip: u8) -> bool {
    if !r.maps_addr() { return true; }
    let a = manip_addr(t, manip);
    let n = addr_len(t.l3num);
    let lo = &r.min_addr.0[..n];
    let hi = &r.max_addr.0[..n];
    let cur = &a.0[..n];
    cur >= lo && cur <= hi
}

/// Whether the tuple's manipulated port falls inside the range. A range with
/// no port bounds constrains nothing. # C: O(1)
pub fn port_in_range(t: &Tuple, r: &NatRange, manip: u8) -> bool {
    if !r.proto_specified() { return true; }
    let (lo, hi) = r.ordered_ports();
    let p = manip_port(t, manip);
    p >= lo && p <= hi
}

/// Whether the tuple already satisfies the whole request. # C: O(addr len)
pub fn in_range(t: &Tuple, r: &NatRange, manip: u8) -> bool {
    addr_in_range(t, r, manip) && port_in_range(t, r, manip)
}

/// Default port window for a source translation with no explicit range.
/// Privileged sources keep a privileged mapped port, because a service that
/// authenticates on "the peer bound a reserved port" must not be defeated by
/// a NAT that maps it to an unprivileged one.
/// # C: O(1)
pub fn default_port_window(port: u16) -> (u16, u32) {
    use conntrack::limits::*;
    if port < NAT_PRIVILEGED_PORT {
        if port < NAT_LOW_WINDOW_PORT {
            (NAT_PORT_LOW_MIN, (NAT_PORT_LOW_MAX - NAT_PORT_LOW_MIN + 1) as u32)
        } else {
            (NAT_PORT_MID_MIN, (NAT_PORT_MID_MAX - NAT_PORT_MID_MIN + 1) as u32)
        }
    } else {
        (NAT_PORT_HIGH_MIN, (NAT_PORT_HIGH_MAX - NAT_PORT_HIGH_MIN + 1) as u32)
    }
}

/// The port window and key field a protocol allocates from. `None` means the
/// protocol has no port-like field to remap and the tuple stands as it is.
/// # C: O(1)
pub fn proto_window(t: &Tuple, r: &NatRange, manip: u8) -> Option<(u16, u32)> {
    if r.proto_specified() {
        let (lo, hi) = r.ordered_ports();
        return Some((lo, (hi - lo) as u32 + 1));
    }
    match t.protonum {
        IPPROTO_ICMP | IPPROTO_ICMPV6 => Some((0, 65536)),
        IPPROTO_TCP | IPPROTO_UDP | IPPROTO_UDPLITE | IPPROTO_SCTP => {
            // A destination port is never invented: the client asked for a
            // specific service, and moving it silently would break the flow.
            if manip == NF_NAT_MANIP_DST { return None; }
            Some(default_port_window(manip_port(t, manip)))
        }
        _ => None,
    }
}

/// Pick the mapped address inside `[min, max]`, deterministically from the
/// source so one client keeps one mapping. Without `PERSISTENT` the
/// destination participates too, spreading one client's flows across the pool.
/// # C: O(addr words)
pub fn pick_addr(t: &Tuple, r: &NatRange, manip: u8) -> InetAddr {
    if !r.maps_addr() { return manip_addr(t, manip); }
    if r.min_addr == r.max_addr { return r.min_addr; }
    let n = addr_len(t.l3num) / 4;
    let mut src_words = [0u32; 4];
    for (i, w) in src_words.iter_mut().take(n).enumerate() {
        *w = u32::from_be_bytes([t.src.addr.0[i * 4], t.src.addr.0[i * 4 + 1],
                                 t.src.addr.0[i * 4 + 2], t.src.addr.0[i * 4 + 3]]);
    }
    let dst_last = u32::from_be_bytes([
        t.dst.addr.0[(n - 1) * 4], t.dst.addr.0[(n - 1) * 4 + 1],
        t.dst.addr.0[(n - 1) * 4 + 2], t.dst.addr.0[(n - 1) * 4 + 3]]);
    let seed = if r.persistent() { 0 } else { dst_last ^ t.zone as u32 };
    let mut j = jhash2(&src_words[..n], seed);
    let mut out = [0u8; 16];
    let mut full_range = false;
    for i in 0..n {
        let (minip, dist) = if full_range {
            (0u32, u32::MAX)
        } else {
            let lo = u32::from_be_bytes([r.min_addr.0[i * 4], r.min_addr.0[i * 4 + 1],
                                         r.min_addr.0[i * 4 + 2], r.min_addr.0[i * 4 + 3]]);
            let hi = u32::from_be_bytes([r.max_addr.0[i * 4], r.max_addr.0[i * 4 + 1],
                                         r.max_addr.0[i * 4 + 2], r.max_addr.0[i * 4 + 3]]);
            (lo, hi.wrapping_sub(lo).wrapping_add(1))
        };
        let word = minip.wrapping_add(reciprocal_scale(j, dist));
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        let maxw = u32::from_be_bytes([r.max_addr.0[i * 4], r.max_addr.0[i * 4 + 1],
                                       r.max_addr.0[i * 4 + 2], r.max_addr.0[i * 4 + 3]]);
        if word != maxw { full_range = true; }
        if !r.persistent() {
            let w = u32::from_be_bytes([t.dst.addr.0[i * 4], t.dst.addr.0[i * 4 + 1],
                                        t.dst.addr.0[i * 4 + 2], t.dst.addr.0[i * 4 + 3]]);
            j ^= w;
        }
    }
    if t.l3num != NFPROTO_IPV6 { out[4..].fill(0); }
    InetAddr(out)
}

/// One-to-one prefix map: keep the host part, replace the network part with
/// the range's. Used when the request asks for a whole-prefix translation
/// rather than a pool.
/// # C: O(addr len)
pub fn netmap_addr(current: InetAddr, r: &NatRange, l3num: u8) -> InetAddr {
    let n = addr_len(l3num);
    let mut out = current.0;
    for i in 0..n {
        let netmask = !(r.min_addr.0[i] ^ r.max_addr.0[i]);
        out[i] = (r.min_addr.0[i] & netmask) | (current.0[i] & !netmask);
    }
    InetAddr(out)
}
