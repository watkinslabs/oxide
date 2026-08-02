// Receive-side ancillary messages for the IP levels: WHICH control messages a
// datagram produces, in WHAT ORDER, with WHAT payload. One ungated owner so
// the whole decision is hosted-testable; `recvmsg` only moves the bytes.
//
// Module manifest:
// - this file: the message numbers, the received-datagram view, and the plan.
// - `payload`: the wire layout of each non-scalar message.
// - `pktoptions`: the stream socket's on-demand publication of the same set.
// - `tests`: hosted coverage for the ordering and the layouts.

pub mod payload;
pub mod pktoptions;
#[cfg(test)]
mod tests;

use alloc::vec::Vec;

use crate::addr::Ipv4Addr;

pub const SOL_IP: i32 = 0;
/// `SOL_UDP` / `IPPROTO_UDP`.
pub const SOL_UDP: i32 = 17;
pub const SOL_IPV6: i32 = 41;

/// `UDP_GRO` publishes the segment size a coalesced receive was built from.
pub const UDP_GRO: i32 = 104;

pub const IP_TOS: i32 = 1;
pub const IP_TTL: i32 = 2;
pub const IP_RECVOPTS: i32 = 6;
pub const IP_RETOPTS: i32 = 7;
pub const IP_PKTINFO: i32 = 8;
pub const IP_ORIGDSTADDR: i32 = 20;
pub const IP_CHECKSUM: i32 = 23;
pub const IP_RECVFRAGSIZE: i32 = 25;
/// `SCM_SECURITY` is published at the IP level by `IP_PASSSEC`.
pub const SCM_SECURITY: i32 = 3;

pub const IPV6_2292PKTINFO: i32 = 2;
pub const IPV6_2292HOPOPTS: i32 = 3;
pub const IPV6_2292DSTOPTS: i32 = 4;
pub const IPV6_2292RTHDR: i32 = 5;
pub const IPV6_2292HOPLIMIT: i32 = 8;
pub const IPV6_FLOWINFO: i32 = 11;
pub const IPV6_PKTINFO: i32 = 50;
pub const IPV6_HOPLIMIT: i32 = 52;
pub const IPV6_HOPOPTS: i32 = 54;
pub const IPV6_RTHDR: i32 = 57;
pub const IPV6_DSTOPTS: i32 = 59;
pub const IPV6_TCLASS: i32 = 67;
pub const IPV6_ORIGDSTADDR: i32 = 74;
pub const IPV6_RECVFRAGSIZE: i32 = 77;

/// Extension-header kinds the receive path republishes.
pub const NH_HOP_BY_HOP: u8 = 0;
pub const NH_ROUTING: u8 = 43;
pub const NH_DEST_OPTS: u8 = 60;

/// The twenty-eight bits an IPv6 header carries below the version field.
pub const IPV6_FLOWINFO_MASK: u32 = 0x0fff_ffff;

/// One ancillary message, ready to copy out. # C: O(1)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Msg { pub level: i32, pub kind: i32, pub bytes: Vec<u8> }

impl Msg {
    /// One `int`-shaped message. # C: O(1)
    pub(crate) fn int(level: i32, kind: i32, value: i32) -> Self {
        Self { level, kind, bytes: Vec::from(value.to_ne_bytes()) }
    }
    /// One message whose payload is a wire layout. # C: O(bytes)
    pub(crate) fn raw(level: i32, kind: i32, bytes: &[u8]) -> Self {
        Self { level, kind, bytes: Vec::from(bytes) }
    }
}

/// Which receive options the socket turned on. # C: O(1)
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Want {
    /// `UDP_GRO` — the receive-coalescing segment size.
    pub gro: bool,
    pub pktinfo: bool,
    pub ttl: bool,
    pub tos: bool,
    pub recvopts: bool,
    pub retopts: bool,
    pub passsec: bool,
    pub origdstaddr: bool,
    pub checksum: bool,
    pub fragsize: bool,

    pub pktinfo6: bool,
    pub hoplimit6: bool,
    pub tclass6: bool,
    pub flowinfo6: bool,
    pub hopopts6: bool,
    pub dstopts6: bool,
    pub rthdr6: bool,
    pub origdstaddr6: bool,
    pub fragsize6: bool,
    /// The RFC 2292 personality, which carries its own message numbers.
    pub old_pktinfo6: bool,
    pub old_hoplimit6: bool,
    pub old_hopopts6: bool,
    pub old_dstopts6: bool,
    pub old_rthdr6: bool,
}

impl Want {
    /// Whether any option at all is on — the shortcut the receive path takes
    /// before it looks at the datagram. # C: O(1)
    pub fn any(&self) -> bool { *self != Self::default() }
}

/// The received datagram's header state, as the queue captured it. # C: O(1)
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RxMeta {
    /// Destination address and receiving interface.
    pub dst: Option<([u8; 4], u32)>,
    pub ttl: Option<u8>,
    pub tos: Option<u8>,
    /// Compiled receive-side IPv4 option area, empty when the header carried
    /// none.
    pub options: crate::ipv4_options::Compiled,
    /// Source address, which decides whether an echoed source route would
    /// name the sender twice.
    pub src: [u8; 4],
    /// Destination port, which completes the original-destination address.
    pub dport: u16,
    /// Largest fragment the datagram was reassembled from.
    pub frag_max: u32,
    /// A complete datagram checksum, present only when the receive path
    /// actually computed one over the whole packet.
    pub checksum: Option<u32>,
    /// The peer's security label, present only when a module labels sockets.
    pub security: Option<Vec<u8>>,
    /// The segment size several coalesced datagrams were assembled from, and
    /// `None` for a receive of one datagram.
    pub gro: Option<i32>,

    pub dst6: Option<([u8; 16], u32)>,
    pub hoplimit: Option<u8>,
    pub tclass: Option<u8>,
    pub flowinfo: u32,
    /// `(header kind, whole header bytes)`, in the order they arrived.
    pub ext_headers: Vec<(u8, Vec<u8>)>,
    pub scope_id: u32,
}

/// `ip6_flowinfo`: the traffic class and flow label, without the version
/// field, in network byte order. # C: O(1)
pub fn flowinfo(traffic_class: u8, flow_label: u32) -> u32 {
    (((traffic_class as u32) << 20) | (flow_label & 0x000f_ffff)) & IPV6_FLOWINFO_MASK
}

/// Every ancillary message one received datagram produces, in the order the
/// control buffer carries them. # C: O(headers)
pub fn plan(want: &Want, meta: &RxMeta) -> Vec<Msg> {
    let mut out = Vec::new();
    if !want.any() { return out; }
    // The segmentation size of a coalesced receive precedes the IP-level
    // ancillary data on both families. Whether it exists at all is the
    // coalescing owner's rule, not this table's.
    if let Some(seg) = crate::udp_gro::reported_seg_size(want.gro, meta.gro) {
        out.push(Msg::int(SOL_UDP, UDP_GRO, seg));
    }
    ipv4(want, meta, &mut out);
    ipv6(want, meta, &mut out);
    out
}

/// The IPv4 level, ordered by the frequency a receiver asks for them.
/// # C: O(optlen)
fn ipv4(want: &Want, meta: &RxMeta, out: &mut Vec<Msg>) {
    if want.pktinfo {
        if let Some((addr, ifindex)) = meta.dst {
            out.push(Msg::raw(SOL_IP, IP_PKTINFO, &payload::in_pktinfo(addr, ifindex)));
        }
    }
    if want.ttl {
        if let Some(ttl) = meta.ttl { out.push(Msg::int(SOL_IP, IP_TTL, ttl as i32)); }
    }
    // The type-of-service byte is published as ONE byte, not as an `int` —
    // the one scalar at this level that is not `int`-shaped.
    if want.tos {
        if let Some(tos) = meta.tos { out.push(Msg::raw(SOL_IP, IP_TOS, &[tos])); }
    }
    // A header with no option area produces no message at all, rather than an
    // empty one. Both messages are the SAME echoed area: IP_RETOPTS publishes
    // the reply as it would go out, IP_RECVOPTS the same reply with the
    // pointer the ECHO advanced stepped back and that slot cleared — the area
    // as this host received and recorded it, not as the sender wrote it.
    if (want.recvopts || want.retopts) && !meta.options.is_empty() {
        if let Ok(echoed) = crate::ipv4_options::echo(&meta.options, Ipv4Addr::new(meta.src[0], meta.src[1], meta.src[2], meta.src[3])) {
            if !echoed.is_empty() {
                if want.recvopts {
                    let undone = crate::ipv4_options::undo(&echoed);
                    out.push(Msg::raw(SOL_IP, IP_RECVOPTS, &undone));
                }
                if want.retopts { out.push(Msg::raw(SOL_IP, IP_RETOPTS, &echoed.data)); }
            }
        }
    }
    if want.passsec {
        if let Some(label) = &meta.security {
            out.push(Msg::raw(SOL_IP, SCM_SECURITY, label));
        }
    }
    if want.origdstaddr {
        if let Some((addr, _)) = meta.dst {
            out.push(Msg::raw(SOL_IP, IP_ORIGDSTADDR,
                &payload::sockaddr_in(addr, meta.dport)));
        }
    }
    if want.checksum {
        if let Some(csum) = meta.checksum {
            out.push(Msg::raw(SOL_IP, IP_CHECKSUM, &csum.to_ne_bytes()));
        }
    }
    // A datagram that arrived whole reports no fragment size.
    if want.fragsize && meta.frag_max != 0 {
        out.push(Msg::int(SOL_IP, IP_RECVFRAGSIZE, meta.frag_max as i32));
    }
}

/// The IPv6 level: the RFC 3542 personality first, then the extension headers
/// in wire order, then the RFC 2292 personality, then the address and size.
/// # C: O(headers)
fn ipv6(want: &Want, meta: &RxMeta, out: &mut Vec<Msg>) {
    if want.pktinfo6 {
        if let Some((addr, ifindex)) = meta.dst6 {
            out.push(Msg::raw(SOL_IPV6, IPV6_PKTINFO, &payload::in6_pktinfo(addr, ifindex)));
        }
    }
    if want.hoplimit6 {
        if let Some(hop) = meta.hoplimit { out.push(Msg::int(SOL_IPV6, IPV6_HOPLIMIT, hop as i32)); }
    }
    if want.tclass6 {
        if let Some(tc) = meta.tclass { out.push(Msg::int(SOL_IPV6, IPV6_TCLASS, tc as i32)); }
    }
    // An all-zero flow-info field produces no message.
    if want.flowinfo6 && meta.flowinfo != 0 {
        out.push(Msg::raw(SOL_IPV6, IPV6_FLOWINFO, &meta.flowinfo.to_be_bytes()));
    }
    // The hop-by-hop header can appear only once, and only first.
    if want.hopopts6 {
        if let Some(bytes) = first_header(meta, NH_HOP_BY_HOP) {
            out.push(Msg::raw(SOL_IPV6, IPV6_HOPOPTS, bytes));
        }
    }
    // The remaining headers are republished in the order they arrived, which
    // is the only way a receiver can tell a pre-routing destination-options
    // header from a post-routing one.
    for (kind, bytes) in &meta.ext_headers {
        match *kind {
            NH_DEST_OPTS if want.dstopts6 =>
                out.push(Msg::raw(SOL_IPV6, IPV6_DSTOPTS, bytes)),
            NH_ROUTING if want.rthdr6 =>
                out.push(Msg::raw(SOL_IPV6, IPV6_RTHDR, bytes)),
            _ => {}
        }
    }
    legacy_ipv6(want, meta, out);
    if want.origdstaddr6 {
        if let Some((addr, _)) = meta.dst6 {
            out.push(Msg::raw(SOL_IPV6, IPV6_ORIGDSTADDR,
                &payload::sockaddr_in6(addr, meta.dport, meta.scope_id)));
        }
    }
    if want.fragsize6 && meta.frag_max != 0 {
        out.push(Msg::int(SOL_IPV6, IPV6_RECVFRAGSIZE, meta.frag_max as i32));
    }
}

/// The RFC 2292 personality, which numbers its messages separately and orders
/// the destination-options header around the routing header rather than by
/// arrival. # C: O(headers)
fn legacy_ipv6(want: &Want, meta: &RxMeta, out: &mut Vec<Msg>) {
    if want.old_pktinfo6 {
        if let Some((addr, ifindex)) = meta.dst6 {
            out.push(Msg::raw(SOL_IPV6, IPV6_2292PKTINFO,
                &payload::in6_pktinfo(addr, ifindex)));
        }
    }
    if want.old_hoplimit6 {
        if let Some(hop) = meta.hoplimit {
            out.push(Msg::int(SOL_IPV6, IPV6_2292HOPLIMIT, hop as i32));
        }
    }
    if want.old_hopopts6 {
        if let Some(bytes) = first_header(meta, NH_HOP_BY_HOP) {
            out.push(Msg::raw(SOL_IPV6, IPV6_2292HOPOPTS, bytes));
        }
    }
    let routing = meta.ext_headers.iter().position(|(kind, _)| *kind == NH_ROUTING);
    if want.old_dstopts6 {
        if let Some(bytes) = dstopts_before(meta, routing) {
            out.push(Msg::raw(SOL_IPV6, IPV6_2292DSTOPTS, bytes));
        }
    }
    if want.old_rthdr6 {
        if let Some(at) = routing {
            out.push(Msg::raw(SOL_IPV6, IPV6_2292RTHDR, &meta.ext_headers[at].1));
        }
    }
    if want.old_dstopts6 {
        if let Some(bytes) = dstopts_after(meta, routing) {
            out.push(Msg::raw(SOL_IPV6, IPV6_2292DSTOPTS, bytes));
        }
    }
}

fn first_header(meta: &RxMeta, kind: u8) -> Option<&[u8]> {
    meta.ext_headers.iter().find(|(k, _)| *k == kind).map(|(_, b)| b.as_slice())
}

/// The destination-options header a routing header follows. With no routing
/// header there is none: the sole destination-options header belongs after.
/// # C: O(headers)
fn dstopts_before(meta: &RxMeta, routing: Option<usize>) -> Option<&[u8]> {
    let at = routing?;
    meta.ext_headers[..at].iter().find(|(k, _)| *k == NH_DEST_OPTS).map(|(_, b)| b.as_slice())
}

/// The destination-options header that follows the routing header, or the
/// only one when the packet carries no routing header. # C: O(headers)
fn dstopts_after(meta: &RxMeta, routing: Option<usize>) -> Option<&[u8]> {
    let from = routing.map_or(0, |at| at + 1);
    meta.ext_headers.get(from..)?.iter().find(|(k, _)| *k == NH_DEST_OPTS)
        .map(|(_, b)| b.as_slice())
}
