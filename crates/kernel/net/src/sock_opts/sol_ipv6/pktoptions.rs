// `IPV6_2292PKTOPTIONS`, both directions.
//
// The write is an ancillary-message STREAM, admitted under the send-control
// rules and folded into the socket's sticky transmit headers; the read is the
// same set of messages published back. Neither direction is a scalar, so
// neither belongs in `set`/`get`'s value tables — they route here.
//
// Both halves are ungated so the whole decision — which message number each
// field takes, which receive bit gates it, what order they come in, and how a
// short buffer truncates — runs under hosted `cargo test`.

use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::cmsg::{self, Msg, SOL_IPV6};
use crate::sock_opts::sol_socket::OptCaps;

/// `SOL_SOCKET` as a control-message level.
pub const SOL_SOCKET: i32 = 1;

/// The ceiling a written stream may not exceed. Two kilobytes per standard
/// header is sixteen kilobytes, so the limit is generous rather than tight.
pub const PKTOPTIONS_MAX: u32 = 64 * 1024;

/// `sizeof(struct ipv6_opt_hdr)`: a next-header byte and a length byte.
const OPT_HDR_SIZE: usize = 2;
/// `sizeof(struct ipv6_rt_hdr)`: next header, length, type, segments left.
const RT_HDR_SIZE: usize = 4;
/// The one routing-header type a send-control stream may carry — NOT the
/// segment-routing type the sticky `IPV6_RTHDR` write admits.
const SRCRT_TYPE_2: u8 = 2;
/// Type-2 routing headers are fixed: one 16-byte address, one segment left.
const SRCRT_TYPE_2_HDRLEN: u8 = 2;
const SRCRT_TYPE_2_SEGMENTS: u8 = 1;

/// The four sticky transmit headers a written stream settles, in wire order.
///
/// A stream REPLACES the socket's whole sticky header block: a slot the stream
/// did not name ends up empty, exactly as a zero-length write clears all four.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Slots {
    /// Hop-by-hop options.
    pub hop: Option<Vec<u8>>,
    /// Destination options placed BEFORE the routing header.
    pub dst_before_routing: Option<Vec<u8>>,
    pub routing: Option<Vec<u8>>,
    /// Destination options placed AFTER the routing header.
    pub dst_after_routing: Option<Vec<u8>>,
}

/// Whether a written stream's length is admissible. # C: O(1)
pub fn admit_len(optlen: u32) -> Result<(), Errno> {
    if optlen > PKTOPTIONS_MAX { return Err(Errno::Einval); }
    Ok(())
}

/// Admit one written ancillary stream and settle the sticky headers it names.
///
/// `entries` is the walked stream as `(level, type, payload)`. Levels this
/// option does not own are stepped over — including `SOL_SOCKET`, whose
/// messages carry per-send state that no sticky block retains — and an
/// unknown type at THIS level fails the whole write rather than being ignored.
///
/// The scalar messages are validated and then discarded: a hop limit, traffic
/// class, flow label, packet-info or fragmentation choice named here describes
/// one datagram, and this write installs no datagram.
/// # C: O(stream bytes)
pub fn admit_stream<'a, I>(entries: I, caps: OptCaps) -> Result<Slots, Errno>
where I: IntoIterator<Item = (i32, i32, &'a [u8])>
{
    let mut out = Slots::default();
    for (level, kind, data) in entries {
        if level == SOL_SOCKET || level != SOL_IPV6 { continue; }
        admit_one(kind, data, caps, &mut out)?;
    }
    Ok(out)
}

/// One message of a written stream. # C: O(len)
fn admit_one(kind: i32, data: &[u8], caps: OptCaps, out: &mut Slots) -> Result<(), Errno> {
    match kind {
        // Validated then dropped: the sticky block holds no per-datagram state.
        cmsg::IPV6_PKTINFO | cmsg::IPV6_2292PKTINFO => {
            if data.len() < crate::sock_opts::sol_ipv6::uapi::IN6_PKTINFO_SIZE {
                return Err(Errno::Einval);
            }
        }
        cmsg::IPV6_FLOWINFO => { if data.len() < 4 { return Err(Errno::Einval); } }
        // These three are the only messages screened for an EXACT `int`.
        cmsg::IPV6_HOPLIMIT | cmsg::IPV6_2292HOPLIMIT => { int_in(data, -1, 255)?; }
        cmsg::IPV6_TCLASS => { int_in(data, -1, 255)?; }
        IPV6_DONTFRAG_CMSG => { int_in(data, 0, 1)?; }

        cmsg::IPV6_HOPOPTS | cmsg::IPV6_2292HOPOPTS => {
            // A second hop-by-hop header is refused rather than replacing the
            // first — the only slot with that rule under BOTH numbers.
            if out.hop.is_some() { return Err(Errno::Einval); }
            out.hop = Some(ext_header(data, caps)?);
        }
        cmsg::IPV6_2292DSTOPTS => {
            let header = ext_header(data, caps)?;
            if out.dst_after_routing.is_some() { return Err(Errno::Einval); }
            out.dst_after_routing = Some(header);
        }
        cmsg::IPV6_DSTOPTS => { out.dst_after_routing = Some(ext_header(data, caps)?); }
        IPV6_RTHDRDSTOPTS_CMSG => { out.dst_before_routing = Some(ext_header(data, caps)?); }
        cmsg::IPV6_RTHDR | cmsg::IPV6_2292RTHDR => {
            out.routing = Some(routing_header(data)?);
            // Under the older number a destination-options header already seen
            // belongs BEFORE the routing header, so it moves slots.
            if kind == cmsg::IPV6_2292RTHDR {
                if let Some(header) = out.dst_after_routing.take() {
                    out.dst_before_routing = Some(header);
                }
            }
        }
        _ => return Err(Errno::Einval),
    }
    Ok(())
}

/// `IPV6_RTHDRDSTOPTS` as a control-message number.
const IPV6_RTHDRDSTOPTS_CMSG: i32 = 55;
/// `IPV6_DONTFRAG` as a control-message number.
const IPV6_DONTFRAG_CMSG: i32 = 62;

/// The messages screened for an exact `int` operand inside a stated window.
/// # C: O(1)
fn int_in(data: &[u8], min: i32, max: i32) -> Result<i32, Errno> {
    if data.len() != 4 { return Err(Errno::Einval); }
    let value = i32::from_ne_bytes(data[..4].try_into().unwrap());
    if value < min || value > max { return Err(Errno::Einval); }
    Ok(value)
}

/// A hop-by-hop or destination-options header: the declared length may not
/// exceed the supplied bytes, and constructing one at all is privileged.
/// The privilege check runs AFTER the shape screen. # C: O(len)
fn ext_header(data: &[u8], caps: OptCaps) -> Result<Vec<u8>, Errno> {
    if data.len() < OPT_HDR_SIZE { return Err(Errno::Einval); }
    let len = (data[1] as usize + 1) << 3;
    if data.len() < len { return Err(Errno::Einval); }
    if !caps.net_raw { return Err(Errno::Eperm); }
    Ok(Vec::from(&data[..len]))
}

/// A routing header carried by a send-control stream: only the type-2 form,
/// whose length and segment count are both fixed, and whose declared length
/// must be covered by the supplied bytes. Unprivileged, unlike the options
/// headers. # C: O(len)
fn routing_header(data: &[u8]) -> Result<Vec<u8>, Errno> {
    if data.len() < RT_HDR_SIZE { return Err(Errno::Einval); }
    if data[2] != SRCRT_TYPE_2 { return Err(Errno::Einval); }
    if data[1] != SRCRT_TYPE_2_HDRLEN || data[3] != SRCRT_TYPE_2_SEGMENTS {
        return Err(Errno::Einval);
    }
    let len = (data[1] as usize + 1) << 3;
    if data.len() < len { return Err(Errno::Einval); }
    // The segment count must also agree with the declared length.
    if data[1] >> 1 != data[3] { return Err(Errno::Einval); }
    Ok(Vec::from(&data[..len]))
}

/// The socket state the READ side synthesises its answer from, when the socket
/// holds no stashed receive snapshot to walk.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Published {
    /// `IPV6_RECVPKTINFO`.
    pub rxinfo: bool,
    /// `IPV6_RECVHOPLIMIT`.
    pub rxhlim: bool,
    /// `IPV6_RECVTCLASS`.
    pub rxtclass: bool,
    /// `IPV6_2292PKTINFO`.
    pub rxoinfo: bool,
    /// `IPV6_2292HOPLIMIT`.
    pub rxohlim: bool,
    /// `IPV6_FLOWINFO`.
    pub rxflow: bool,
    /// `IPV6_MULTICAST_IF`; when set it answers BOTH packet-info fields.
    pub mcast_oif: u32,
    pub sticky_addr: [u8; 16],
    pub sticky_ifindex: u32,
    /// The connected peer, which the multicast interface's answer names.
    pub daddr: [u8; 16],
    pub mcast_hops: i32,
    /// `IPV6_FLOWINFO` as received, in host order.
    pub rcv_flowinfo: u32,
}

/// `ip6_tclass`: the traffic-class byte inside a flow-info word. # C: O(1)
pub fn tclass_of(flowinfo: u32) -> i32 { ((flowinfo & 0x0ff0_0000) >> 20) as i32 }

/// The messages a read publishes when the socket stashed no receive snapshot.
///
/// The two personalities are BOTH answered, from the same state, each under
/// its own receive bit: the modern numbering for packet info, hop limit and
/// traffic class, the RFC 2292 numbering for the packet info and hop limit it
/// renumbered, and the flow label under its single number. A socket that
/// enabled both personalities gets the packet info twice, under both numbers.
/// # C: O(1)
pub fn published(s: &Published) -> Vec<Msg> {
    let mut out = Vec::new();
    let src_info = || {
        if s.mcast_oif != 0 { cmsg::payload::in6_pktinfo(s.daddr, s.mcast_oif) }
        else { cmsg::payload::in6_pktinfo(s.sticky_addr, s.sticky_ifindex) }
    };
    if s.rxinfo { out.push(Msg::raw(SOL_IPV6, cmsg::IPV6_PKTINFO, &src_info())); }
    if s.rxhlim { out.push(Msg::int(SOL_IPV6, cmsg::IPV6_HOPLIMIT, s.mcast_hops)); }
    if s.rxtclass {
        out.push(Msg::int(SOL_IPV6, cmsg::IPV6_TCLASS, tclass_of(s.rcv_flowinfo)));
    }
    if s.rxoinfo { out.push(Msg::raw(SOL_IPV6, cmsg::IPV6_2292PKTINFO, &src_info())); }
    if s.rxohlim { out.push(Msg::int(SOL_IPV6, cmsg::IPV6_2292HOPLIMIT, s.mcast_hops)); }
    // The flow label rides back in network order, as it arrived.
    if s.rxflow {
        out.push(Msg::raw(SOL_IPV6, cmsg::IPV6_FLOWINFO, &s.rcv_flowinfo.to_be_bytes()));
    }
    out
}

#[cfg(test)]
mod tests;
