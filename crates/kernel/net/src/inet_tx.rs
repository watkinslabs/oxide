// Outbound datagram parameter selection, shared by the IPv4 UDP, IPv6 UDP, and
// raw send paths.
//
// Every rule here used to sit inside a `#[cfg(target_os = "oxide-kernel")]`
// file (`sock/udp.rs`, `sock/send.rs`, `sock_v6.rs`), where a `#[cfg(test)]`
// block compiles away in silence — `sock_v6.rs` shipped one that had never
// executed. The rules are pure functions of stored option values and the
// destination address, so they belong out here where a test reaches them.
//
// Three families of rule live here:
//
// - the socket-option "unset" sentinel: hop limit, TTL, and traffic class are
//   stored as `i32` where a negative value means "the caller never set this",
//   and each has its own default — 1 for a multicast hop limit, the IPv6
//   default for a unicast one, 0 for a traffic class;
// - source-address selection for a socket bound to the wildcard, which is a
//   CHOICE of where to look, not the lookup itself: the caller still resolves
//   the multicast or route answer with the state only it holds;
// - multicast loopback: a multicast send out the loopback interface with
//   `IP_MULTICAST_LOOP` off is accepted and delivered nowhere, and the
//   loopback drain that lets an immediate receive on the same socket see a
//   datagram runs for everything EXCEPT that suppressed case.
//
// Ungated on purpose: this is the decision logic, and a target-gated module
// would compile its tests away silently.

use crate::{Ipv4Addr, Ipv6Addr, NetError};

/// Where an outbound IPv4 datagram takes its source address from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceChoice {
    /// The socket is bound to a specific address; it wins outright.
    Bound(Ipv4Addr),
    /// A multicast destination: the multicast source rule answers.
    Multicast,
    /// A loopback destination reached from the wildcard.
    Loopback,
    /// Anything else: the route to the destination names the source.
    Route,
}

/// Source selection for a socket bound to `bound`. A wildcard-bound socket
/// that sent every datagram from the loopback address could never be answered
/// by a remote peer, so the wildcard case consults the destination.
/// # C: O(1)
pub fn source_choice(bound: Ipv4Addr, dst: Ipv4Addr) -> SourceChoice {
    if bound != Ipv4Addr::ANY { return SourceChoice::Bound(bound); }
    if dst.is_multicast() { return SourceChoice::Multicast; }
    if dst.is_loopback() { return SourceChoice::Loopback; }
    SourceChoice::Route
}

/// Outbound IPv4 TTL: a multicast destination takes `IP_MULTICAST_TTL`, any
/// other takes `IP_TTL`, whose negative sentinel means the caller never set it.
///
/// An unset unicast TTL is the default hop budget, not zero. A datagram sent
/// with TTL 0 is discarded by the first router, which answers ICMP Time
/// Exceeded — so a guest whose sockets all leave `IP_TTL` alone (every ordinary
/// program does) can reach nothing beyond its own link.
/// # C: O(1)
pub fn ipv4_ttl(mcast_ttl: i32, unicast_ttl: i32, multicast: bool) -> u8 {
    if multicast { return mcast_ttl as u8; }
    if unicast_ttl < 0 { crate::ipv4::IPV4_DEFAULT_TTL } else { unicast_ttl as u8 }
}

/// Outbound IPv6 hop limit: `IPV6_MULTICAST_HOPS` for a multicast destination,
/// `IPV6_UNICAST_HOPS` otherwise. The negative sentinel means unset, and the
/// two defaults differ. # C: O(1)
pub fn ipv6_hop_limit(mcast_hops: i32, unicast_hops: i32, multicast: bool) -> u8 {
    if multicast {
        if mcast_hops < 0 { 1 } else { mcast_hops as u8 }
    } else if unicast_hops < 0 { crate::ipv6::IPV6_DEFAULT_HOP_LIMIT } else { unicast_hops as u8 }
}

/// Outbound IPv6 traffic class. Unlike the hop limit this does not depend on
/// the destination, and its unset default is 0. # C: O(1)
pub fn ipv6_tclass(tclass: i32) -> u8 { if tclass < 0 { 0 } else { tclass as u8 } }

/// Whether a multicast send is accepted and delivered nowhere: loopback is the
/// only interface it could reach, and this socket turned loopback off.
/// # C: O(1)
pub fn multicast_delivers_nowhere(multicast: bool, mcast_loop: bool, loopback_iface: bool) -> bool {
    multicast && !mcast_loop && loopback_iface
}

/// Whether the send drains the loopback queue so an immediate receive on the
/// same socket sees the datagram. A multicast send with loopback off has
/// nothing to drain. # C: O(1)
pub fn drains_loopback(multicast: bool, mcast_loop: bool) -> bool { !multicast || mcast_loop }

/// Reject a mapped IPv6 destination on an `IPV6_V6ONLY` datagram socket. The
/// rejection lands BEFORE any ephemeral bind, so a refused send leaves the
/// socket exactly as it found it. # C: O(1)
pub fn validate_udp6_mapped_destination(dst_ip: Ipv6Addr, v6only: bool) -> Result<(), NetError> {
    if v6only && dst_ip.to_v4_mapped().is_some() { Err(NetError::Enetunreach) } else { Ok(()) }
}

/// Native IPv6 or mapped IPv4 for a stream destination. `Ok(None)` is native;
/// `Ok(Some(v4))` retargets the connection at the IPv4 stack. # C: O(1)
pub fn tcp6_mapped_destination(dst_ip: Ipv6Addr, v6only: bool)
    -> Result<Option<Ipv4Addr>, NetError>
{
    let Some(dst_ip) = dst_ip.to_v4_mapped() else { return Ok(None) };
    if v6only { Err(NetError::Enetunreach) } else { Ok(Some(dst_ip)) }
}

#[cfg(test)]
mod tests;
