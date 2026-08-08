// One owner for everything the transparent-proxy socket permission decides
// beyond the bind screen: which received destinations reach a local socket,
// and which source addresses an outbound packet may carry.
//
// The permission is a single socket bit shared by both families — the
// `IPPROTO_IPV6` option number writes the very storage the `IPPROTO_IP` one
// does — so the decisions here are shared too. `crate::bind_screen` owns the
// bind half of the same bit; this module owns the delivery and transmit
// halves. Nothing caches the bit: callers reach the socket and ask.
//
// Ungated on purpose. These are pure functions of classification results, so a
// hosted test reaches them; a target-gated module would compile its tests away
// in silence.

use crate::bind_screen::SockNonlocal;
use crate::netdev::NetError;

/// Whether an outbound packet may carry a source address this host does not
/// own.
///
/// The transparent permission grants it — that is what lets a proxy answer a
/// client from the address the client addressed. A header-including raw socket
/// writes its own network header, so its source is never screened either.
/// A nonlocal-bind permission buys a bind and nothing more: a socket bound
/// nonlocally through `IP_FREEBIND` alone still has to source its packets from
/// an address the host owns.
/// # C: O(1)
pub fn any_source(sock: SockNonlocal, hdrincl: bool) -> bool { sock.transparent || hdrincl }

/// Local-input decision, shared by both address families.
///
/// Three ways a received destination is delivered rather than forwarded, in
/// the order the routing decision reaches them: an always-local class the
/// family names for itself (loopback, broadcast, a joined multicast group, an
/// owned anycast address), a route of local type covering the destination —
/// the transparent-proxy delivery shape, where policy routing deliberately
/// selects local input for an address no interface owns — and, last, an
/// address a live interface is configured with.
///
/// The route is consulted BEFORE the address table because an address the
/// namespace owns has a local route too, so the order changes no answer for
/// owned addresses while giving the routing decision the first word. Both
/// lookups are deferred so an always-local destination costs neither.
/// # C: O(1) plus whichever lookup runs
pub fn delivers_locally(always_local: bool, local_route: impl FnOnce() -> bool,
    owned: impl FnOnce() -> bool) -> bool
{
    always_local || local_route() || owned()
}

/// How the namespace classifies a candidate IPv4 SOURCE address for transmit.
/// The unspecified source is the caller declining to choose, which leaves the
/// choice to route selection. `Local` covers both an address configured on an
/// interface and one a local-table route makes local; everything else is
/// `Foreign` and needs the any-source permission.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum V4Source { Unspecified, Multicast, LimitedBroadcast, Local, Foreign }

/// Screen one explicit IPv4 source address at route-output time.
///
/// Verified ordering, which is not the obvious one:
///
/// - the unspecified source is always accepted; route selection fills it in;
/// - a multicast or limited-broadcast SOURCE is malformed and rejected with
///   `EINVAL` — the any-source permission does not excuse it;
/// - a destination that fans out (multicast, limited broadcast) with no
///   outbound interface pinned takes its interface FROM the source address, so
///   that source must be one the host owns; a foreign source leaves the send
///   with no interface to choose and is unreachable. The any-source permission
///   does not excuse this one either;
/// - otherwise a foreign source is accepted only with the any-source
///   permission, and is otherwise unreachable.
///
/// `ENETUNREACH`, not `EADDRNOTAVAIL`: the refusal is a routing failure, not
/// an address-availability one — the bind screen already had its say.
/// # C: O(1)
pub fn screen_v4_source(src: V4Source, dst_fans_out: bool, oif_pinned: bool, any_source: bool)
    -> Result<(), NetError>
{
    match src {
        V4Source::Unspecified => Ok(()),
        V4Source::Multicast | V4Source::LimitedBroadcast => Err(NetError::Einval),
        V4Source::Local => Ok(()),
        V4Source::Foreign if dst_fans_out && !oif_pinned => Err(NetError::Enetunreach),
        V4Source::Foreign if any_source => Ok(()),
        V4Source::Foreign => Err(NetError::Enetunreach),
    }
}

/// Classify an IPv4 source address against a live namespace. Locality reuses
/// the bind screen's classifier, so "an address this host owns" has exactly
/// one definition across bind and transmit. # C: O(N_addrs)
pub fn classify_v4_source(net_ns: u64, src: crate::Ipv4Addr) -> V4Source {
    if src.is_unspecified() { return V4Source::Unspecified; }
    if src.is_multicast() { return V4Source::Multicast; }
    if src.is_broadcast() { return V4Source::LimitedBroadcast; }
    match crate::bind_screen::classify_v4(net_ns, src, None) {
        crate::bind_screen::V4AddrType::Local => V4Source::Local,
        _ => V4Source::Foreign,
    }
}

/// Screen an IPv4 source address a socket transmit selected, against that
/// socket's live permission. One call site shape for every v4 socket send.
/// # C: O(N_addrs)
pub fn screen_v4_socket_source(net_ns: u64, src: crate::Ipv4Addr, dst: crate::Ipv4Addr,
    oif_pinned: bool, sock: SockNonlocal, hdrincl: bool) -> Result<(), NetError>
{
    screen_v4_source(classify_v4_source(net_ns, src),
        dst.is_multicast() || dst.is_broadcast(), oif_pinned, any_source(sock, hdrincl))
}

/// Whether an IPv6 source address a socket selected is used verbatim.
///
/// It always is. IPv6 route output never screens an explicit source for
/// locality — the family has no equivalent of the IPv4 owned-source test — so
/// a socket bound to a foreign address answers from that address with no
/// permission consulted, and no source-selection step may overwrite it. The
/// permission still gates the bind that produced the address.
/// # C: O(1)
pub fn v6_source_is_verbatim(src: crate::Ipv6Addr) -> bool { !src.is_unspecified() }

#[cfg(test)]
mod tests;
