// IPv6 transmit source selection for a socket that named none.
//
// Ungated on purpose. The connect path that consumes this lives in a
// target-gated file, so the DECISION lives here where a hosted test reaches it
// (`docs/53`); the gated caller only routes to it.

use super::{InetSocket, NetError};

/// The IPv6 source a wildcard-bound active open takes: the route's preferred
/// source when it names one, else address selection over the egress
/// interface, under the socket's `IPV6_ADDR_PREFERENCES`.
///
/// A connection's local address is settled at connect time — every segment it
/// ever sends carries that address verbatim — so leaving the wildcard in place
/// puts the unspecified address in the SYN's source field.
///
/// No route is `ENETUNREACH`; a route whose interface carries no usable
/// address is `EADDRNOTAVAIL`. There is no locality screen: IPv6 route output
/// never applies one to a source address, so a socket bound to a foreign
/// address answers from it with no permission consulted. # C: O(N_addrs)
pub(crate) fn v6_connect_source(sock: &InetSocket, dst_ip: crate::Ipv6Addr)
    -> Result<crate::Ipv6Addr, NetError>
{
    let net_ns = sock.net_ns();
    let stack = super::stack();
    let mark = super::sock_mark(sock);
    let iface = match super::iface::v6_egress_iface(sock)? {
        Some(id) => id,
        None => stack.routes6.lookup_policy_mark_in(net_ns, dst_ip, stack.policy_rules(), mark)
            .ok_or(NetError::Enetunreach)?.iface,
    };
    let hint = stack.routes6.lookup_policy_iface_mark_in(
        net_ns, dst_ip, iface, stack.policy_rules(), mark).and_then(|route| route.src_hint);
    stack.v6_select_source_with_prefs(iface, dst_ip, hint, sock.opts.ipv6.srcprefs())
        .ok_or(NetError::Eaddrnotavail)
}

#[cfg(test)]
mod tests;
