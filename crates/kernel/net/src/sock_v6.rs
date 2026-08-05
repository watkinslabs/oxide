// F180b: AF_INET6 connect helpers. Extracted from sock.rs for the
// 1000-line cap (docs/08§7). v6 UDP "connect" stashes the peer in
// the v6 peer slot; v6 TCP routes through tcp_connect_ip with a
// v1 source-address pick (LOOPBACK for ::1 else ANY).

use crate::netdev::NetError;
pub use crate::sock_v6_name::{name_bound_ifindex, name_scope_id};
use crate::sock::{
    InetSocket,
    alloc_ephemeral_udp6_owned, drain_loopback, stack,
};

/// v6 connect dispatch. # C: O(1) UDP, O(RTT) TCP.
pub(crate) fn connect_udp6_locked(sock: &InetSocket, local_port: &mut Option<u16>,
    dst_ip: crate::Ipv6Addr, port: u16, scope_id: u32) -> Result<(), NetError> {
    if sock.released.load(core::sync::atomic::Ordering::Acquire) {
        return Err(NetError::Einval);
    }
    let iface = scoped_iface(sock, dst_ip, scope_id)?;
    // Linux's mapped-IPv4 connect uses the IPv4 route and publishes its
    // selected source as a mapped IPv6 socket name before getsockname can
    // observe the socket. Leaving this as `::` violates getaddrinfo's
    // AF_INET-over-AF_INET6 conversion invariant.
    let mapped_source = dst_ip.to_v4_mapped()
        .map(|ip| mapped_v4_source(sock, ip, iface))
        .transpose()?;
    if local_port.is_none() {
        let policy = crate::sock::bind_port_policy(sock, 0);
        let (port, endpoint) = alloc_ephemeral_udp6_owned(
            sock.owner.clone(), mapped_source.map(crate::Ipv6Addr::from_v4_mapped)
                .unwrap_or_else(|| *sock.local_ip6.lock()), sock.error.clone(), iface,
            sock.opts.reuseaddr.clone(), sock.opts.reuseport.clone(),
            sock.opts.ipv6_v6only.clone(),
            sock.peer6.clone(), sock.opts.ip_mtu_discover.clone(),
            sock.opts.ipv6_mtu_discover.clone(), sock.opts.udp.no_check6_rx.clone(),
            sock.opts.udp.gro.clone(), sock.bpf_filter.clone(), sock.mcast.clone(),
            policy.range,
        ).map_err(|error| if error == NetError::Eaddrinuse { NetError::Eagain } else { error })?;
        endpoint.register_poll_subs(&sock.poll_subs);
        *sock.udp6.lock() = Some(endpoint);
        *local_port = Some(port);
    }
    if let Some(source) = mapped_source {
        *sock.local_ip6.lock() = crate::Ipv6Addr::from_v4_mapped(source);
    }
    *sock.peer6.lock() = Some((dst_ip, port));
    sock.peer6_scope.store(scope_id, core::sync::atomic::Ordering::Release);
    Ok(())
}

/// Resolve an IPv6 scope id to the interface a send leaves by. A zero scope
/// falls back to the socket's multicast or unicast interface; a non-zero one
/// must name a live interface in this namespace and must not fight the binding.
/// # C: O(1) lookup
pub(crate) fn scoped_iface(sock: &InetSocket, dst: crate::Ipv6Addr, scope_id: u32)
    -> Result<Option<crate::NetIfaceId>, NetError>
{
    if scope_id == 0 {
        return if dst.is_multicast() { crate::sock_mcast::bound_iface6(sock, dst) }
        else { crate::sock::iface::v6_egress_iface(sock) };
    }
    let iface = crate::NetIfaceId::from_raw(scope_id);
    let net_ns = sock.net_ns();
    if stack().ifaces.lookup_in_ns(iface, net_ns).is_none() { return Err(NetError::Enodev); }
    let bound = sock.opts.bound_ifindex.load(core::sync::atomic::Ordering::Acquire);
    if bound != 0 && bound != scope_id { return Err(NetError::Enodev); }
    Ok(Some(iface))
}

/// Apply sticky `IPV6_PKTINFO` after the explicit scope/device choice. # C: O(1)
fn sticky_pktinfo_choice(local: crate::Ipv6Addr, sticky: ([u8; 16], u32),
                         explicit: Option<crate::NetIfaceId>)
    -> (crate::Ipv6Addr, Option<crate::NetIfaceId>)
{
    let source = crate::Ipv6Addr(sticky.0);
    let source = if source.is_unspecified() { local } else { source };
    let iface = explicit.or_else(|| (sticky.1 != 0).then(|| crate::NetIfaceId::from_raw(sticky.1)));
    (source, iface)
}

/// Resolve the outbound hop limit for a v6 datagram from the socket's
/// IPV6_MULTICAST_HOPS (multicast dst) or IPV6_UNICAST_HOPS (unicast dst).
/// The `-1` sentinel means "unset" → Linux default: 1 for multicast,
/// `IPV6_DEFAULT_HOP_LIMIT` for unicast. # C: O(1)
fn resolve_v6_hop_limit(sock: &InetSocket, dst_ip: crate::Ipv6Addr) -> u8 {
    use core::sync::atomic::Ordering;
    crate::inet_tx::ipv6_hop_limit(sock.opts.ipv6_mcast_hops.load(Ordering::Acquire),
        sock.opts.ipv6_ucast_hops.load(Ordering::Acquire), dst_ip.is_multicast())
}

/// Resolve the outbound traffic class for a v6 datagram from the socket's
/// sticky IPV6_TCLASS. The `-1` sentinel means "unset" → Linux default 0.
/// Unlike hop limit, traffic class does not depend on multicast. # C: O(1)
fn resolve_v6_tclass(sock: &InetSocket) -> u8 {
    crate::inet_tx::ipv6_tclass(sock.opts.ipv6_tclass.load(core::sync::atomic::Ordering::Acquire))
}

/// Raw IPv6 send with socket scope, PMTU, and protocol-override state. # C: O(payload + N)
pub(crate) fn sendto_raw6(sock: &InetSocket, endpoint: &crate::raw6::Raw6Endpoint,
    dst_ip: crate::Ipv6Addr, dst_protocol: Option<u16>, scope_id: u32,
    payload: &[u8], control: &crate::send_control::Raw6Control) -> Result<usize, NetError>
{
    let protocol_override = if endpoint.protocol() == crate::addr::IpProto::Raw as u8
        && !endpoint.header_included()
    {
        match dst_protocol {
            Some(protocol) if protocol <= u8::MAX as u16 => Some(protocol as u8),
            Some(_) => return Err(NetError::Einval),
            None => None,
        }
    } else { None };
    xmit_raw6_with_sticky(sock, endpoint, dst_ip, protocol_override, scope_id, payload, control)?;
    // Transmit and receive must not share a frame: the loopback pass below re-enters the
    // whole receive stack, and the sticky-option merge above holds a cloned `Raw6Control`
    // plus the transmit argument block the whole way down.
    drain_loopback();
    Ok(payload.len())
}

/// Apply the socket's sticky IPv6 options to one message's control block.
///
/// `#[inline(never)]`: cloning a `Raw6Control` materialises four optional
/// extension-header vectors, and those temporaries have no business living in the
/// transmit frame that follows.
/// # C: O(control bytes)
#[inline(never)]
fn merge_sticky_raw6_control(sock: &InetSocket, control: &crate::send_control::Raw6Control)
    -> crate::send_control::Raw6Control
{
    let mut effective = control.clone();
    if effective.multicast_loop.is_none() {
        effective.multicast_loop = Some(
            sock.opts.ipv6_mcast_loop.load(core::sync::atomic::Ordering::Acquire) != 0);
    }
    // Linux tclass precedence: per-message IPV6_TCLASS cmsg > sticky
    // IPV6_TCLASS > flowinfo tclass byte. Inject the sticky value only when
    // it is set (>= 0) and no cmsg carried one, leaving the flowinfo fallback
    // (raw.rs) intact when the socket option is unset.
    if effective.traffic_class.is_none() {
        let sticky = sock.opts.ipv6_tclass.load(core::sync::atomic::Ordering::Acquire);
        if sticky >= 0 { effective.traffic_class = Some(sticky); }
    }
    if effective.source.is_none() {
        let (addr, _) = sock.opts.ipv6.sticky_pktinfo();
        let addr = crate::Ipv6Addr(addr);
        if !addr.is_unspecified() { effective.source = Some(addr); }
    }
    effective
}

/// Merge sticky socket options into the per-message control block and transmit.
/// Split out of `sendto_raw6` so the merged control never occupies the frame that
/// continues into the loopback receive pass (Linux `noinline_for_stack`).
/// # C: O(payload)
#[inline(never)]
fn xmit_raw6_with_sticky(sock: &InetSocket, endpoint: &crate::raw6::Raw6Endpoint,
    dst_ip: crate::Ipv6Addr, protocol_override: Option<u8>, scope_id: u32,
    payload: &[u8], control: &crate::send_control::Raw6Control) -> Result<(), NetError>
{
    let hop = resolve_v6_hop_limit(sock, dst_ip);
    let pmtudisc = sock.opts.ipv6_mtu_discover.load(core::sync::atomic::Ordering::Acquire);
    let effective = merge_sticky_raw6_control(sock, control);
    let scoped = if control.iface.is_some() && scope_id == 0 {
        crate::sock::bound_iface(sock)?
    } else { scoped_iface(sock, dst_ip, scope_id)? };
    let (_, scoped) = sticky_pktinfo_choice(crate::Ipv6Addr::ANY,
        sock.opts.ipv6.sticky_pktinfo(), scoped);
    stack().send_raw6_with_frag_size(endpoint, dst_ip, scoped,
        protocol_override, payload, hop, pmtudisc, sock.opts.ipv6.frag_size(), &effective)
}

fn ensure_udp6_bound(sock: &InetSocket, dst_ip: crate::Ipv6Addr, scope_id: u32)
    -> Result<u16, NetError>
{
    let src_port = {
        let mut slot = sock.local_port.lock();
        if sock.released.load(core::sync::atomic::Ordering::Acquire) {
            return Err(NetError::Einval);
        }
        match *slot {
            Some(p) => p,
            None    => {
                // Linux `inet6_autobind` keeps the local address already named.
                let bind_ip = *sock.local_ip6.lock();
                let policy = crate::sock::bind_port_policy(sock, 0);
                let (p, endpoint) = alloc_ephemeral_udp6_owned(
                    sock.owner.clone(), bind_ip, sock.error.clone(),
                    scoped_iface(sock, dst_ip, scope_id)?,
                    sock.opts.reuseaddr.clone(), sock.opts.reuseport.clone(),
                    sock.opts.ipv6_v6only.clone(),
                    sock.peer6.clone(), sock.opts.ip_mtu_discover.clone(),
                    sock.opts.ipv6_mtu_discover.clone(), sock.opts.udp.no_check6_rx.clone(),
                    sock.opts.udp.gro.clone(), sock.bpf_filter.clone(), sock.mcast.clone(),
                    policy.range,
                ).map_err(|error| if error == NetError::Eaddrinuse { NetError::Eagain } else { error })?;
                endpoint.register_poll_subs(&sock.poll_subs);
                *sock.udp6.lock() = Some(endpoint);
                *slot = Some(p);
                p
            }
        }
    };
    Ok(src_port)
}

fn sendto_v4_mapped(sock: &InetSocket, dst_ip: crate::Ipv4Addr, dst_port: u16,
                    payload: &[u8]) -> Result<usize, NetError> {
    if crate::udp::udp4_payload_too_large(payload.len()) { return Err(NetError::Emsgsize); }
    let src_port = ensure_udp6_bound(sock, crate::Ipv6Addr::from_v4_mapped(dst_ip), 0)?;
    let bound = if dst_ip.is_multicast() {
        crate::sock_mcast::bound_iface(sock, dst_ip)?
    } else {
        crate::sock::bound_iface(sock)?
    };
    let src_ip = mapped_v4_source(sock, dst_ip, bound)?;
    let multicast_loop = sock.opts.ip_mcast_loop.load(
        core::sync::atomic::Ordering::Acquire,
    ) != 0;
    if dst_ip.is_multicast() && !multicast_loop
        && crate::sock_mcast::is_loopback_iface(bound)
    {
        return Ok(payload.len());
    }
    // A v4-mapped destination leaves as an IPv4 datagram, so an unset hop
    // budget is the sentinel the IPv4 transmit path resolves against the
    // route, and the checksum suppression is the IPv4 one.
    let ttl = if dst_ip.is_multicast() {
        sock.opts.ip_mcast_ttl.load(core::sync::atomic::Ordering::Acquire) as u8
    } else {
        let ttl = sock.opts.ip_ttl.load(core::sync::atomic::Ordering::Acquire);
        if ttl < 0 { 0 } else { ttl as u8 }
    };
    stack().send_udp_pmtu_to_bound_opts_owned(
        &sock.owner, src_ip, src_port, dst_ip, dst_port, payload, bound,
        sock.opts.ip_tos.load(core::sync::atomic::Ordering::Acquire) as u8, ttl,
        sock.opts.ip_mtu_discover.load(core::sync::atomic::Ordering::Acquire),
        sock.opts.ip.options().as_ref(),
        sock.opts.generic.flag(crate::sock_opts::sol_socket::flag::NO_CHECK_TX),
    )?;
    if !dst_ip.is_multicast() || multicast_loop { drain_loopback(); }
    Ok(payload.len())
}

/// Choose the IPv4 source shared by mapped IPv6 `connect` and `sendto`.
/// # C: O(route lookup)
fn mapped_v4_source(sock: &InetSocket, dst_ip: crate::Ipv4Addr,
                    bound: Option<crate::NetIfaceId>) -> Result<crate::Ipv4Addr, NetError> {
    let local = *sock.local_ip6.lock();
    if let Some(ip) = local.to_v4_mapped() { return Ok(ip); }
    if local != crate::Ipv6Addr::ANY { return Err(NetError::Eaddrnotavail); }
    if dst_ip.is_multicast() { return Ok(crate::sock_mcast::src_ip(sock, dst_ip, bound)); }
    if dst_ip.is_loopback() { return Ok(crate::Ipv4Addr::LOOPBACK); }
    let net_ns = sock.net_ns();
    Ok(stack().routes.lookup_in(net_ns, dst_ip).and_then(|route| route.src_hint)
        .or_else(|| crate::sock::iface_primary_ip(
            bound.or_else(|| stack().routes.lookup_in(net_ns, dst_ip).map(|route| route.iface)),
        ))
        .unwrap_or(crate::Ipv4Addr::LOOPBACK))
}

/// F180b: AF_INET6 datagram sendto. Allocates an ephemeral src port
/// on demand; routes via the selected IP family. # C: O(payload)
pub fn sendto_v6(sock: &InetSocket,
                  dst_ip: crate::Ipv6Addr, dst_port: u16,
                  scope_id: u32,
                  payload: &[u8]) -> Result<usize, NetError> {
    let eno = sock.take_pending_recv_error();
    if eno != 0 { return Err(crate::sock_error::pending_net_error(eno)); }
    crate::inet_tx::validate_udp6_mapped_destination(
        dst_ip,
        sock.opts.ipv6_v6only.load(core::sync::atomic::Ordering::Acquire) != 0,
    )?;
    if let Some(dst_ip) = dst_ip.to_v4_mapped() {
        return sendto_v4_mapped(sock, dst_ip, dst_port, payload);
    }
    if crate::udp::udp6_payload_too_large(payload.len()) { return Err(NetError::Emsgsize); }
    let src_port = ensure_udp6_bound(sock, dst_ip, scope_id)?;
    let sticky = sock.opts.ipv6.sticky_pktinfo();
    let hop = resolve_v6_hop_limit(sock, dst_ip);
    let tclass = resolve_v6_tclass(sock);
    let pmtudisc = sock.opts.ipv6_mtu_discover.load(core::sync::atomic::Ordering::Acquire);
    let frag_size = sock.opts.ipv6.frag_size();
    // Linux gives the explicit scope/device choice precedence, then applies
    // sticky IPV6_PKTINFO's output interface before route lookup.
    let (src_ip, iface) = sticky_pktinfo_choice(*sock.local_ip6.lock(), sticky,
        scoped_iface(sock, dst_ip, scope_id)?);
    let iface = match iface {
        Some(iface) if sticky.1 != 0 && iface.raw() == sticky.1 => {
            if stack().ifaces.lookup_in_ns(iface, sock.net_ns()).is_none() {
                return Err(NetError::Enodev);
            }
            Some(iface)
        }
        other => other,
    };
    let no_check = sock.opts.udp.no_check6_tx();
    // UDP_SEGMENT: one write becomes N wire datagrams of the segmentation
    // size, the last carrying the remainder.
    let gso = sock.opts.udp.gso_size();
    if gso != 0 {
        let mtu = stack().path_mtu_in(
            sock.net_ns(), crate::addr::IpAddr::V6(dst_ip), iface, false)? as usize;
        if let Some(plan) = crate::sock_opts::sol_udp::segment::plan_v6(
            payload.len(), gso, mtu, no_check)?
        {
            for segment in payload.chunks(plan.seg_size) {
                stack().send_udp6_pmtu_to_bound_opts_owned(
                    &sock.owner, src_ip, src_port, dst_ip, dst_port, segment, iface, hop, tclass,
                    pmtudisc, frag_size, no_check,
                )?;
            }
            drain_loopback();
            return Ok(payload.len());
        }
    }
    stack().send_udp6_pmtu_to_bound_opts_owned(
        &sock.owner, src_ip, src_port, dst_ip, dst_port, payload,
        iface, hop, tclass, pmtudisc, frag_size, no_check,
    )?;
    drain_loopback();
    Ok(payload.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sticky_pktinfo_selects_source_and_interface_unless_explicitly_bound() {
        let local = crate::Ipv6Addr::LOOPBACK;
        let sticky = crate::Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 9]);
        let (source, iface) = sticky_pktinfo_choice(local, (sticky.0, 7), None);
        assert_eq!(source, sticky);
        assert_eq!(iface, Some(crate::NetIfaceId::from_raw(7)));
        let (source, iface) = sticky_pktinfo_choice(local, (sticky.0, 7),
            Some(crate::NetIfaceId::from_raw(3)));
        assert_eq!(source, sticky);
        assert_eq!(iface, Some(crate::NetIfaceId::from_raw(3)));
    }

    #[test]
    fn zero_scope_uses_ipv6_unicast_interface_before_route_lookup() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let owner = crate::net_ns::test_support::allocate_namespace();
        let ns = owner.id().as_u64();
        let iface = stack().ifaces.register_in_ns(alloc::sync::Arc::new(crate::LoopbackDev::new()), ns);
        let sock = InetSocket::new_udp_in(owner);
        let ifindex = stack().ifaces.ifindex_in_ns(iface, ns).unwrap();
        sock.opts.ipv6.set_unicast_if(ifindex);
        assert_eq!(scoped_iface(&sock, crate::Ipv6Addr::LOOPBACK, 0), Ok(Some(iface)));
    }
}
