// F180b: AF_INET6 connect helpers. Extracted from sock.rs for the
// 1000-line cap (docs/08§7). v6 UDP "connect" stashes the peer in
// the v6 peer slot; v6 TCP routes through tcp_connect_ip with a
// v1 source-address pick (LOOPBACK for ::1 else ANY).

use crate::netdev::NetError;
use crate::sock::{
    InetSocket,
    alloc_ephemeral_udp6_owned, drain_loopback, stack,
};

const IPV6_MULTICAST_SCOPE_MASK: u8 = 0x0f;
const IPV6_SCOPE_LINK_LOCAL: u8 = 2;
const IPV6_SCOPE_OCTET: usize = 1;
const IPV6_NO_SCOPE_ID: u32 = 0;

/// Linux `ipv6_iface_scope_id`: expose a device only for interface- or
/// link-scoped addresses, never for global IPv6 addresses. # C: O(1)
pub fn name_scope_id(address: crate::Ipv6Addr, bound_ifindex: u32) -> u32 {
    let multicast_scope = address.is_multicast()
        && (address.0[IPV6_SCOPE_OCTET] & IPV6_MULTICAST_SCOPE_MASK) <= IPV6_SCOPE_LINK_LOCAL;
    if address.is_link_local() || multicast_scope { bound_ifindex } else { IPV6_NO_SCOPE_ID }
}

/// Resolve the device recorded by the live IPv6 transport owner for a name
/// query. A socket-level SO_BINDTODEVICE setting is authoritative before an
/// endpoint exists; otherwise the endpoint/reservation owns the binding.
/// # C: O(1)
pub fn name_bound_ifindex(sock: &InetSocket) -> u32 {
    use core::sync::atomic::Ordering;
    let configured = sock.opts.bound_ifindex.load(Ordering::Acquire);
    if configured != IPV6_NO_SCOPE_ID { return configured; }
    if let Some(endpoint) = sock.udp6.lock().as_ref().cloned() {
        return endpoint.bound_ifindex.load(Ordering::Acquire);
    }
    sock.tcp_bind.lock().as_ref().and_then(|bind| bind.bound_iface())
        .map(crate::NetIfaceId::raw).unwrap_or(IPV6_NO_SCOPE_ID)
}

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
        let (port, endpoint) = alloc_ephemeral_udp6_owned(
            sock.owner.clone(), mapped_source.map(crate::Ipv6Addr::from_v4_mapped)
                .unwrap_or(crate::Ipv6Addr::ANY), sock.error.clone(), iface,
            sock.opts.reuseaddr.clone(), sock.opts.reuseport.clone(),
            sock.opts.ipv6_v6only.clone(),
            sock.peer6.clone(), sock.opts.ip_mtu_discover.clone(),
            sock.opts.ipv6_mtu_discover.clone(),
            sock.bpf_filter.clone(), sock.mcast.clone(),
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

/// Reject a mapped IPv6 datagram destination on an IPV6_V6ONLY socket. # C: O(1)
pub(crate) fn validate_udp6_mapped_destination(dst_ip: crate::Ipv6Addr, v6only: bool)
    -> Result<(), NetError>
{
    if v6only && dst_ip.to_v4_mapped().is_some() { Err(NetError::Enetunreach) }
    else { Ok(()) }
}

/// Select native TCP6 or mapped TCP4 after CONNECT6 policy ran. # C: O(1)
pub(crate) fn tcp6_mapped_destination(dst_ip: crate::Ipv6Addr, v6only: bool)
    -> Result<Option<crate::Ipv4Addr>, NetError>
{
    let Some(dst_ip) = dst_ip.to_v4_mapped() else { return Ok(None); };
    if v6only { Err(NetError::Enetunreach) } else { Ok(Some(dst_ip)) }
}

pub(crate) fn scoped_iface(sock: &InetSocket, dst: crate::Ipv6Addr, scope_id: u32)
    -> Result<Option<crate::NetIfaceId>, NetError>
{
    if scope_id == 0 { return crate::sock_mcast::bound_iface6(sock, dst); }
    let iface = crate::NetIfaceId::from_raw(scope_id);
    let net_ns = sock.net_ns();
    if stack().ifaces.lookup_in_ns(iface, net_ns).is_none() { return Err(NetError::Enodev); }
    let bound = sock.opts.bound_ifindex.load(core::sync::atomic::Ordering::Acquire);
    if bound != 0 && bound != scope_id { return Err(NetError::Enodev); }
    Ok(Some(iface))
}

/// Resolve the outbound hop limit for a v6 datagram from the socket's
/// IPV6_MULTICAST_HOPS (multicast dst) or IPV6_UNICAST_HOPS (unicast dst).
/// The `-1` sentinel means "unset" → Linux default: 1 for multicast,
/// `IPV6_DEFAULT_HOP_LIMIT` for unicast. # C: O(1)
fn resolve_v6_hop_limit(sock: &InetSocket, dst_ip: crate::Ipv6Addr) -> u8 {
    use core::sync::atomic::Ordering;
    if dst_ip.is_multicast() {
        let h = sock.opts.ipv6_mcast_hops.load(Ordering::Acquire);
        if h < 0 { 1 } else { h as u8 }
    } else {
        let h = sock.opts.ipv6_ucast_hops.load(Ordering::Acquire);
        if h < 0 { crate::ipv6::IPV6_DEFAULT_HOP_LIMIT } else { h as u8 }
    }
}

/// Resolve the outbound traffic class for a v6 datagram from the socket's
/// sticky IPV6_TCLASS. The `-1` sentinel means "unset" → Linux default 0.
/// Unlike hop limit, traffic class does not depend on multicast. # C: O(1)
fn resolve_v6_tclass(sock: &InetSocket) -> u8 {
    use core::sync::atomic::Ordering;
    let t = sock.opts.ipv6_tclass.load(Ordering::Acquire);
    if t < 0 { 0 } else { t as u8 }
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
    let hop = resolve_v6_hop_limit(sock, dst_ip);
    let pmtudisc = sock.opts.ipv6_mtu_discover.load(core::sync::atomic::Ordering::Acquire);
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
    let scoped = if control.iface.is_some() && scope_id == 0 {
        crate::sock::bound_iface(sock)?
    } else { scoped_iface(sock, dst_ip, scope_id)? };
    stack().send_raw6(endpoint, dst_ip, scoped,
        protocol_override, payload, hop, pmtudisc, &effective)?;
    drain_loopback();
    Ok(payload.len())
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
                let (p, endpoint) = alloc_ephemeral_udp6_owned(
                    sock.owner.clone(), crate::Ipv6Addr::ANY, sock.error.clone(),
                    scoped_iface(sock, dst_ip, scope_id)?,
                    sock.opts.reuseaddr.clone(), sock.opts.reuseport.clone(),
                    sock.opts.ipv6_v6only.clone(),
                    sock.peer6.clone(), sock.opts.ip_mtu_discover.clone(),
                    sock.opts.ipv6_mtu_discover.clone(),
                    sock.bpf_filter.clone(), sock.mcast.clone(),
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
    if eno != 0 { return Err(crate::sock_io::pending_net_error(eno)); }
    validate_udp6_mapped_destination(
        dst_ip,
        sock.opts.ipv6_v6only.load(core::sync::atomic::Ordering::Acquire) != 0,
    )?;
    if let Some(dst_ip) = dst_ip.to_v4_mapped() {
        return sendto_v4_mapped(sock, dst_ip, dst_port, payload);
    }
    if crate::udp::udp6_payload_too_large(payload.len()) { return Err(NetError::Emsgsize); }
    let src_port = ensure_udp6_bound(sock, dst_ip, scope_id)?;
    let src_ip = *sock.local_ip6.lock();
    let hop = resolve_v6_hop_limit(sock, dst_ip);
    let tclass = resolve_v6_tclass(sock);
    let pmtudisc = sock.opts.ipv6_mtu_discover.load(core::sync::atomic::Ordering::Acquire);
    stack().send_udp6_pmtu_to_bound_opts_owned(
        &sock.owner, src_ip, src_port, dst_ip, dst_port, payload,
        scoped_iface(sock, dst_ip, scope_id)?, hop, tclass, pmtudisc,
    )?;
    drain_loopback();
    Ok(payload.len())
}

#[cfg(test)]
mod tests {
    #[test]
    fn v6only_mapped_udp_destination_is_network_unreachable_before_send() {
        let mapped = crate::Ipv6Addr::from_v4_mapped(
            crate::Ipv4Addr::new(192, 0, 2, 1),
        );
        assert_eq!(
            super::validate_udp6_mapped_destination(mapped, true),
            Err(crate::NetError::Enetunreach),
        );
        assert_eq!(super::validate_udp6_mapped_destination(mapped, false), Ok(()));
        assert_eq!(
            super::validate_udp6_mapped_destination(crate::Ipv6Addr::LOOPBACK, true),
            Ok(()),
        );
        let sock = crate::sock::InetSocket::new_udp6();
        sock.opts.ipv6_v6only.store(1, core::sync::atomic::Ordering::Release);
        assert_eq!(
            super::sendto_v6(&sock, mapped, 53, 0, b"query"),
            Err(crate::NetError::Enetunreach),
        );
        assert!(sock.local_port.lock().is_none());
    }

    #[test]
    fn mapped_tcp_destination_selects_tcp4_unless_v6only() {
        let mapped_ip = crate::Ipv4Addr::new(198, 51, 100, 7);
        let mapped = crate::Ipv6Addr::from_v4_mapped(mapped_ip);
        assert_eq!(
            super::tcp6_mapped_destination(mapped, true),
            Err(crate::NetError::Enetunreach),
        );
        assert_eq!(
            super::tcp6_mapped_destination(mapped, false),
            Ok(Some(mapped_ip)),
        );
        assert_eq!(
            super::tcp6_mapped_destination(crate::Ipv6Addr::LOOPBACK, false),
            Ok(None),
        );
    }
}
