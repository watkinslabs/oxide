// F180b: AF_INET6 connect helpers. Extracted from sock.rs for the
// 1000-line cap (docs/08§7). v6 UDP "connect" stashes the peer in
// the v6 peer slot; v6 TCP routes through tcp_connect_ip with a
// v1 source-address pick (LOOPBACK for ::1 else ANY).

use crate::netdev::NetError;
use crate::sock::{
    InetSocket, SockKind,
    alloc_ephemeral_udp6, drain_loopback, stack,
};
use crate::sock_opts::apply_tcp_keepalive_opts;

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
pub fn connect_v6(sock: &alloc::sync::Arc<InetSocket>,
                   dst_ip: crate::Ipv6Addr, port: u16, scope_id: u32,
                   nonblock: bool) -> Result<(), NetError> {
    if let SockKind::Raw6(endpoint) = &*sock.kind.lock() {
        let iface = scoped_iface(sock, dst_ip, scope_id)?;
        return endpoint.connect_routed(crate::raw6::Raw6Address::new(dst_ip, scope_id), iface);
    }
    {
        let kind = sock.kind.lock();
        match &*kind {
            SockKind::Udp => {
                drop(kind);
                let local_port = {
                    let mut slot = sock.local_port.lock();
                    if sock.released.load(core::sync::atomic::Ordering::Acquire) {
                        return Err(NetError::Einval);
                    }
                    match *slot {
                        Some(p) => p,
                        None    => {
                            let (p, endpoint) = alloc_ephemeral_udp6(
                                sock.net_ns(),
                                crate::Ipv6Addr::ANY, sock.error.clone(),
                                scoped_iface(sock, dst_ip, scope_id)?,
                                sock.opts.reuseaddr.clone(), sock.opts.reuseport.clone(),
                                sock.owner_uid,
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
                *sock.peer6.lock() = Some((dst_ip, port));
                sock.peer6_scope.store(scope_id, core::sync::atomic::Ordering::Release);
                return Ok(());
            }
            SockKind::TcpConn(e) => {
                let st = e.conn.lock().state;
                if st == crate::tcp_state::TcpState::Established { return Err(NetError::Eisconn); }
                return Err(NetError::Ealready);
            }
            SockKind::TcpListener(_) => return Err(NetError::Einval),
            _ => {}
        }
    }
    let _ = scoped_iface(sock, dst_ip, scope_id)?;
    sock.peer6_scope.store(scope_id, core::sync::atomic::Ordering::Release);
    crate::sock::tcp_lifecycle::connect_tcp6(sock, dst_ip, port, nonblock)
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

/// F180b: AF_INET6 datagram sendto. Allocates an ephemeral src port
/// on demand; routes via stack().send_udp6_to.
/// # C: O(payload)
pub fn sendto_v6(sock: &InetSocket,
                  dst_ip: crate::Ipv6Addr, dst_port: u16,
                  scope_id: u32,
                  payload: &[u8]) -> Result<usize, NetError> {
    let eno = sock.take_pending_recv_error();
    if eno != 0 { return Err(crate::sock_io::pending_net_error(eno)); }
    if crate::udp::udp6_payload_too_large(payload.len()) { return Err(NetError::Emsgsize); }
    // Lock-across-match hazard (see connect_v6): read the slot into a
    // temporary so the guard drops before the None arm re-locks to
    // assign — otherwise the re-lock spins against the still-held
    // scrutinee guard. An unbound v6 sendto hits the None arm every
    // call, so this deadlocked every first v6 send.
    let src_port = {
        let mut slot = sock.local_port.lock();
        if sock.released.load(core::sync::atomic::Ordering::Acquire) {
            return Err(NetError::Einval);
        }
        match *slot {
            Some(p) => p,
            None    => {
                let (p, endpoint) = alloc_ephemeral_udp6(
                    sock.net_ns(),
                    crate::Ipv6Addr::ANY, sock.error.clone(),
                    scoped_iface(sock, dst_ip, scope_id)?,
                    sock.opts.reuseaddr.clone(), sock.opts.reuseport.clone(),
                    sock.owner_uid,
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
    let src_ip = *sock.local_ip6.lock();
    let hop = resolve_v6_hop_limit(sock, dst_ip);
    let tclass = resolve_v6_tclass(sock);
    let pmtudisc = sock.opts.ipv6_mtu_discover.load(core::sync::atomic::Ordering::Acquire);
    stack().send_udp6_pmtu_to_bound_opts_in(
        sock.net_ns(),
        src_ip, src_port, dst_ip, dst_port, payload,
        scoped_iface(sock, dst_ip, scope_id)?, hop, tclass, pmtudisc,
    )?;
    drain_loopback();
    Ok(payload.len())
}
