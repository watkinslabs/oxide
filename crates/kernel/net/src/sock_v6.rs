// F180b: AF_INET6 connect helpers. Extracted from sock.rs for the
// 1000-line cap (docs/08§7). v6 UDP "connect" stashes the peer in
// the v6 peer slot; v6 TCP routes through tcp_connect_ip with a
// v1 source-address pick (LOOPBACK for ::1 else ANY).

use crate::netdev::NetError;
use crate::sock::{
    InetSocket, SockKind, alloc_ephemeral_port, alloc_ephemeral_port6,
    bound_iface, drain_loopback, stack,
};
use crate::sock_opts::apply_tcp_keepalive_opts;

/// v6 connect dispatch. # C: O(1) UDP, O(RTT) TCP.
pub fn connect_v6(sock: &alloc::sync::Arc<InetSocket>,
                   dst_ip: crate::Ipv6Addr, port: u16) -> Result<(), NetError> {
    let is_dgram = matches!(*sock.kind.lock(), SockKind::Udp);
    if is_dgram {
        *sock.peer6.lock() = Some((dst_ip, port));
        return Ok(());
    }
    let local_port = {
        let cur = *sock.local_port.lock();
        match cur {
            Some(p) => p,
            None    => { let p = alloc_ephemeral_port()?; *sock.local_port.lock() = Some(p); p }
        }
    };
    let bound6 = *sock.local_ip6.lock();
    let any6 = crate::Ipv6Addr::ANY;
    let local_ip = if bound6 != any6 {
        bound6
    } else if dst_ip == crate::Ipv6Addr::LOOPBACK {
        crate::Ipv6Addr::LOOPBACK
    } else {
        any6
    };
    let bound = bound_iface(sock)?;
    let entry = stack().tcp_connect_ip_bound(
        crate::addr::IpAddr::V6(local_ip), local_port,
        crate::addr::IpAddr::V6(dst_ip),   port,
        bound,
    )?;
    entry.register_poll_subs(&sock.poll_subs);
    apply_tcp_keepalive_opts(sock, &entry);
    *sock.kind.lock() = SockKind::TcpConn(entry.clone());
    *sock.peer6.lock() = Some((dst_ip, port));
    crate::sock_io::connect_wait_established(&entry)
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

/// F180b: AF_INET6 datagram sendto. Allocates an ephemeral src port
/// on demand; routes via stack().send_udp6_to.
/// # C: O(payload)
pub fn sendto_v6(sock: &InetSocket,
                  dst_ip: crate::Ipv6Addr, dst_port: u16,
                  payload: &[u8]) -> Result<usize, NetError> {
    // Lock-across-match hazard (see connect_v6): read the slot into a
    // temporary so the guard drops before the None arm re-locks to
    // assign — otherwise the re-lock spins against the still-held
    // scrutinee guard. An unbound v6 sendto hits the None arm every
    // call, so this deadlocked every first v6 send.
    let src_port = {
        let cur = *sock.local_port.lock();
        match cur {
            Some(p) => p,
            None    => {
                let p = alloc_ephemeral_port6()?;
                stack().set_udp6_bound_iface(p, bound_iface(sock)?);
                *sock.local_port.lock() = Some(p);
                p
            }
        }
    };
    let src_ip = *sock.local_ip6.lock();
    let hop = resolve_v6_hop_limit(sock, dst_ip);
    stack().send_udp6_to_bound_opts(src_ip, src_port, dst_ip, dst_port, payload, bound_iface(sock)?, hop)?;
    drain_loopback();
    Ok(payload.len())
}
