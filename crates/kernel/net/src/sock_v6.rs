// F180b: AF_INET6 connect helpers. Extracted from sock.rs for the
// 1000-line cap (docs/08§7). v6 UDP "connect" stashes the peer in
// the v6 peer slot; v6 TCP routes through tcp_connect_ip with a
// v1 source-address pick (LOOPBACK for ::1 else ANY).

use crate::netdev::NetError;
use crate::sock::{InetSocket, SockKind, alloc_ephemeral_port, alloc_ephemeral_port6, drain_loopback, stack};

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
    let entry = stack().tcp_connect_ip(
        crate::addr::IpAddr::V6(local_ip), local_port,
        crate::addr::IpAddr::V6(dst_ip),   port,
    )?;
    entry.register_poll_subs(&sock.poll_subs);
    *sock.kind.lock() = SockKind::TcpConn(entry.clone());
    *sock.peer6.lock() = Some((dst_ip, port));
    crate::sock_io::connect_wait_established(&entry)
}

/// F180b: AF_INET6 datagram sendto. Allocates an ephemeral src port
/// on demand; routes via stack().send_udp6_to.
/// # C: O(payload)
pub fn sendto_v6(sock: &alloc::sync::Arc<InetSocket>,
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
            None    => { let p = alloc_ephemeral_port6()?; *sock.local_port.lock() = Some(p); p }
        }
    };
    let src_ip = *sock.local_ip6.lock();
    stack().send_udp6_to(src_ip, src_port, dst_ip, dst_port, payload)?;
    drain_loopback();
    Ok(payload.len())
}
