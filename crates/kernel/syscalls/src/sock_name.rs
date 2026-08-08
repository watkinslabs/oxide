// The `sk->sk_prot->getname` DECISIONS behind `getsockname(2)` /
// `getpeername(2)` / `SO_PEERNAME`: which socket field answers the query, and
// which error a socket with no such name reports. No user memory, no `hal`,
// no cfg gating — the kernel-only slots (`051_getsockname`, `052_getpeername`)
// classify the fd and marshal the result, while every family/state rule lives
// here where hosted `cargo test` drives it against real sockets.

use alloc::sync::Arc;
use syscall::errno::Errno;
use net::sock::{InetSocket, SockKind};
use crate::sockaddr_encode::{encoded_sockaddr_for_socket, encoded_sockaddr_in,
    encoded_sockaddr_in6, encoded_sockaddr_ll, encoded_sockaddr_un,
    v6_name_is_v4_mapped, EncodedSockaddr};

/// `sk->sk_prot->getname(sock, addr, peer=1)`: the peer address a connected
/// socket reports, shared by `getpeername(2)` and `SO_PEERNAME`. # C: O(1)
pub(crate) fn peer_sockaddr(sock: &Arc<InetSocket>) -> Result<EncodedSockaddr, Errno> {
    // A peer name carries the flow information a connect settled, and only
    // for a socket that asked to send one; a local name never carries any.
    let flowinfo = peer_flowinfo(sock);
    let raw = match &*sock.kind.lock() {
        SockKind::Raw4(endpoint) => match endpoint.snapshot().remote {
            Some(peer) => Some(encoded_sockaddr_in(peer.as_u32().to_be(), 0)),
            None => return Err(Errno::Enotconn),
        },
        SockKind::Raw6(endpoint) => match endpoint.peer() {
            Some(peer) => Some(encoded_sockaddr_in6(peer.addr.0, 0, peer.scope_id,
                flowinfo)),
            None => return Err(Errno::Enotconn),
        },
        _ => None,
    };
    if let Some(sa) = raw { return Ok(sa); }
    // Linux AF_PACKET installs `packet_getname`, which rejects its peer
    // query with EOPNOTSUPP rather than falling through to generic INET peer
    // state. AF_PACKET owns no peer address, so do not synthesize one from
    // the generic socket tuple.
    if family(sock) == net::sock::AF_PACKET { return Err(Errno::Eopnotsupp); }
    // AF_UNIX sockets keep their peer as a UnixPair (SockKind::Unix /
    // UnixMsgPair), never in the IPv4 `peer` tuple. A connected AF_UNIX end
    // must report success — the peer's sockaddr_un (its bound sun_path as
    // seen by a client; a bare AF_UNIX family for an unnamed peer) — not
    // ENOTCONN. sd-bus, dbus-daemon and logind call getpeername on their
    // AF_UNIX connections; ENOTCONN on a live connection broke them.
    if family(sock) == net::sock::AF_UNIX {
        return match net::sock::unix_peer_path(sock) {
            Some(path) => Ok(encoded_sockaddr_un(path.as_deref())),
            None => Err(Errno::Enotconn),
        };
    }
    let tcp_peer_unavailable = match &*sock.kind.lock() {
        SockKind::TcpConn(entry) => !entry.peer_name_connected(),
        _ => false,
    };
    if tcp_peer_unavailable { return Err(Errno::Enotconn); }
    if family(sock) == net::sock::AF_INET6 {
        // Only a NATIVE v6 peer lives in `peer6`. A dual-stack socket that
        // connected to an IPv4 peer (`::ffff:a.b.c.d`, the standard
        // `getaddrinfo(AI_V4MAPPED)` client shape) took the v4 path, so its
        // peer tuple is in `sock.peer` — `inet6_getname` still answers with
        // `sk->sk_v6_daddr` == `::ffff:a.b.c.d`. Returning ENOTCONN as soon
        // as `peer6` was empty declared every such live connection
        // unconnected.
        if let Some((ip, port)) = *sock.peer6.lock() {
            let bound_ifindex = net::sock_v6_name::name_bound_ifindex(sock);
            return Ok(encoded_sockaddr_in6(ip.0, port.to_be(),
                net::sock_v6_name::name_scope_id(ip, bound_ifindex), flowinfo));
        }
    }
    let (ip, port) = match *sock.peer.lock() {
        Some(t) => t, None => return Err(Errno::Enotconn),
    };
    Ok(encoded_sockaddr_for_socket(sock, ip, port, flowinfo))
}

/// `sk->sk_prot->getname(sock, addr, peer=0)`: the local address a socket
/// reports. Every family answers — an unbound INET socket names the wildcard
/// tuple rather than failing. # C: O(1)
pub(crate) fn local_sockaddr(sock: &Arc<InetSocket>) -> EncodedSockaddr {
    let raw = match &*sock.kind.lock() {
        SockKind::Raw4(endpoint) => {
            let state = endpoint.snapshot();
            Some(encoded_sockaddr_in(state.local.as_u32().to_be(),
                endpoint.ping_ident().to_be()))
        }
        SockKind::Raw6(endpoint) => {
            let local = endpoint.local();
            Some(encoded_sockaddr_in6(local.addr.0, endpoint.ping_ident().to_be(),
                local.scope_id, 0))
        }
        _ => None,
    };
    if let Some(sa) = raw { return sa; }
    // AF_PACKET names its bound interface through `packet_getname`, whose
    // `sockaddr_ll` carries the hardware address — never the INET tuple.
    if let Some(packet) = net::sock::packet_local_addr(sock) {
        return encoded_sockaddr_ll(packet);
    }
    let port = (*sock.local_port.lock()).unwrap_or(0);
    let ip   = *sock.local_ip.lock();
    if family(sock) == net::sock::AF_INET6 {
        let ip6 = *sock.local_ip6.lock();
        // `inet6_getname`: report `sk->sk_v6_rcv_saddr`, or the v4-mapped
        // form when that is unspecified. A dual-stack socket that connected
        // to an IPv4 peer took the v4 path, so its local address is in the
        // IPv4 tuple; reading `local_ip6` unconditionally reported `[::]`
        // for every such socket.
        if v6_name_is_v4_mapped(ip6, ip) {
            return encoded_sockaddr_for_socket(sock, ip, port, 0);
        }
        let bound_ifindex = net::sock_v6_name::name_bound_ifindex(sock);
        return encoded_sockaddr_in6(ip6.0, port.to_be(),
            net::sock_v6_name::name_scope_id(ip6, bound_ifindex), 0);
    }
    encoded_sockaddr_for_socket(sock, ip, port, 0)
}

/// The `sin6_flowinfo` this socket's PEER name carries. # C: O(1)
pub(crate) fn peer_flowinfo(sock: &InetSocket) -> u32 {
    net::sock_opts::sol_ipv6::sndflow::reported(
        sock.opts.ipv6.flag(net::sock_opts::sol_ipv6::flag::SNDFLOW),
        sock.opts.ipv6.flow_label())
}

fn family(sock: &InetSocket) -> u16 {
    sock.family.load(core::sync::atomic::Ordering::Acquire)
}

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod tests;
