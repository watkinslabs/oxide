use super::*;
use core::sync::atomic::Ordering;

fn tcp_v6only(sock: &InetSocket, ip: crate::IpAddr) -> bool {
    matches!(ip, crate::IpAddr::V6(_))
        && sock.opts.ipv6_v6only.load(Ordering::Acquire) != 0
}

/// Reserve one TCP local name and publish it into the owning socket. # C: O(N_port)
pub(super) fn bind_tcp(sock: &alloc::sync::Arc<InetSocket>, ip: crate::IpAddr,
                       requested_port: u16, scoped_iface: Option<NetIfaceId>) -> Result<(), NetError> {
    let mut local_port = sock.local_port.lock();
    if sock.released.load(Ordering::Acquire) { return Err(NetError::Einval); }
    if local_port.is_some() || sock.tcp_bind.lock().is_some() { return Err(NetError::Einval); }
    if !matches!(*sock.kind.lock(), SockKind::TcpInit) { return Err(NetError::Einval); }
    let iface = match scoped_iface {
        Some(iface) => Some(iface),
        None => bound_iface(sock)?,
    };
    let reuseaddr = sock.opts.reuseaddr.load(Ordering::Acquire) != 0;
    let reuseport = sock.opts.reuseport.load(Ordering::Acquire) != 0;
    let bind = stack().tcp_reserve_in(sock.net_ns(),
        ip, requested_port, iface, reuseaddr, reuseport,
        sock.owner_uid, tcp_v6only(sock, ip))?;
    *local_port = Some(bind.local.port);
    match ip {
        crate::IpAddr::V4(addr) => *sock.local_ip.lock() = addr,
        crate::IpAddr::V6(addr) => *sock.local_ip6.lock() = addr,
    }
    *sock.tcp_bind.lock() = Some(bind);
    Ok(())
}

fn ensure_tcp_bind(sock: &InetSocket, local_ip: crate::IpAddr,
                   local_port: &mut Option<u16>)
    -> Result<Arc<crate::stack::TcpBindReservation>, NetError> {
    if let Some(bind) = sock.tcp_bind.lock().as_ref().cloned() { return Ok(bind); }
    let iface = bound_iface(sock)?;
    let bind = stack().tcp_reserve_in(sock.net_ns(), local_ip, 0, iface,
        sock.opts.reuseaddr.load(Ordering::Acquire) != 0,
        sock.opts.reuseport.load(Ordering::Acquire) != 0,
        sock.owner_uid, tcp_v6only(sock, local_ip))?;
    *local_port = Some(bind.local.port);
    *sock.tcp_bind.lock() = Some(bind.clone());
    Ok(bind)
}

/// Linux listen transition, including implicit bind to a nonzero port. # C: O(N)
pub(super) fn listen_tcp(sock: &alloc::sync::Arc<InetSocket>, backlog: i32,
                         somaxconn: usize) -> Result<(), NetError> {
    let mut local_port = sock.local_port.lock();
    if sock.released.load(Ordering::Acquire) { return Err(NetError::Einval); }
    {
        let kind = sock.kind.lock();
        if let SockKind::TcpListener(listener) = &*kind {
            listener.set_backlog(backlog, somaxconn);
            return Ok(());
        }
        if !matches!(*kind, SockKind::TcpInit) { return Err(NetError::Einval); }
    }
    let family = sock.family.load(Ordering::Acquire);
    let local_ip = if family == AF_INET6 {
        crate::IpAddr::V6(*sock.local_ip6.lock())
    } else {
        crate::IpAddr::V4(*sock.local_ip.lock())
    };
    let bind = ensure_tcp_bind(sock, local_ip, &mut local_port)?;
    let listener = stack().tcp_listen_reserved_filter_pmtu_modes(
        &bind, sock.bpf_filter.clone(), sock.opts.ip_mtu_discover.clone(),
        sock.opts.ipv6_mtu_discover.clone())?;
    listener.set_backlog(backlog, somaxconn);
    listener.register_poll_subs(&sock.poll_subs);
    *sock.kind.lock() = SockKind::TcpListener(listener);
    Ok(())
}

fn connect_tcp(sock: &alloc::sync::Arc<InetSocket>, local_ip: crate::IpAddr,
               remote_ip: crate::IpAddr, remote_port: u16, nonblock: bool)
    -> Result<(), NetError> {
    let mut local_port = sock.local_port.lock();
    if sock.released.load(Ordering::Acquire) { return Err(NetError::Einval); }
    let bind = ensure_tcp_bind(sock, local_ip, &mut local_port)?;
    let entry = stack().tcp_connect_reserved_filter_pmtu_modes(
        &bind, local_ip, remote_ip, remote_port, sock.error.clone(), sock.bpf_filter.clone(),
        sock.opts.ip_mtu_discover.clone(), sock.opts.ipv6_mtu_discover.clone(),
    )?;
    entry.register_poll_subs(&sock.poll_subs);
    apply_tcp_keepalive_opts(sock, &entry);
    *sock.kind.lock() = SockKind::TcpConn(entry.clone());
    match remote_ip {
        crate::IpAddr::V4(ip) => *sock.peer.lock() = Some((ip, remote_port)),
        crate::IpAddr::V6(ip) => *sock.peer6.lock() = Some((ip, remote_port)),
    }
    drop(local_port);
    if nonblock { return Err(NetError::Einprogress); }
    crate::sock_io::connect_wait_established(sock, &entry)
}

/// Select IPv4 source and perform one reservation-backed active open. # C: O(N + RTT)
pub(super) fn connect_tcp4(sock: &alloc::sync::Arc<InetSocket>, dst_ip: Ipv4Addr,
                           remote_port: u16, nonblock: bool) -> Result<(), NetError> {
    let net_ns = sock.net_ns();
    let configured = *sock.local_ip.lock();
    let local_ip = if configured != Ipv4Addr::ANY {
        configured
    } else if dst_ip.is_loopback() {
        Ipv4Addr::LOOPBACK
    } else {
        let iface = bound_iface(sock)?;
        stack().routes.lookup_in(net_ns, dst_ip).and_then(|route| route.src_hint)
            .or_else(|| iface_primary_ip(iface.or_else(|| stack().routes.lookup_in(net_ns, dst_ip).map(|r| r.iface))))
            .unwrap_or(Ipv4Addr::LOOPBACK)
    };
    connect_tcp(sock, crate::IpAddr::V4(local_ip), crate::IpAddr::V4(dst_ip), remote_port, nonblock)
}

/// Select IPv6 source and perform one reservation-backed active open. # C: O(N + RTT)
pub(crate) fn connect_tcp6(sock: &alloc::sync::Arc<InetSocket>, dst_ip: crate::Ipv6Addr,
                           remote_port: u16, nonblock: bool) -> Result<(), NetError> {
    let configured = *sock.local_ip6.lock();
    let local_ip = if configured != crate::Ipv6Addr::ANY {
        configured
    } else if dst_ip == crate::Ipv6Addr::LOOPBACK {
        crate::Ipv6Addr::LOOPBACK
    } else {
        crate::Ipv6Addr::ANY
    };
    connect_tcp(sock, crate::IpAddr::V6(local_ip), crate::IpAddr::V6(dst_ip), remote_port, nonblock)
}
