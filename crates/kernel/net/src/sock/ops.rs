use super::*;

pub enum BoundAddr {
    /// `bind` on an AF_UNIX SOCK_STREAM/SOCK_SEQPACKET socket reserves `path`;
    /// `listen(2)` performs the listener state transition.
    UnixListener(crate::UnixAddr),
    /// `bind` on an AF_UNIX SOCK_DGRAM socket — register the
    /// already-allocated queue at `path`.
    UnixDgram { addr: crate::UnixAddr, queue: alloc::sync::Arc<crate::UnixDgramQueue> },
    /// `bind` on an AF_INET socket — UDP-style port reservation.
    Inet { ip: Ipv4Addr, port: u16 },
    /// F180a: `bind` on an AF_INET6 socket — IPv6 UDP port slot.
    Inet6 { ip: crate::Ipv6Addr, port: u16, scope_id: u32 },
}

/// Bind a socket to a typed address per `bind(2)`.
/// # C: O(1) for inet, O(N_unix_listeners) for unix
pub fn bind(sock: &alloc::sync::Arc<InetSocket>, addr: BoundAddr) -> Result<(), NetError> {
    let context = security::network::Context {
        namespace: sock.net_ns(),
        family: sock.family.load(core::sync::atomic::Ordering::Acquire),
        socket_type: 0, protocol: 0,
        operation: security::network::Operation::Bind,
    };
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return Err(NetError::Eacces);
    }
    match addr {
        BoundAddr::UnixListener(addr) => {
            let kind = sock.kind.lock();
            if !matches!(*kind, SockKind::TcpInit) { return Err(NetError::Einval); }
            let mut bound = sock.unix_bound.lock();
            if bound.is_some() { return Err(NetError::Einval); }
            // B518/SC1: bind into the registry that OWNS this address —
            // pathname sockets are filesystem-global (ns 0), abstract ones
            // are private to the socket's retained namespace owner.
            let listener = crate::net_ns::unix_registry_for_addr_in(&sock.net_namespace, &addr)
                .bind_addr(addr).map_err(|_| NetError::Eaddrinuse)?;
            *bound = Some(listener);
            drop(kind);
            Ok(())
        }
        BoundAddr::UnixDgram { addr, queue } => {
            // SC1: same pathname-global / abstract-per-ns split as the
            // stream listener above.
            crate::net_ns::unix_registry_for_addr_in(&sock.net_namespace, &addr)
                .dgram_bind_addr(addr.clone(), queue.clone()).map_err(|_| NetError::Eaddrinuse)?;
            queue.set_bound(addr);
            Ok(())
        }
        BoundAddr::Inet { ip, port } => {
            if let Some(result) = bind_raw4(sock, ip) { return result; }
            let is_udp = matches!(*sock.kind.lock(), SockKind::Udp);
            if !is_udp && !matches!(*sock.kind.lock(), SockKind::TcpInit) { return Err(NetError::Einval); }
            if is_udp {
                let mut local_port = sock.local_port.lock();
                if sock.released.load(core::sync::atomic::Ordering::Acquire) { return Err(NetError::Einval); }
                if local_port.is_some() || sock.udp4.lock().is_some() { return Err(NetError::Einval); }
                let iface = bound_iface(sock)?;
                let (port, endpoint) = if port == 0 {
                    alloc_ephemeral_udp4(sock.net_ns(),
                                         ip, sock.error.clone(), iface,
                                         sock.opts.reuseaddr.clone(), sock.opts.reuseport.clone(),
                                         sock.opts.ip_mtu_discover.clone(),
                                         sock.owner_uid,
                                         sock.peer.clone(), sock.bpf_filter.clone(), sock.mcast.clone())?
                } else {
                    (port, stack().bind_udp_socket_in(
                        sock.net_ns(),
                        ip, port, iface, sock.error.clone(),
                        sock.opts.reuseaddr.clone(), sock.opts.reuseport.clone(),
                        sock.opts.ip_mtu_discover.clone(),
                        sock.owner_uid,
                        sock.peer.clone(), sock.bpf_filter.clone(), sock.mcast.clone(),
                    )?)
                };
                endpoint.register_poll_subs(&sock.poll_subs);
                *sock.udp4.lock() = Some(endpoint);
                *local_port = Some(port);
                *sock.local_ip.lock() = ip;
                return Ok(());
            }
            super::tcp_lifecycle::bind_tcp(sock, crate::IpAddr::V4(ip), port)
        }
        BoundAddr::Inet6 { ip, port, scope_id } => {
            if let Some(result) = bind_raw6(sock, ip, scope_id) { return result; }
            let is_udp = matches!(*sock.kind.lock(), SockKind::Udp);
            if !is_udp && !matches!(*sock.kind.lock(), SockKind::TcpInit) { return Err(NetError::Einval); }
            if is_udp {
                let mut local_port = sock.local_port.lock();
                if sock.released.load(core::sync::atomic::Ordering::Acquire) { return Err(NetError::Einval); }
                if local_port.is_some() || sock.udp6.lock().is_some() { return Err(NetError::Einval); }
                let iface = crate::sock_v6::scoped_iface(sock, ip, scope_id)?;
                let (port, endpoint) = if port == 0 {
                    alloc_ephemeral_udp6(sock.net_ns(),
                                         ip, sock.error.clone(), iface,
                                         sock.opts.reuseaddr.clone(), sock.opts.reuseport.clone(),
                                         sock.owner_uid,
                                         sock.opts.ipv6_v6only.clone(),
                                         sock.peer6.clone(), sock.opts.ip_mtu_discover.clone(),
                                         sock.opts.ipv6_mtu_discover.clone(),
                                         sock.bpf_filter.clone(), sock.mcast.clone())?
                } else {
                    (port, stack().bind_udp6_socket_in(
                        sock.net_ns(),
                        ip, port, iface, sock.error.clone(),
                        sock.opts.reuseaddr.clone(), sock.opts.reuseport.clone(),
                        sock.owner_uid,
                        sock.opts.ipv6_v6only.clone(),
                        sock.peer6.clone(), sock.opts.ip_mtu_discover.clone(),
                        sock.opts.ipv6_mtu_discover.clone(),
                        sock.bpf_filter.clone(), sock.mcast.clone(),
                    )?)
                };
                endpoint.register_poll_subs(&sock.poll_subs);
                *sock.udp6.lock() = Some(endpoint);
                *local_port = Some(port);
                *sock.local_ip6.lock() = ip;
                return Ok(());
            }
            super::tcp_lifecycle::bind_tcp(sock, crate::IpAddr::V6(ip), port)
        }
    }
}
/// Already-validated remote-address target for connect/sendto.
#[derive(Clone)]
pub enum RemoteAddr {
    /// AF_UNSPEC disconnect request.
    Unspec,
    /// `connect`/`sendto` on AF_UNIX — registry lookup by path.
    Unix(crate::UnixAddr),
    /// `connect`/`sendto` on AF_INET — IPv4 destination.
    Inet { ip: Ipv4Addr, port: u16 },
    /// F180b: `connect`/`sendto` on AF_INET6 — IPv6 destination.
    Inet6 { ip: crate::Ipv6Addr, port: u16, scope_id: u32 },
}

fn disconnect_tcp(entry: &alloc::sync::Arc<TcpEntry>) {
    entry.close_and_wake();
    stack().tcp_disconnect_entry(entry);
}

/// # C: O(1) for UDP/UNIX, O(drain_iterations) for TCP.
pub fn connect(sock: &alloc::sync::Arc<InetSocket>, addr: RemoteAddr, nonblock: bool) -> Result<(), NetError> {
    match addr {
        RemoteAddr::Unspec => {
            enum Disc {
                Udp,
                UnixDgram(alloc::sync::Arc<crate::UnixDgramQueue>),
                TcpConn(alloc::sync::Arc<TcpEntry>),
                TcpListener(alloc::sync::Arc<TcpListenEntry>),
                Raw4(alloc::sync::Arc<crate::raw4::Raw4Endpoint>),
                Raw6(alloc::sync::Arc<crate::raw6::Raw6Endpoint>),
                Bad,
            }
            let disc = {
                let kind = sock.kind.lock();
                match &*kind {
                    SockKind::Udp => Disc::Udp,
                    SockKind::UnixDgram(q) => Disc::UnixDgram(q.clone()),
                    SockKind::TcpConn(entry) => Disc::TcpConn(entry.clone()),
                    SockKind::TcpListener(listener) => Disc::TcpListener(listener.clone()),
                    SockKind::Raw4(endpoint) => Disc::Raw4(endpoint.clone()),
                    SockKind::Raw6(endpoint) => Disc::Raw6(endpoint.clone()),
                    _ => Disc::Bad,
                }
            };
            match disc {
                Disc::Udp => {
                    *sock.peer.lock() = None;
                    *sock.peer6.lock() = None;
                    sock.peer6_scope.store(0, core::sync::atomic::Ordering::Release);
                    Ok(())
                }
                Disc::UnixDgram(q) => {
                    q.clear_peer();
                    Ok(())
                }
                Disc::TcpConn(entry) => {
                    disconnect_tcp(&entry);
                    *sock.peer.lock() = None;
                    *sock.peer6.lock() = None;
                    sock.peer6_scope.store(0, core::sync::atomic::Ordering::Release);
                    *sock.kind.lock() = SockKind::TcpInit;
                    Ok(())
                }
                Disc::TcpListener(listener) => {
                    stack().tcp_unlisten_entry(&listener);
                    *sock.kind.lock() = SockKind::TcpInit;
                    Ok(())
                }
                Disc::Raw4(endpoint) => { endpoint.disconnect(); Ok(()) }
                Disc::Raw6(endpoint) => { endpoint.disconnect(); Ok(()) }
                Disc::Bad => Err(NetError::Einval),
            }
        }
        RemoteAddr::Unix(addr) => super::unix::connect(sock, addr, nonblock),
        RemoteAddr::Inet { ip: dst_ip, port } => {
            if let SockKind::Raw4(endpoint) = &*sock.kind.lock() {
                let iface = bound_iface(sock)?;
                if dst_ip.is_broadcast() && sock.opts.broadcast.load(
                    core::sync::atomic::Ordering::Acquire) == 0 { return Err(NetError::Eacces); }
                return endpoint.connect_routed(dst_ip, iface);
            }
            {
                let kind = sock.kind.lock();
                match &*kind {
                    SockKind::Udp => {
                        drop(kind);
                        sock.ensure_bound()?;
                        *sock.peer.lock() = Some((dst_ip, port));
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
            super::tcp_lifecycle::connect_tcp4(sock, dst_ip, port, nonblock)
        }
        RemoteAddr::Inet6 { ip, port, scope_id } =>
            crate::sock_v6::connect_v6(sock, ip, port, scope_id, nonblock),
    }
}


/// `listen` per `listen(2)`. AF_UNIX bind reserves the local address and this
/// call publishes it as connectable. F176: SO_REUSEADDR forwarded.
/// # C: O(1)
pub fn listen(sock: &alloc::sync::Arc<InetSocket>, backlog: i32) -> Result<(), NetError> {
    let net_ns = sock.net_ns();
    let somaxconn = crate::sysctl::somaxconn_in(net_ns).ok_or(NetError::Enodev)?;
    // AF_UNIX listener (incl. socket-activated /run/udev/control passed to
    // udevd): register the listener's epoll subscribers against the socket's
    // `poll_subs` so `UnixRegistry::connect`'s `notify_subs` targets the epoll
    // that ADD'd this fd — not just the global rescan fallback (60§R22).
    if sock.family.load(core::sync::atomic::Ordering::Acquire) == AF_UNIX {
        let listener = {
            let mut kind = sock.kind.lock();
            if let SockKind::UnixListener(l) = &*kind {
                l.clone()
            } else {
                if !matches!(*kind, SockKind::TcpInit) { return Err(NetError::Einval); }
                let listener = sock.unix_bound.lock().clone().ok_or(NetError::Einval)?;
                *kind = SockKind::UnixListener(listener.clone());
                listener
            }
        };
        listener.register_subs(&sock.poll_subs);
        let cred = sched::live::current().map(|c| {
            use core::sync::atomic::Ordering;
            (c.visible_pid(), c.creds.euid.load(Ordering::Relaxed), c.creds.egid.load(Ordering::Relaxed))
        });
        listener.listen_with_cred(backlog, somaxconn, cred);
        #[cfg(target_os = "oxide-kernel")]
        sock.connect_waiters.wake_all();
        return Ok(());
    }
    super::tcp_lifecycle::listen_tcp(sock, backlog, somaxconn)
}

/// Result of `accept` — a new socket plus optionally the peer
/// address for the ABI layer to write back to the user `sockaddr`.
pub struct Accepted {
    pub new_sock: alloc::sync::Arc<InetSocket>,
    pub peer: Option<(Ipv4Addr, u16)>,
    pub unix_gc_pin: Option<crate::GcPin>,
}

/// `accept` per `accept(2)`. Non-blocking: returns Err(Eagain) when
/// no connection is ready. work fn — caller (ABI shim)
/// wraps the returned `InetSocket` in a vfs::File and allocates a fd.
/// # C: O(1) + drain
pub fn accept(sock: &alloc::sync::Arc<InetSocket>) -> Result<Accepted, NetError> {
    drain_loopback();
    // AF_UNIX listener: pop one queued UnixPair.
    let unix_listener = {
        let kind = sock.kind.lock();
        if let SockKind::UnixListener(l) = &*kind { Some(l.clone()) } else { None }
    };
    if let Some(l) = unix_listener {
        let (pair, pin) = l.accept()?;
        #[cfg(feature = "debug-dbus")]
        {
            let nm = sched::live::current().and_then(|c| unsafe { (*c.exe_path.get()).as_ref().map(|s| s.clone()) }).unwrap_or_default();
            klog::write_raw(b"[UXACCEPT comm="); klog::write_raw(nm.as_bytes());
            klog::write_raw(b" pair="); klog::write_hex_u64(alloc::sync::Arc::as_ptr(&pair) as u64);
            klog::write_raw(b"]\n");
        }
        let new_sock = InetSocket::from_accepted_unix(sock, pair);
        return Ok(Accepted { new_sock, peer: None, unix_gc_pin: Some(pin) });
    }
    let listener_arc = match &*sock.kind.lock() {
        SockKind::TcpListener(l) => l.clone(),
        _ => return Err(NetError::Einval),
    };
    let entry = stack().tcp_accept(&listener_arc).ok_or(NetError::Eagain)?;
    let (peer_ip_any, peer_port) = {
        let c = entry.conn.lock();
        (c.remote.ip, c.remote.port)
    };
    let new_sock = InetSocket::from_accepted_tcp(sock, entry.clone());
    inherit_tcp_keepalive_opts(&new_sock, sock);
    apply_tcp_keepalive_opts(&new_sock, &entry);
    // F180b: pin the peer slot for the family the listener was opened
    // in. v6 listeners only ever see v6 conns (deliver path keys by
    // IpAddr); same for v4.
    let peer_v4 = match peer_ip_any { crate::addr::IpAddr::V4(a) => Some((a, peer_port)), _ => None };
    Ok(Accepted { new_sock, peer: peer_v4, unix_gc_pin: None })
}

#[cfg(all(test, target_os = "oxide-kernel"))]
mod tests {
    use super::*;

    #[test]
    fn udp_af_unspec_connect_clears_peer() {
        let sock = alloc::sync::Arc::new(InetSocket::new_udp());
        connect(&sock, RemoteAddr::Inet { ip: Ipv4Addr::LOOPBACK, port: 53 }, false).unwrap();
        assert_eq!(*sock.peer.lock(), Some((Ipv4Addr::LOOPBACK, 53)));

        connect(&sock, RemoteAddr::Unspec, false).unwrap();

        assert_eq!(*sock.peer.lock(), None);
    }

    #[test]
    fn unix_dgram_af_unspec_connect_clears_peer() {
        let sock = alloc::sync::Arc::new(InetSocket::new_unix_dgram());
        let addr = crate::UnixAddr::from_sockaddr_path(b"\0svc".to_vec());
        if let SockKind::UnixDgram(q) = &*sock.kind.lock() {
            q.set_peer(addr);
        } else {
            panic!("expected unix dgram socket");
        }

        connect(&sock, RemoteAddr::Unspec, false).unwrap();

        if let SockKind::UnixDgram(q) = &*sock.kind.lock() {
            assert!(q.peer().is_none());
        } else {
            panic!("expected unix dgram socket");
        }
    }

    #[test]
    fn connected_stream_connect_returns_eisconn() {
        let sock = alloc::sync::Arc::new(InetSocket::new_tcp());
        let local = crate::Endpoint { ip: crate::addr::IpAddr::V4(Ipv4Addr::LOOPBACK), port: 40000 };
        let remote = crate::Endpoint { ip: crate::addr::IpAddr::V4(Ipv4Addr::LOOPBACK), port: 80 };
        let mut conn = crate::TcpConn::new_client(local, remote, 1);
        conn.state = crate::tcp_state::TcpState::Established;
        *sock.kind.lock() = SockKind::TcpConn(alloc::sync::Arc::new(TcpEntry::new(conn)));

        assert_eq!(
            connect(&sock, RemoteAddr::Inet { ip: Ipv4Addr::LOOPBACK, port: 80 }, false),
            Err(NetError::Eisconn),
        );
    }
}
