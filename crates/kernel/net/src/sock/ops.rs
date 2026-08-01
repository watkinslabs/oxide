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
    let admission = admit_bind(sock)?;
    bind_admitted(sock, addr, admission)
}

/// Bind after the canonical Linux security admission has succeeded.
/// # C: O(1) for inet, O(N_unix_listeners) for unix
pub fn bind_admitted(sock: &alloc::sync::Arc<InetSocket>, addr: BoundAddr,
                     _admission: BindAdmission) -> Result<(), NetError> {
    match addr {
        BoundAddr::UnixListener(addr) => {
            let kind = sock.kind.lock();
            if !matches!(*kind, SockKind::UnixUnbound(_, _)) { return Err(NetError::Einval); }
            let mut bound = sock.unix_bound.lock();
            if bound.is_some() { return Err(NetError::Einval); }
            // B518/SC1: bind into the registry that OWNS this address —
            // pathname sockets are filesystem-global (ns 0), abstract ones
            // are private to the socket's retained namespace owner.
            let listener = crate::net_ns::unix_registry_for_addr_in(&sock.net_namespace, &addr)
                .bind_addr(addr).map_err(|_| NetError::Eaddrinuse)?;
            listener.set_owner_domain(crate::landlock_glue::current_domain());
            *bound = Some(listener);
            drop(kind);
            Ok(())
        }
        BoundAddr::UnixDgram { addr, queue } => {
            // SC1: same pathname-global / abstract-per-ns split as the
            // stream listener above.
            crate::net_ns::unix_registry_for_addr_in(&sock.net_namespace, &addr)
                .dgram_bind_addr(addr.clone(), queue.clone()).map_err(|_| NetError::Eaddrinuse)?;
            queue.set_owner_domain(crate::landlock_glue::current_domain());
            queue.set_bound(addr);
            Ok(())
        }
        BoundAddr::Inet { ip, port } => {
            if let Some(result) = bind_raw4(sock, ip, port) { return result; }
            let is_udp = matches!(*sock.kind.lock(), SockKind::Udp);
            if !is_udp && !matches!(*sock.kind.lock(), SockKind::TcpInit) { return Err(NetError::Einval); }
            // The local-address screen precedes the port rules on the IPv4
            // path: a socket that names an address the namespace does not own
            // reports that, whatever the port would have done.
            super::nonlocal::screen_v4(sock, ip, bound_iface(sock)?)?;
            if is_udp {
                let mut local_port = sock.local_port.lock();
                if sock.released.load(core::sync::atomic::Ordering::Acquire) { return Err(NetError::Einval); }
                if local_port.is_some() || sock.udp4.lock().is_some() { return Err(NetError::Einval); }
                let iface = bound_iface(sock)?;
                let (port, endpoint) = if port == 0 {
                    alloc_ephemeral_udp4_owned(sock.owner.clone(), ip, sock.error.clone(), iface,
                                         sock.opts.reuseaddr.clone(), sock.opts.reuseport.clone(),
                                         sock.opts.ip_mtu_discover.clone(), sock.opts.udp.gro.clone(),
                                         sock.peer.clone(), sock.bpf_filter.clone(), sock.mcast.clone())?
                } else {
                    (port, stack().bind_udp_socket_owned(
                        sock.owner.clone(), ip, port, iface, sock.error.clone(),
                        sock.opts.reuseaddr.clone(), sock.opts.reuseport.clone(),
                        sock.opts.ip_mtu_discover.clone(), sock.opts.udp.gro.clone(),
                        sock.peer.clone(), sock.bpf_filter.clone(), sock.mcast.clone(),
                    )?)
                };
                endpoint.register_poll_subs(&sock.poll_subs);
                stack().join_udp4_reuseport(&endpoint, &sock.reuseport_group);
                *sock.udp4.lock() = Some(endpoint);
                *local_port = Some(port);
                *sock.local_ip.lock() = ip;
                return Ok(());
            }
            super::tcp_lifecycle::bind_tcp(sock, crate::IpAddr::V4(ip), port, None)
        }
        BoundAddr::Inet6 { ip, port, scope_id } => {
            if let Some(result) = bind_raw6(sock, ip, scope_id, port) { return result; }
            let is_udp = matches!(*sock.kind.lock(), SockKind::Udp);
            if !is_udp && !matches!(*sock.kind.lock(), SockKind::TcpInit) { return Err(NetError::Einval); }
            super::nonlocal::screen_v6(sock, ip, crate::sock_v6::scoped_iface(sock, ip, scope_id)?)?;
            if is_udp {
                let mut local_port = sock.local_port.lock();
                if sock.released.load(core::sync::atomic::Ordering::Acquire) { return Err(NetError::Einval); }
                if local_port.is_some() || sock.udp6.lock().is_some() { return Err(NetError::Einval); }
                let iface = crate::sock_v6::scoped_iface(sock, ip, scope_id)?;
                let (port, endpoint) = if port == 0 {
                    alloc_ephemeral_udp6_owned(sock.owner.clone(), ip, sock.error.clone(), iface,
                                         sock.opts.reuseaddr.clone(), sock.opts.reuseport.clone(),
                                         sock.opts.ipv6_v6only.clone(),
                                         sock.peer6.clone(), sock.opts.ip_mtu_discover.clone(),
                                         sock.opts.ipv6_mtu_discover.clone(),
                                         sock.opts.udp.no_check6_rx.clone(), sock.opts.udp.gro.clone(),
                                         sock.bpf_filter.clone(), sock.mcast.clone())?
                } else {
                    (port, stack().bind_udp6_socket_owned(
                        sock.owner.clone(), ip, port, iface, sock.error.clone(),
                        sock.opts.reuseaddr.clone(), sock.opts.reuseport.clone(),
                        sock.opts.ipv6_v6only.clone(),
                        sock.peer6.clone(), sock.opts.ip_mtu_discover.clone(),
                        sock.opts.ipv6_mtu_discover.clone(),
                        sock.opts.udp.no_check6_rx.clone(), sock.opts.udp.gro.clone(),
                        sock.bpf_filter.clone(), sock.mcast.clone(),
                    )?)
                };
                endpoint.register_poll_subs(&sock.poll_subs);
                stack().join_udp6_reuseport(&endpoint, &sock.reuseport_group);
                *sock.udp6.lock() = Some(endpoint);
                *local_port = Some(port);
                *sock.local_ip6.lock() = ip;
                return Ok(());
            }
            let iface = crate::sock_v6::scoped_iface(sock, ip, scope_id)?;
            super::tcp_lifecycle::bind_tcp(sock, crate::IpAddr::V6(ip), port, iface)
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
    let admission = super::admit_connect(sock)?;
    connect_admitted(sock, addr, nonblock, admission)
}

/// Connect after canonical generic security admission. # C: O(1) or O(wait)
pub fn connect_admitted(sock: &alloc::sync::Arc<InetSocket>, addr: RemoteAddr, nonblock: bool,
                        admission: ConnectAdmission) -> Result<(), NetError> {
    match addr {
        RemoteAddr::Unspec => {
            let _lifecycle = sock.local_port.lock();
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
        addr @ (RemoteAddr::Inet { .. } | RemoteAddr::Inet6 { .. }) =>
            super::preflight_connect_admitted(sock, admission)?.commit(addr, nonblock),
    }
}


/// `listen` per `listen(2)`. AF_UNIX bind reserves the local address and this
/// call publishes it as connectable. F176: SO_REUSEADDR forwarded.
/// # C: O(1)
pub fn listen(sock: &alloc::sync::Arc<InetSocket>, backlog: i32) -> Result<(), NetError> {
    let context = security::network::Context {
        namespace: sock.net_ns(),
        family: sock.family.load(core::sync::atomic::Ordering::Acquire),
        socket_type: 0, protocol: 0,
        operation: security::network::Operation::Listen,
    };
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return Err(NetError::Eacces);
    }
    let net_ns = sock.net_ns();
    let somaxconn = crate::sysctl::somaxconn_in(net_ns).ok_or(NetError::Enodev)?;
    // AF_UNIX listener (incl. socket-activated /run/udev/control passed to
    // udevd): register the listener's epoll subscribers against the socket's
    // `poll_subs` so `UnixRegistry::connect`'s `notify_subs` targets the epoll
    // that ADD'd this fd — not just the global rescan fallback (60§R22).
    if sock.family.load(core::sync::atomic::Ordering::Acquire) == AF_UNIX {
        let shape = match &*sock.kind.lock() {
            SockKind::UnixDgram(_) => crate::listen_admit::ListenShape::UnixDatagram,
            SockKind::UnixListener(_) => crate::listen_admit::ListenShape::UnixListening,
            SockKind::UnixUnbound(_, _) => crate::listen_admit::ListenShape::UnixBound,
            _ => crate::listen_admit::ListenShape::UnixUnnameable,
        };
        if let crate::listen_admit::ListenAdmit::Refuse(error) =
            crate::listen_admit::admit_listen(shape)
        { return Err(error); }
        let listener = {
            let mut kind = sock.kind.lock();
            if let SockKind::UnixListener(l) = &*kind {
                l.clone()
            } else {
                // A socket that was bound but whose name is gone has nothing
                // to publish, the same state error the shape ladder names.
                let listener = sock.unix_bound.lock().clone().ok_or(NetError::Einval)?;
                *kind = SockKind::UnixListener(listener.clone());
                listener
            }
        };
        listener.register_subs(&sock.poll_subs);
        let current = sched::live::current();
        let cred = crate::PeerCred::of_current();
        let identity = current.as_ref().map(|c| c.thread_group.leader_pid());
        listener.listen_with_cred(backlog, somaxconn, cred, identity);
        #[cfg(target_os = "oxide-kernel")]
        sock.connect_waiters.wake_all();
        return Ok(());
    }
    // A datagram or raw INET socket has no listen operation at all, which is
    // a different refusal from a stream socket in the wrong state. Only the
    // stream kinds reach `listen_tcp`.
    let shape = match &*sock.kind.lock() {
        SockKind::Packet { .. } | SockKind::Udp | SockKind::Raw4(_) | SockKind::Raw6(_) =>
            crate::listen_admit::ListenShape::NoListenOp,
        _ => crate::listen_admit::ListenShape::Stream,
    };
    if let crate::listen_admit::ListenAdmit::Refuse(error) =
        crate::listen_admit::admit_listen(shape)
    { return Err(error); }
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
    let context = security::network::Context {
        namespace: sock.net_ns(),
        family: sock.family.load(core::sync::atomic::Ordering::Acquire),
        socket_type: 0, protocol: 0,
        operation: security::network::Operation::Accept,
    };
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return Err(NetError::Eacces);
    }
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
            let nm = sched::live::current().and_then(|c| c.exe_path()).unwrap_or_default();
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
    inherit_tcp_oobinline(&new_sock, sock);
    new_sock.opts.tcp.inherit(&sock.opts.tcp);
    apply_tcp_keepalive_opts(&new_sock, &entry);
    {
        let mut c = entry.conn.lock();
        crate::sock_opts::sol_tcp::apply::to_conn(&new_sock.opts, &mut c);
        crate::sock_opts::sol_tcp::apply::collect_saved_syn(&new_sock.opts, &mut c);
    }
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
