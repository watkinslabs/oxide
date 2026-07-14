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
    Inet6 { ip: crate::Ipv6Addr, port: u16 },
}

/// Bind a socket to an address per `bind(2)`. work fn:
/// takes typed args, returns typed result, no `&SyscallArgs`.
/// # C: O(1) for inet, O(N_unix_listeners) for unix
pub fn bind(sock: &alloc::sync::Arc<InetSocket>, addr: BoundAddr) -> Result<(), NetError> {
    match addr {
        BoundAddr::UnixListener(addr) => {
            let kind = sock.kind.lock();
            if !matches!(*kind, SockKind::TcpInit) { return Err(NetError::Einval); }
            let mut bound = sock.unix_bound.lock();
            if bound.is_some() { return Err(NetError::Einval); }
            // B518/SC1: bind into the registry that OWNS this address —
            // pathname sockets are filesystem-global (ns 0), abstract ones
            // are private to the caller's net_ns (see unix_ns_for_path).
            // Record that ns so Drop unbinds from the SAME registry.
            let ns = crate::net_ns::unix_ns_for_addr(&addr);
            let listener = crate::net_ns::ns_unix_registry(ns)
                .bind_addr(addr).map_err(|_| NetError::Eaddrinuse)?;
            sock.unix_ns.store(ns, core::sync::atomic::Ordering::Release);
            *bound = Some(listener);
            drop(kind);
            Ok(())
        }
        BoundAddr::UnixDgram { addr, queue } => {
            // SC1: same pathname-global / abstract-per-ns split as the
            // stream listener above.
            let ns = crate::net_ns::unix_ns_for_addr(&addr);
            crate::net_ns::ns_unix_registry(ns)
                .dgram_bind_addr(addr.clone(), queue.clone()).map_err(|_| NetError::Eaddrinuse)?;
            queue.set_bound(addr);
            sock.unix_ns.store(ns, core::sync::atomic::Ordering::Release);
            Ok(())
        }
        BoundAddr::Inet { ip, port } => {
            stack().bind_udp_with_iface(ip, port, bound_iface(sock)?)?;
            *sock.local_port.lock() = Some(port);
            *sock.local_ip.lock() = ip;
            // F181a: register subscribers on the just-bound queue.
            if let Some(q) = stack().udp_queue_arc(port) {
                q.register_poll_subs(&sock.poll_subs);
            }
            Ok(())
        }
        BoundAddr::Inet6 { ip, port } => {
            // F180a: AF_INET6 UDP bind routes through udp6 map.
            stack().bind_udp6_with_iface(ip, port, bound_iface(sock)?)?;
            *sock.local_port.lock() = Some(port);
            *sock.local_ip6.lock() = ip;
            if let Some(q) = stack().udp6_queue_arc(port) {
                q.register_poll_subs(&sock.poll_subs);
            }
            Ok(())
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
    Inet6 { ip: crate::Ipv6Addr, port: u16 },
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
                Bad,
            }
            let disc = {
                let kind = sock.kind.lock();
                match &*kind {
                    SockKind::Udp => Disc::Udp,
                    SockKind::UnixDgram(q) => Disc::UnixDgram(q.clone()),
                    SockKind::TcpConn(entry) => Disc::TcpConn(entry.clone()),
                    SockKind::TcpListener(listener) => Disc::TcpListener(listener.clone()),
                    _ => Disc::Bad,
                }
            };
            match disc {
                Disc::Udp => {
                    *sock.peer.lock() = None;
                    *sock.peer6.lock() = None;
                    Ok(())
                }
                Disc::UnixDgram(q) => {
                    q.clear_peer();
                    Ok(())
                }
                Disc::TcpConn(entry) => {
                    stack().tcp_disconnect_entry(&entry);
                    entry.conn.lock().state = crate::tcp_state::TcpState::Closed;
                    *sock.peer.lock() = None;
                    *sock.peer6.lock() = None;
                    *sock.kind.lock() = SockKind::TcpInit;
                    Ok(())
                }
                Disc::TcpListener(listener) => {
                    stack().tcp_unlisten_entry(&listener);
                    *sock.kind.lock() = SockKind::TcpInit;
                    Ok(())
                }
                Disc::Bad => Err(NetError::Einval),
            }
        }
        RemoteAddr::Unix(addr) => super::unix::connect(sock, addr, nonblock),
        RemoteAddr::Inet { ip: dst_ip, port } => {
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
            // TCP active open: allocate local port if unbound, default
            // local IP to loopback if ANY, kick stack, drain a few
            // times, fail with Etimedout (mapped at the ABI layer)
            // if we don't reach Established.
            //
            // Lock-across-match hazard: a match scrutinee like
            // `match *sock.local_port.lock() { … None => *sock.local_port.lock() = … }`
            // keeps the scrutinee's MutexGuard alive across the arms
            // (Rust temporary scoping rule), and the None arm's
            // re-lock deadlocks against it. Read the slot, drop the
            // guard, then re-acquire to assign.
            let local_port = {
                let cur = *sock.local_port.lock();
                match cur {
                    Some(p) => p,
                    None    => {
                        let p = alloc_ephemeral_port()?;
                        *sock.local_port.lock() = Some(p);
                        p
                    }
                }
            };
            // F156: source-IP pick matches socket_sendto's F150 logic —
            // an ANY-bound TCP socket connecting to a remote slirp
            // address must claim src=iface_primary (10.0.2.15) not
            // src=127.0.0.1, or the SYN-ACK can never come back.
            let bound = *sock.local_ip.lock();
            let local_ip = if bound != Ipv4Addr::ANY {
                bound
            } else if dst_ip.is_loopback() {
                Ipv4Addr::LOOPBACK
            } else {
                let bound_iface = bound_iface(sock)?;
                stack().routes.lookup(dst_ip)
                    .and_then(|r| r.src_hint)
                    .or_else(|| iface_primary_ip(bound_iface.or_else(|| stack().routes.lookup(dst_ip).map(|r| r.iface))))
                    .unwrap_or(Ipv4Addr::LOOPBACK)
            };
            let entry = stack().tcp_connect_ip_bound(
                crate::addr::IpAddr::V4(local_ip), local_port,
                crate::addr::IpAddr::V4(dst_ip), port,
                bound_iface(sock)?,
            )?;
            // F181a: bind owning fd's subscribers so deliver_tcp can
            // wake epoll without broadcasting.
            entry.register_poll_subs(&sock.poll_subs);
            apply_tcp_keepalive_opts(sock, &entry);
            *sock.kind.lock() = SockKind::TcpConn(entry.clone());
            *sock.peer.lock() = Some((dst_ip, port));
            if nonblock { return Err(NetError::Einprogress); }
            // F159: park on entry.rx_waiters for the SYN-ACK. The
            // virtio_net_rx_kthread drives the SYN retransmission
            // timer (RFC 6298) and aborts after 6 SYN retries;
            // deliver_tcp wakes us on the SYN-ACK that drives state
            // to Established, and tcp_retx_tick wakes us when it
            // flips state to Closed on retry-exhaustion. Race-safe:
            // we re-check state under entry.conn.lock() each iter;
            // wakes are issued post-mutation.
            crate::sock_io::connect_wait_established(&entry)
        }
        RemoteAddr::Inet6 { ip, port } => crate::sock_v6::connect_v6(sock, ip, port, nonblock),
    }
}


/// `listen` per `listen(2)`. AF_UNIX bind reserves the local address and this
/// call publishes it as connectable. F176: SO_REUSEADDR forwarded.
/// # C: O(1)
pub fn listen(sock: &alloc::sync::Arc<InetSocket>, backlog: i32) -> Result<(), NetError> {
    let net_ns = sock.net_ns.load(core::sync::atomic::Ordering::Acquire);
    let somaxconn = crate::sysctl::somaxconn_in(net_ns);
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
    let port = sock.local_port.lock().ok_or(NetError::Einval)?;
    let reuseaddr = sock.opts.reuseaddr.load(core::sync::atomic::Ordering::Acquire) != 0;
    let reuseport = sock.opts.reuseport.load(core::sync::atomic::Ordering::Acquire) != 0;
    let fam = sock.family.load(core::sync::atomic::Ordering::Acquire);
    let local_ip = if fam == AF_INET6 {
        crate::addr::IpAddr::V6(*sock.local_ip6.lock())
    } else {
        crate::addr::IpAddr::V4(*sock.local_ip.lock())
    };
    let le = stack().tcp_listen_ip_with(local_ip, port, reuseaddr, reuseport)?;
    le.set_bound_iface(bound_iface(sock)?);
    le.set_backlog(backlog, somaxconn);
    le.register_poll_subs(&sock.poll_subs);
    *sock.kind.lock() = SockKind::TcpListener(le);
    Ok(())
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
        let new_sock = alloc::sync::Arc::new(InetSocket::new_tcp());
        new_sock.net_ns.store(
            sock.net_ns.load(core::sync::atomic::Ordering::Acquire),
            core::sync::atomic::Ordering::Release,
        );
        // The accepted connection is AF_UNIX: SO_DOMAIN must report AF_UNIX, not
        // the `new_tcp` default of AF_INET. dbus-broker's SASL EXTERNAL auth
        // checks the peer connection's domain (getsockopt SO_DOMAIN / SO_PEERCRED);
        // an AF_INET-reporting accepted socket failed that check, so dbus-broker
        // closed every client connection ("Connection terminated" on systemd's
        // AddMatch), which timed out every Type=dbus unit and stalled multi-user →
        // graphical. Same class as the socketpair SO_DOMAIN fix (PR #2313).
        new_sock.family.store(AF_UNIX, core::sync::atomic::Ordering::Release);
        // F181a: server end is A. Register subscribers before
        // assigning the kind so the first write from peer-B sees
        // a live subscription.
        pair.register_end_subs(crate::UnixEnd::A, &new_sock.poll_subs);
        *new_sock.kind.lock() = SockKind::Unix(pair, crate::UnixEnd::A);
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
    let listener_fam = sock.family.load(core::sync::atomic::Ordering::Acquire);
    let new_sock = alloc::sync::Arc::new(
        if listener_fam == AF_INET6 { InetSocket::new_tcp6() } else { InetSocket::new_tcp() }
    );
    new_sock.net_ns.store(
        sock.net_ns.load(core::sync::atomic::Ordering::Acquire),
        core::sync::atomic::Ordering::Release,
    );
    inherit_tcp_keepalive_opts(&new_sock, sock);
    entry.register_poll_subs(&new_sock.poll_subs);
    apply_tcp_keepalive_opts(&new_sock, &entry);
    *new_sock.kind.lock() = SockKind::TcpConn(entry);
    // F180b: pin the peer slot for the family the listener was opened
    // in. v6 listeners only ever see v6 conns (deliver path keys by
    // IpAddr); same for v4.
    let peer_v4 = match peer_ip_any { crate::addr::IpAddr::V4(a) => Some((a, peer_port)), _ => None };
    let peer_v6 = match peer_ip_any { crate::addr::IpAddr::V6(a) => Some((a, peer_port)), _ => None };
    if let Some(p) = peer_v4 { *new_sock.peer.lock() = Some(p); }
    if let Some(p) = peer_v6 { *new_sock.peer6.lock() = Some(p); }
    Ok(Accepted { new_sock, peer: peer_v4, unix_gc_pin: None })
}


/// `sendto`/`send` per `sendto(2)`. work fn — ABI shim
/// supplies the payload as a slice, the optional destination as a
/// typed RemoteAddr, and the sender's creds for AF_UNIX SCM.
///
/// Behaviour by socket kind:
///   UnixDgram  → push to peer's queue (dest required)
///   TcpConn    → tcp_send + drain
///   Udp/other  → socket_sendto with dest or stored peer
/// # C: O(payload bytes)
pub fn sendto(
    sock: &InetSocket,
    payload: &[u8],
    dest: Option<RemoteAddr>,
    creds: SenderCreds,
) -> Result<usize, NetError> {
    if sock.write_shut.load(core::sync::atomic::Ordering::Acquire) { return Err(NetError::Epipe); }
    // F134: AF_UNIX SOCK_SEQPACKET / SOCK_DGRAM on a socketpair.
    // dhcpcd's launcher waits on its grandchild via
    //   send(fork_fd, &exit_code, sizeof(exit_code), MSG_EOR)
    // over a SOCK_SEQPACKET socketpair. Previously sendto fell
    // through to the AF_INET UDP arm + Eaddrnotavail because there
    // was no dest path or peer recorded, so the launcher hung
    // forever waiting on a signal it could never receive.
    if let SockKind::UnixMsgPair(pair, end) = &*sock.kind.lock() {
        let pair = pair.clone();
        let end = *end;
        return pair.send(end, payload).map_err(|e| match e {
            crate::UnixMsgError::PeerClosed => NetError::Epipe,
            crate::UnixMsgError::PeerRefused => NetError::Econnrefused,
        });
    }
    // AF_UNIX SOCK_STREAM socketpair: same shape, byte ring instead.
    if let SockKind::Unix(pair, end) = &*sock.kind.lock() {
        let pair = pair.clone();
        let end = *end;
        return pair.write(end, payload).map_err(|_| NetError::Epipe);
    }
    // AF_UNIX SOCK_DGRAM: explicit dest or connected peer.
    if let SockKind::UnixDgram(q) = &*sock.kind.lock() {
        let sender = q.bound();
        let path = match dest.clone() {
            Some(RemoteAddr::Unix(p)) => p,
            Some(RemoteAddr::Unspec) => return Err(NetError::Einval),
            _ => q.peer().ok_or(NetError::Edestaddrreq)?,
        };
        let q = crate::net_ns::unix_registry_for_addr(&path).dgram_lookup_addr(&path)
            .ok_or(NetError::Econnrefused)?;
        crate::trace_dgram_journal(&path.display, payload);
        q.try_push_from(crate::UnixDgram {
            payload: payload.to_vec(),
            creds: (creds.pid, creds.uid, creds.gid),
            fds: alloc::vec::Vec::new(),
        }, sender)?;
        return Ok(payload.len());
    }
    // TCP: send into the existing connection.
    if let SockKind::TcpConn(entry) = &*sock.kind.lock() {
        let entry = entry.clone();
        let cap = sock.opts.sndbuf.load(core::sync::atomic::Ordering::Acquire)
            .max(TCP_SNDBUF_DEFAULT) as usize;
        let nodelay = sock.opts.tcp_nodelay.load(core::sync::atomic::Ordering::Acquire) != 0;
        let cork = sock.opts.tcp_cork.load(core::sync::atomic::Ordering::Acquire) != 0;
        let n = stack().tcp_send(&entry, payload, cap, nodelay, cork)?;
        drain_loopback();
        return Ok(n);
    }
    // UDP/other: dest or stored peer.
    if let Some(RemoteAddr::Inet6 { ip, port }) = dest {
        return crate::sock_v6::sendto_v6(sock, ip, port, payload);
    }
    if sock.family.load(core::sync::atomic::Ordering::Acquire) == AF_INET6 {
        let (ip, port) = sock.peer6.lock().ok_or(NetError::Edestaddrreq)?;
        return crate::sock_v6::sendto_v6(sock, ip, port, payload);
    }
    let (dst_ip, dst_port) = match dest {
        Some(RemoteAddr::Inet { ip, port }) => (ip, port),
        Some(RemoteAddr::Unspec)            => return Err(NetError::Einval),
        Some(RemoteAddr::Unix(_))           => return Err(NetError::Einval),
        Some(RemoteAddr::Inet6 { .. })      => unreachable!(),
        None => sock.peer.lock().ok_or(NetError::Edestaddrreq)?,
    };
    socket_sendto(sock, dst_ip, dst_port, payload)
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
