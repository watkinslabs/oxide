use super::*;
use alloc::string::String;

pub enum BoundAddr {
    /// `bind` on an AF_UNIX SOCK_STREAM/SOCK_SEQPACKET socket —
    /// register a listener at `path`.
    UnixListener(String),
    /// `bind` on an AF_UNIX SOCK_DGRAM socket — register the
    /// already-allocated queue at `path`.
    UnixDgram { path: String, queue: alloc::sync::Arc<crate::UnixDgramQueue> },
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
        BoundAddr::UnixListener(path) => {
            let listener = UNIX_REGISTRY.bind(path).map_err(|_| NetError::Eaddrinuse)?;
            // Link the listener socket's epoll subscribers so connect() can wake an
            // epoll_wait-blocked accept loop (dbus-broker) on a new connection.
            listener.register_subs(&sock.poll_subs);
            *sock.kind.lock() = SockKind::UnixListener(listener);
            Ok(())
        }
        BoundAddr::UnixDgram { path, queue } => {
            UNIX_REGISTRY.dgram_bind(path, queue).map_err(|_| NetError::Eaddrinuse)
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
    /// `connect`/`sendto` on AF_UNIX — registry lookup by path.
    UnixPath(String),
    /// `connect`/`sendto` on AF_INET — IPv4 destination.
    Inet { ip: Ipv4Addr, port: u16 },
    /// F180b: `connect`/`sendto` on AF_INET6 — IPv6 destination.
    Inet6 { ip: crate::Ipv6Addr, port: u16 },
}

/// # C: O(1) for UDP/UNIX, O(drain_iterations) for TCP.
pub fn connect(sock: &alloc::sync::Arc<InetSocket>, addr: RemoteAddr) -> Result<(), NetError> {
    match addr {
        RemoteAddr::UnixPath(path) => {
            if let SockKind::UnixDgram(q) = &*sock.kind.lock() {
                if UNIX_REGISTRY.dgram_lookup(&path).is_none() {
                    return Err(NetError::Econnrefused);
                }
                q.set_peer(path);
                return Ok(());
            }
            // B47: connect to a non-existent AF_UNIX path returns
            // ECONNREFUSED on Linux (no listener) — used to return
            // ENOBUFS which dhcpcd treated as fatal "out of buffer
            // memory" instead of "nobody home, I'll create my own
            // socket and listen".
            let pair = UNIX_REGISTRY.connect(&path).ok_or(NetError::Econnrefused)?;
            // F181a: client end is B; register subscribers before
            // setting kind so peer-A writes find live subs.
            pair.register_end_subs(crate::UnixEnd::B, &sock.poll_subs);
            // SO_PEERCRED: the connecting task owns end B.
            if let Some(c) = sched::live::current() {
                use core::sync::atomic::Ordering;
                pair.set_end_cred(crate::UnixEnd::B, c.visible_pid(),
                    c.creds.euid.load(Ordering::Relaxed), c.creds.egid.load(Ordering::Relaxed));
            }
            *sock.kind.lock() = SockKind::Unix(pair, crate::UnixEnd::B);
            Ok(())
        }
        RemoteAddr::Inet { ip: dst_ip, port } => {
            let is_dgram = matches!(*sock.kind.lock(), SockKind::Udp);
            if is_dgram {
                *sock.peer.lock() = Some((dst_ip, port));
                return Ok(());
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
                STACK.routes.lookup(dst_ip)
                    .and_then(|r| r.src_hint)
                    .or_else(|| iface_primary_ip(bound_iface.or_else(|| STACK.routes.lookup(dst_ip).map(|r| r.iface))))
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
        RemoteAddr::Inet6 { ip, port } => crate::sock_v6::connect_v6(sock, ip, port),
    }
}


/// `listen` per `listen(2)`. AF_UNIX listeners bind(2) does the
/// work; listen is a no-op. F176: SO_REUSEADDR forwarded.
/// # C: O(1)
pub fn listen(sock: &alloc::sync::Arc<InetSocket>, backlog: i32) -> Result<(), NetError> {
    // AF_UNIX listener (incl. socket-activated /run/udev/control passed to
    // udevd): register the listener's epoll subscribers against the socket's
    // `poll_subs` so `UnixRegistry::connect`'s `notify_subs` targets the epoll
    // that ADD'd this fd — not just the global rescan fallback (60§R22).
    if let SockKind::UnixListener(l) = &*sock.kind.lock() {
        l.register_subs(&sock.poll_subs);
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
    le.set_backlog(backlog);
    le.register_poll_subs(&sock.poll_subs);
    *sock.kind.lock() = SockKind::TcpListener(le);
    Ok(())
}

/// Result of `accept` — a new socket plus optionally the peer
/// address for the ABI layer to write back to the user `sockaddr`.
pub struct Accepted {
    pub new_sock: alloc::sync::Arc<InetSocket>,
    pub peer: Option<(Ipv4Addr, u16)>,
}

/// `accept` per `accept(2)`. Non-blocking: returns Err(Eagain) when
/// no connection is ready. work fn — caller (ABI shim)
/// wraps the returned `InetSocket` in a vfs::File and allocates a fd.
/// # C: O(1) + drain
pub fn accept(sock: &alloc::sync::Arc<InetSocket>) -> Result<Accepted, NetError> {
    drain_loopback();
    // AF_UNIX listener: pop one queued UnixPair.
    if let SockKind::UnixListener(l) = &*sock.kind.lock() {
        let l = l.clone();
        let pair = l.accept_q.lock().pop_front().ok_or(NetError::Eagain)?;
        let new_sock = alloc::sync::Arc::new(InetSocket::new_tcp());
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
        // SO_PEERCRED: the accepting task owns end A.
        if let Some(c) = sched::live::current() {
            use core::sync::atomic::Ordering;
            pair.set_end_cred(crate::UnixEnd::A, c.visible_pid(),
                c.creds.euid.load(Ordering::Relaxed), c.creds.egid.load(Ordering::Relaxed));
        }
        *new_sock.kind.lock() = SockKind::Unix(pair, crate::UnixEnd::A);
        return Ok(Accepted { new_sock, peer: None });
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
    Ok(Accepted { new_sock, peer: peer_v4 })
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
    sock: &alloc::sync::Arc<InetSocket>,
    payload: &[u8],
    dest: Option<RemoteAddr>,
    creds: SenderCreds,
) -> Result<usize, NetError> {
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
        return Ok(pair.send(end, payload));
    }
    // AF_UNIX SOCK_STREAM socketpair: same shape, byte ring instead.
    if let SockKind::Unix(pair, end) = &*sock.kind.lock() {
        let pair = pair.clone();
        let end = *end;
        return Ok(pair.write(end, payload));
    }
    // AF_UNIX SOCK_DGRAM: explicit dest or connected peer.
    if let SockKind::UnixDgram(q) = &*sock.kind.lock() {
        let path = match dest.clone() {
            Some(RemoteAddr::UnixPath(p)) => p,
            _ => q.peer().ok_or(NetError::Eaddrnotavail)?,
        };
        let q = UNIX_REGISTRY.dgram_lookup(&path).ok_or(NetError::Enobufs)?;
        crate::trace_dgram_journal(&path, payload);
        q.push(crate::UnixDgram {
            payload: payload.to_vec(),
            creds: (creds.pid, creds.uid, creds.gid),
            fds: alloc::vec::Vec::new(),
        });
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
    let (dst_ip, dst_port) = match dest {
        Some(RemoteAddr::Inet { ip, port }) => (ip, port),
        Some(RemoteAddr::UnixPath(_))       => return Err(NetError::Einval),
        Some(RemoteAddr::Inet6 { .. })      => unreachable!(),
        None => sock.peer.lock().ok_or(NetError::Eaddrnotavail)?,
    };
    socket_sendto(sock, dst_ip, dst_port, payload)
}
