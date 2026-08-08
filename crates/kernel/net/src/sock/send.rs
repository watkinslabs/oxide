use super::*;

/// Arm, recheck, and park one blocking TCP sender on canonical ACK readiness. # C: O(retx) + park
#[cfg(target_os = "oxide-kernel")]
pub fn wait_transmit(sock: &InetSocket, deadline_ns: u64) -> bool {
    let entry = match &*sock.kind.lock() {
        SockKind::TcpConn(entry) => entry.clone(), _ => return false,
    };
    let cap = sock.opts.sndbuf.load(core::sync::atomic::Ordering::Acquire)
        .max(0) as usize;
    if !entry.arm_transmit_wait(&sock.write_shut, cap, deadline_ns) { return true; }
    // SAFETY: arm_transmit_wait published current before dropping conn.
    unsafe { sched::live::schedule::schedule(); }
    entry.rx_waiters.remove_current();
    true
}

/// Transmit one raw IPv4 datagram.
///
/// `#[inline(never)]`: the option area, the control clone and the ping probe
/// are this branch's alone, and `sendto` sits under the deepest send path in
/// the tree — its frame must not carry one protocol's working set into every
/// other protocol's call (Linux `noinline_for_stack`).
/// # C: O(payload bytes)
#[inline(never)]
fn sendto_raw4(sock: &InetSocket, endpoint: &alloc::sync::Arc<crate::raw4::Raw4Endpoint>,
    payload: &[u8], dest: Option<RemoteAddr>, control: &crate::send_control::SendControl,
    tx: crate::TxMeta) -> Result<usize, NetError>
{
    if sock.write_shut.load(core::sync::atomic::Ordering::Acquire) { return Err(NetError::Epipe); }
    let probe;
    let payload = if endpoint.is_ping() {
        probe = crate::ping::prepare_v4(endpoint, payload, control.oob)?;
        &probe[..]
    } else { payload };
    let dst = match dest {
        Some(RemoteAddr::Inet { ip, .. }) => ip,
        None => endpoint.snapshot().remote.ok_or(NetError::Edestaddrreq)?,
        _ => return Err(NetError::Eafnosupport),
    };
    let multicast = dst.is_multicast();
    let iface = if control.raw4.iface.is_some() { control.raw4.iface } else if multicast {
        crate::sock_mcast::bound_iface(sock, dst)?
    } else { super::iface::v4_egress_iface(sock)? };
    let socket_source = if multicast { crate::sock_mcast::src_ip(sock, dst, iface) }
        else { crate::Ipv4Addr::ANY };
    let options = crate::raw4::Raw4TxOptions {
        source: control.raw4.source.or((!socket_source.is_unspecified()).then_some(socket_source)),
        iface,
        tos: control.raw4.tos.unwrap_or(sock.opts.ip_tos.load(core::sync::atomic::Ordering::Acquire) as u8),
        ttl: control.raw4.ttl.unwrap_or(crate::inet_tx::ipv4_ttl(
            sock.opts.ip_mcast_ttl.load(core::sync::atomic::Ordering::Acquire),
            sock.opts.ip_ttl.load(core::sync::atomic::Ordering::Acquire), multicast)),
        pmtudisc: sock.opts.ip_mtu_discover.load(core::sync::atomic::Ordering::Acquire),
        broadcast: sock.opts.broadcast.load(core::sync::atomic::Ordering::Acquire) != 0,
        nodefrag: sock.opts.ip.flag(crate::sock_opts::sol_ip::state::flag::NODEFRAG),
    };
    let mut raw_control = control.raw4.clone();
    // A control message replaces the socket's own option area outright;
    // without one the sticky `IP_OPTIONS` area rides the datagram.
    if raw_control.options.is_none() { raw_control.options = sock.opts.ip.options(); }
    if raw_control.multicast_loop.is_none() {
        raw_control.multicast_loop = Some(
            sock.opts.ip_mcast_loop.load(core::sync::atomic::Ordering::Acquire) != 0);
    }
    stack().send_raw4(endpoint, dst, payload, options, &raw_control, tx)?;
    if crate::send_control::should_drain_loopback(multicast, raw_control.multicast_loop,
        sock.opts.ip_mcast_loop.load(core::sync::atomic::Ordering::Acquire) != 0)
    { drain_loopback(); }
    return Ok(payload.len());
}

/// `sendto`/`send` typed work function for supported socket families. # C: O(payload bytes)
pub fn sendto(sock: &InetSocket, payload: &[u8], dest: Option<RemoteAddr>, creds: SenderCreds,
    control: &crate::send_control::SendControl)
    -> Result<usize, NetError>
{
    let sent = sendto_inner(sock, payload, dest, creds, control);
    // A completed transmit publishes the record its timestamping bits asked
    // for, once, here — the one place that knows both the socket's own bits
    // and the override this message settled over them.
    if sent.is_ok() {
        super::tx_tstamp::publish(sock,
            control.sockcm.tsflags(sock.opts.timestamping.load(
                core::sync::atomic::Ordering::Acquire) as u32),
            control.sockcm.ts_opt_id,
            sock.family.load(core::sync::atomic::Ordering::Acquire) == AF_INET6);
    }
    sent
}

#[inline(never)]
fn sendto_inner(sock: &InetSocket, payload: &[u8], dest: Option<RemoteAddr>, creds: SenderCreds,
    control: &crate::send_control::SendControl)
    -> Result<usize, NetError>
{
    // No security decision here. The transport is entered only after the one
    // message hook has admitted this send, and a second evaluation would both
    // double-count the transaction and let a policy change land mid-message.
    // Every packet this message produces carries one answer for the mark, the
    // transmit band and the departure time: the socket's own, each replaced by
    // the override this message settled. Built once, here.
    let tx = crate::sock::tx_meta(sock, &control.sockcm);
    if matches!(*sock.kind.lock(), SockKind::Packet { .. }) {
        return if sock.has_packet_tx_ring() { sock.kick_packet_tx_ring(None) }
            else { send_packet(sock, payload, None) };
    }
    if let SockKind::Raw4(endpoint) = &*sock.kind.lock() {
        return sendto_raw4(sock, endpoint, payload, dest, control, tx);
    }
    if let SockKind::Raw6(endpoint) = &*sock.kind.lock() {
        if sock.write_shut.load(core::sync::atomic::Ordering::Acquire) { return Err(NetError::Epipe); }
        let probe;
        let payload = if endpoint.is_ping() {
            probe = crate::ping::prepare_v6(endpoint, payload, control.oob)?;
            &probe[..]
        } else { payload };
        let (dst, protocol, scope_id) = match dest {
            Some(RemoteAddr::Inet6 { ip, port, scope_id }) => (ip, Some(port), scope_id),
            None => {
                let peer = endpoint.peer().ok_or(NetError::Edestaddrreq)?;
                (peer.addr, None, peer.scope_id)
            }
            _ => return Err(NetError::Eafnosupport),
        };
        return crate::sock_v6::sendto_raw6(sock, endpoint, dst, protocol, scope_id, payload,
            &control.raw6, tx);
    }
    if matches!(*sock.kind.lock(), SockKind::Udp) {
        let pending = sock.take_pending_recv_error();
        if pending != 0 { return Err(crate::sock_io::pending_net_error(pending)); }
    }
    if sock.write_shut.load(core::sync::atomic::Ordering::Acquire) { return Err(NetError::Epipe); }
    if let SockKind::UnixMsgPair(pair, end) = &*sock.kind.lock() {
        return pair.clone().send(*end, payload).map_err(|e| match e {
            crate::UnixMsgError::PeerClosed => NetError::Epipe,
            crate::UnixMsgError::PeerRefused => NetError::Econnrefused,
        });
    }
    if let SockKind::Unix(pair, end) = &*sock.kind.lock() {
        return pair.clone().write(*end, payload).map_err(|_| NetError::Epipe);
    }
    if let SockKind::UnixDgram(q) = &*sock.kind.lock() {
        let sender = q.bound();
        let path = match dest.clone() {
            Some(RemoteAddr::Unix(p)) => p,
            Some(RemoteAddr::Unspec) => return Err(NetError::Einval),
            _ => q.peer().ok_or(NetError::Edestaddrreq)?,
        };
        // Same abstract-namespace isolation as connect, except that a datagram
        // socket already connected to this peer was admitted when it connected
        // and is not re-checked.
        if q.peer().as_ref().map(|p| p.key != path.key).unwrap_or(true)
            && crate::landlock_glue::abstract_connect_denied(&sock.net_namespace, &path)
        {
            return Err(NetError::Eperm);
        }
        let q = crate::net_ns::unix_registry_for_addr_in(&sock.net_namespace, &path)
            .dgram_lookup_addr(&path)
            .ok_or(NetError::Econnrefused)?;
        crate::trace_dgram_journal(&path.display, payload);
        q.try_push_from(crate::UnixDgram {
            payload: payload.to_vec(), creds: creds.stamp(),
            fds: alloc::vec::Vec::new(),
        }, sender)?;
        return Ok(payload.len());
    }
    if let SockKind::TcpConn(entry) = &*sock.kind.lock() {
        let entry = entry.clone();
        let eno = sock.take_pending_recv_error();
        if eno != 0 { return Err(crate::sock_io::pending_net_error(eno)); }
        if sock.write_shut.load(core::sync::atomic::Ordering::Acquire)
            || crate::stack::tcp_send_closed(entry.conn.lock().state)
        { return Err(NetError::Epipe); }
        let cap = sock.opts.sndbuf.load(core::sync::atomic::Ordering::Acquire)
            .max(0) as usize;
        let nodelay = sock.opts.tcp_nodelay.load(core::sync::atomic::Ordering::Acquire) != 0;
        let cork = sock.opts.tcp_cork.load(core::sync::atomic::Ordering::Acquire) != 0;
        let n = stack().tcp_send(&entry, payload, cap, nodelay, cork)?;
        drain_loopback();
        return Ok(n);
    }
    if matches!(*sock.kind.lock(), SockKind::Udp) {
        // A corked datagram never reaches the builders below: the cork owns
        // the destination and the accumulated bytes until it is pushed.
        if let Some(n) = crate::sock_opts::sol_udp::emit::intercept(sock, &dest, payload)? {
            return Ok(n);
        }
    }
    if let Some(RemoteAddr::Inet6 { ip, port, scope_id }) = dest {
        return crate::sock_v6::sendto_v6_ctl(sock, ip, port, scope_id, payload, &control.raw6, tx);
    }
    if sock.family.load(core::sync::atomic::Ordering::Acquire) == AF_INET6 {
        let (ip, port) = sock.peer6.lock().ok_or(NetError::Edestaddrreq)?;
        let scope_id = sock.peer6_scope.load(core::sync::atomic::Ordering::Acquire);
        return crate::sock_v6::sendto_v6_ctl(sock, ip, port, scope_id, payload, &control.raw6, tx);
    }
    let (dst_ip, dst_port) = match dest {
        Some(RemoteAddr::Inet { ip, port }) => (ip, port),
        Some(RemoteAddr::Unspec) | Some(RemoteAddr::Unix(_)) => return Err(NetError::Einval),
        Some(RemoteAddr::Inet6 { .. }) => unreachable!(),
        None => sock.peer.lock().ok_or(NetError::Edestaddrreq)?,
    };
    socket_sendto_ctl(sock, dst_ip, dst_port, payload, &control.raw4, tx)
}
