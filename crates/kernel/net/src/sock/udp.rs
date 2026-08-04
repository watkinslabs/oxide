use super::*;

/// AF_INET dgram-socket recv — pops one queued datagram for the
/// bound port. Returns (src_ip, src_port, payload) or None.
/// Also drains lo first so any in-flight loopback packets land
/// in the rx queue before we look.
/// # C: O(1)
pub fn socket_recv(sock: &InetSocket) -> Option<(Ipv4Addr, u16, Vec<u8>)> {
    drain_loopback();
    let q = sock.udp4.lock().as_ref().cloned()?;
    q.recv(false).map(|d| (d.src, d.sport, d.payload))
}

/// AF_INET6 UDP dgram receive — pops one datagram from the v6 port
/// map. Mirror of `socket_recv` for the IPv6 family.
/// # C: O(1)
pub fn socket_recv6(sock: &InetSocket) -> Option<(crate::Ipv6Addr, u16, Vec<u8>)> {
    drain_loopback();
    let q = sock.udp6.lock().as_ref().cloned()?;
    q.recv(false).map(|d| (d.src, d.sport, d.payload))
}

/// AF_INET dgram-socket send — auto-binds an ephemeral local
/// port if not already bound, builds + xmits the datagram,
/// drains lo so an immediate recv on the same socket sees it.
/// # C: O(1)
pub fn socket_sendto(sock: &InetSocket, dst: Ipv4Addr, dst_port: u16, payload: &[u8])
    -> Result<usize, NetError>
{
    let net_ns = sock.net_ns();
    let eno = sock.take_pending_recv_error();
    if eno != 0 { return Err(crate::sock_io::pending_net_error(eno)); }
    if crate::udp::udp4_payload_too_large(payload.len()) { return Err(NetError::Emsgsize); }
    let src_port = sock.ensure_bound()?; let src_ip = *sock.local_ip.lock();
    let bound_iface = if dst.is_multicast() { crate::sock_mcast::bound_iface(sock, dst)? }
        else { super::iface::v4_egress_iface(sock)? };
    // F150: pick the right source IP for outbound. ANY-bound socket
    // → use loopback only when dst is loopback; else consult the
    // route table for the outbound iface and use ITS configured IP.
    // Without this every outbound UDP claims src=127.0.0.1, and
    // replies from a remote peer (slirp's DNS at 10.0.2.3, …) can
    // never make it back since they target loopback not eth0.
    let src_ip = match crate::inet_tx::source_choice(src_ip, dst) {
        crate::inet_tx::SourceChoice::Bound(ip) => ip,
        crate::inet_tx::SourceChoice::Multicast => crate::sock_mcast::src_ip(sock, dst, bound_iface),
        crate::inet_tx::SourceChoice::Loopback => Ipv4Addr::LOOPBACK,
        // The outbound interface's primary IPv4, via the route table.
        crate::inet_tx::SourceChoice::Route => bound_iface
            .and_then(|iface| stack().route_v4_on_iface_in(net_ns, dst, iface).ok().flatten()
                .and_then(|route| route.src_hint))
            .or_else(|| stack().routes.lookup_in(net_ns, dst).and_then(|route| route.src_hint))
            .or_else(|| iface_primary_ip(bound_iface.or_else(|| stack().routes.lookup_in(net_ns, dst).map(|r| r.iface))))
            .unwrap_or(Ipv4Addr::LOOPBACK),
    };
    let multicast = dst.is_multicast();
    let mcast_loop = sock.opts.ip_mcast_loop.load(core::sync::atomic::Ordering::Acquire) != 0;
    let ttl = crate::inet_tx::ipv4_ttl(
        sock.opts.ip_mcast_ttl.load(core::sync::atomic::Ordering::Acquire),
        sock.opts.ip_ttl.load(core::sync::atomic::Ordering::Acquire), multicast);
    let tos = sock.opts.ip_tos.load(core::sync::atomic::Ordering::Acquire) as u8;
    if crate::inet_tx::multicast_delivers_nowhere(multicast, mcast_loop,
        crate::sock_mcast::is_loopback_iface(bound_iface))
    { return Ok(payload.len()); }
    let pmtudisc = sock.opts.ip_mtu_discover.load(core::sync::atomic::Ordering::Acquire);
    // `IP_OPTIONS` rides every datagram this socket sends, and a source route
    // among them retargets the route lookup at its first hop.
    let ip_options = sock.opts.ip.options();
    // `SO_NO_CHECK`: the datagram leaves with a zero checksum field, which an
    // IPv4 receiver reads as "not computed".
    let no_check = sock.opts.generic.flag(crate::sock_opts::sol_socket::flag::NO_CHECK_TX);
    // UDP_SEGMENT: one write becomes N wire datagrams of the segmentation
    // size, the last carrying the remainder.
    let gso = sock.opts.udp.gso_size();
    if gso != 0 {
        let mtu = stack().path_mtu_in(net_ns, crate::addr::IpAddr::V4(dst), bound_iface, false)?
            as usize;
        if let Some(plan) = crate::sock_opts::sol_udp::segment::plan_v4(
            payload.len(), gso, mtu, no_check)?
        {
            for segment in payload.chunks(plan.seg_size) {
                stack().send_udp_pmtu_to_bound_opts_owned(
                    &sock.owner, src_ip, src_port, dst, dst_port, segment, bound_iface, tos, ttl,
                    pmtudisc, ip_options.as_ref(), no_check,
                )?;
            }
            if crate::inet_tx::drains_loopback(multicast, mcast_loop) { drain_loopback(); }
            return Ok(payload.len());
        }
    }
    stack().send_udp_pmtu_to_bound_opts_owned(
        &sock.owner, src_ip, src_port, dst, dst_port, payload, bound_iface, tos, ttl, pmtudisc,
        ip_options.as_ref(), no_check,
    )?;
    if crate::inet_tx::drains_loopback(multicast, mcast_loop) { drain_loopback(); }
    Ok(payload.len())
}
