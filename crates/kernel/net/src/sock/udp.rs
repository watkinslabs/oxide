use super::*;

/// AF_INET dgram-socket recv — pops one queued datagram for the
/// bound port. Returns (src_ip, src_port, payload) or None.
/// Also drains lo first so any in-flight loopback packets land
/// in the rx queue before we look.
/// # C: O(1)
pub fn socket_recv(sock: &InetSocket) -> Option<(Ipv4Addr, u16, Vec<u8>)> {
    drain_loopback();
    let port = (*sock.local_port.lock())?;
    STACK.recv_udp(port)
}

/// AF_INET6 UDP dgram receive — pops one datagram from the v6 port
/// map. Mirror of `socket_recv` for the IPv6 family.
/// # C: O(1)
pub fn socket_recv6(sock: &InetSocket) -> Option<(crate::Ipv6Addr, u16, Vec<u8>)> {
    drain_loopback();
    let port = (*sock.local_port.lock())?;
    STACK.recv_udp6(port)
}

/// F150: boot-installed hook: iface primary IPv4 lookup. # C: O(1)
static IFACE_PRIMARY_IP_HOOK: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
pub type IfacePrimaryIpFn = fn(NetIfaceId) -> Option<Ipv4Addr>;

/// # C: O(1) — atomic store; install once at boot.
pub fn set_iface_primary_ip_hook(f: IfacePrimaryIpFn) {
    IFACE_PRIMARY_IP_HOOK.store(f as *mut (), core::sync::atomic::Ordering::Release);
}

/// # C: O(1)
pub(crate) fn iface_primary_ip(id: Option<NetIfaceId>) -> Option<Ipv4Addr> {
    let id = id?;
    let p = IFACE_PRIMARY_IP_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: hook installed via set_iface_primary_ip_hook with a function pointer of the IfacePrimaryIpFn shape.
    let f: IfacePrimaryIpFn = unsafe { core::mem::transmute(p) };
    f(id)
}

/// # C: O(N_ifaces)
pub(crate) fn bound_iface(sock: &InetSocket) -> Result<Option<NetIfaceId>, NetError> {
    stack().bound_iface(sock.opts.bound_ifindex.load(core::sync::atomic::Ordering::Acquire))
}

/// AF_INET dgram-socket send — auto-binds an ephemeral local
/// port if not already bound, builds + xmits the datagram,
/// drains lo so an immediate recv on the same socket sees it.
/// # C: O(1)
pub fn socket_sendto(sock: &InetSocket, dst: Ipv4Addr, dst_port: u16, payload: &[u8])
    -> Result<usize, NetError>
{
    let src_port = sock.ensure_bound()?; let src_ip = *sock.local_ip.lock();
    let bound_iface = if dst.is_multicast() { crate::sock_mcast::bound_iface(sock, dst)? } else { bound_iface(sock)? };
    // F150: pick the right source IP for outbound. ANY-bound socket
    // → use loopback only when dst is loopback; else consult the
    // route table for the outbound iface and use ITS configured IP.
    // Without this every outbound UDP claims src=127.0.0.1, and
    // replies from a remote peer (slirp's DNS at 10.0.2.3, …) can
    // never make it back since they target loopback not eth0.
    let src_ip = if src_ip != Ipv4Addr::ANY {
        src_ip
    } else if dst.is_multicast() {
        crate::sock_mcast::src_ip(sock, dst, bound_iface)
    } else if dst.is_loopback() {
        Ipv4Addr::LOOPBACK
    } else {
        // Find the outbound iface's primary IPv4 via the route table.
        STACK.routes.lookup(dst)
            .and_then(|r| r.src_hint)
            .or_else(|| iface_primary_ip(bound_iface.or_else(|| STACK.routes.lookup(dst).map(|r| r.iface))))
            .unwrap_or(Ipv4Addr::LOOPBACK)
    };
    let mcast_loop = sock.opts.ip_mcast_loop.load(core::sync::atomic::Ordering::Acquire) != 0; let ttl = if dst.is_multicast() { sock.opts.ip_mcast_ttl.load(core::sync::atomic::Ordering::Acquire) } else { sock.opts.ip_ttl.load(core::sync::atomic::Ordering::Acquire) } as u8;
    let tos = sock.opts.ip_tos.load(core::sync::atomic::Ordering::Acquire) as u8; if dst.is_multicast() && !mcast_loop && crate::sock_mcast::is_loopback_iface(bound_iface) { return Ok(payload.len()); }
    STACK.send_udp_to_bound_opts(src_ip, src_port, dst, dst_port, payload, bound_iface, tos, ttl)?;
    if !dst.is_multicast() || mcast_loop { drain_loopback(); }
    Ok(payload.len())
}
