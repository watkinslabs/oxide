use crate::addr::{Ipv4Addr, NetIfaceId};
use crate::netdev::{NetError, NetResult};
use crate::sock::{iface_primary_ip, stack, InetSocket};

fn iface_for_addr(addr: Ipv4Addr) -> Option<NetIfaceId> {
    stack().routes.snapshot().into_iter()
        .find(|r| r.src_hint == Some(addr))
        .map(|r| r.iface)
}

/// Select the egress interface for IPv4 multicast sends. # C: O(N routes)
pub(crate) fn bound_iface(sock: &InetSocket, dst: Ipv4Addr) -> NetResult<Option<NetIfaceId>> {
    use core::sync::atomic::Ordering;
    let raw = sock.opts.ip_mcast_ifindex.load(Ordering::Acquire);
    if raw != 0 {
        let id = NetIfaceId::from_raw(raw);
        return if stack().ifaces.lookup(id).is_some() { Ok(Some(id)) } else { Err(NetError::Enetunreach) };
    }
    let addr = Ipv4Addr::from_u32(sock.opts.ip_mcast_ifaddr.load(Ordering::Acquire));
    if !addr.is_unspecified() {
        return iface_for_addr(addr).map(Some).ok_or(NetError::Enetunreach);
    }
    if let Some(r) = stack().routes.lookup(dst) { return Ok(Some(r.iface)); }
    Ok(None)
}

/// True when the selected multicast egress interface is loopback. # C: O(N)
pub(crate) fn is_loopback_iface(bound: Option<NetIfaceId>) -> bool {
    bound.and_then(|id| stack().ifaces.lookup(id)).is_some_and(|dev| dev.name() == "lo")
}

/// Select source address for IPv4 multicast sends. # C: O(N routes)
pub(crate) fn src_ip(sock: &InetSocket, dst: Ipv4Addr, bound: Option<NetIfaceId>) -> Ipv4Addr {
    use core::sync::atomic::Ordering;
    let bound_ip = *sock.local_ip.lock();
    if bound_ip != Ipv4Addr::ANY { return bound_ip; }
    let opt_addr = Ipv4Addr::from_u32(sock.opts.ip_mcast_ifaddr.load(Ordering::Acquire));
    if !opt_addr.is_unspecified() { return opt_addr; }
    stack().routes.lookup(dst)
        .and_then(|r| r.src_hint)
        .or_else(|| iface_primary_ip(bound))
        .unwrap_or(Ipv4Addr::LOOPBACK)
}
