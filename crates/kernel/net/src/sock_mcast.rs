use crate::addr::{Ipv4Addr, Ipv6Addr, NetIfaceId};
use crate::mcast_filter::{FilterMode, SourceFilter, SourceFilter6, SourceOp};
use crate::netdev::{NetError, NetResult};
use crate::sock::{iface_primary_ip, stack, InetSocket};

fn iface_for_addr(net_ns: u64, addr: Ipv4Addr) -> Option<NetIfaceId> {
    stack().routes.snapshot_in(net_ns).into_iter()
        .find(|r| r.src_hint == Some(addr))
        .map(|r| r.iface)
}

fn resolve_v4_iface(sock: &InetSocket, requested: u32, ifaddr: Ipv4Addr,
                    group: Ipv4Addr) -> NetResult<NetIfaceId> {
    use core::sync::atomic::Ordering;
    let net_ns = sock.net_ns.load(Ordering::Acquire);
    let bound = sock.opts.bound_ifindex.load(Ordering::Acquire);
    let mut raw = requested;
    if raw == 0 && !ifaddr.is_unspecified() {
        raw = iface_for_addr(net_ns, ifaddr).ok_or(NetError::Enodev)?.raw();
    }
    if bound != 0 {
        if raw != 0 && raw != bound { return Err(NetError::Enodev); }
        raw = bound;
    }
    if raw == 0 { raw = sock.opts.ip_mcast_ifindex.load(Ordering::Acquire); }
    if raw == 0 {
        let addr = Ipv4Addr::from_u32(sock.opts.ip_mcast_ifaddr.load(Ordering::Acquire));
        if !addr.is_unspecified() { raw = iface_for_addr(net_ns, addr).ok_or(NetError::Enodev)?.raw(); }
    }
    if raw == 0 { raw = stack().routes.lookup_in(net_ns, group).map(|route| route.iface.raw()).unwrap_or(0); }
    if raw == 0 {
        let routes = stack().routes.snapshot_in(net_ns);
        if routes.len() == 1 { raw = routes[0].iface.raw(); }
    }
    if raw == 0 { return Err(NetError::Enodev); }
    let iface = NetIfaceId::from_raw(raw);
    stack().ifaces.lookup_in_ns(iface, net_ns).map(|_| iface).ok_or(NetError::Enodev)
}

/// Select the egress interface for IPv4 multicast sends. # C: O(N routes)
pub(crate) fn bound_iface(sock: &InetSocket, dst: Ipv4Addr) -> NetResult<Option<NetIfaceId>> {
    use core::sync::atomic::Ordering;
    let net_ns = sock.net_ns.load(Ordering::Acquire);
    let device = sock.opts.bound_ifindex.load(Ordering::Acquire);
    let mut selected = sock.opts.ip_mcast_ifindex.load(Ordering::Acquire);
    if selected == 0 {
        let addr = Ipv4Addr::from_u32(sock.opts.ip_mcast_ifaddr.load(Ordering::Acquire));
        if !addr.is_unspecified() {
            selected = iface_for_addr(net_ns, addr).map(NetIfaceId::raw).ok_or(NetError::Enetunreach)?;
        }
    }
    if device != 0 {
        if selected != 0 && selected != device { return Err(NetError::Enetunreach); }
        selected = device;
    }
    if selected != 0 {
        let id = NetIfaceId::from_raw(selected);
        return stack().ifaces.lookup_in_ns(id, net_ns).map(|_| Some(id)).ok_or(NetError::Enetunreach);
    }
    if let Some(r) = stack().routes.lookup_in(net_ns, dst) { return Ok(Some(r.iface)); }
    Ok(None)
}

/// Select IPv6 multicast egress under IPV6_MULTICAST_IF and SO_BINDTODEVICE. # C: O(N)
pub(crate) fn bound_iface6(sock: &InetSocket, dst: Ipv6Addr) -> NetResult<Option<NetIfaceId>> {
    use core::sync::atomic::Ordering;
    if !dst.is_multicast() { return crate::sock::bound_iface(sock); }
    let device = sock.opts.bound_ifindex.load(Ordering::Acquire);
    let mut selected = sock.opts.ipv6_mcast_ifindex.load(Ordering::Acquire);
    if device != 0 {
        if selected != 0 && selected != device { return Err(NetError::Enetunreach); }
        selected = device;
    }
    if selected == 0 { return Ok(None); }
    let id = NetIfaceId::from_raw(selected);
    let net_ns = sock.net_ns.load(Ordering::Acquire);
    stack().ifaces.lookup_in_ns(id, net_ns).map(|_| Some(id)).ok_or(NetError::Enetunreach)
}

/// True when the selected multicast egress interface is loopback. # C: O(N)
pub(crate) fn is_loopback_iface(bound: Option<NetIfaceId>) -> bool {
    bound.and_then(|id| stack().ifaces.namespace(id).map(|net_ns| (id, net_ns)))
        .and_then(|(id, net_ns)| stack().ifaces.lookup_in_ns(id, net_ns))
        .is_some_and(|dev| dev.name() == "lo")
}

/// Select source address for IPv4 multicast sends. # C: O(N routes)
pub(crate) fn src_ip(sock: &InetSocket, dst: Ipv4Addr, bound: Option<NetIfaceId>) -> Ipv4Addr {
    use core::sync::atomic::Ordering;
    let bound_ip = *sock.local_ip.lock();
    if bound_ip != Ipv4Addr::ANY { return bound_ip; }
    let opt_addr = Ipv4Addr::from_u32(sock.opts.ip_mcast_ifaddr.load(Ordering::Acquire));
    if !opt_addr.is_unspecified() { return opt_addr; }
    let net_ns = sock.net_ns.load(Ordering::Acquire);
    stack().routes.lookup_in(net_ns, dst)
        .and_then(|r| r.src_hint)
        .or_else(|| iface_primary_ip(bound))
        .unwrap_or(Ipv4Addr::LOOPBACK)
}

impl InetSocket {
    fn mcast_guard(&self) -> NetResult<sync::Guard<'_, Option<u16>, sync::Socket>> {
        use core::sync::atomic::Ordering;
        let guard = self.local_port.lock();
        if self.released.load(Ordering::Acquire) { return Err(NetError::Einval); }
        Ok(guard)
    }

    /// Set IPv4 multicast interface after resolving address/index ownership. # C: O(N)
    pub fn set_v4_mcast_iface(&self, addr: Ipv4Addr, ifindex: u32) -> NetResult<()> {
        use core::sync::atomic::Ordering;
        let net_ns = self.net_ns.load(Ordering::Acquire);
        let bound = self.opts.bound_ifindex.load(Ordering::Acquire);
        if ifindex != 0 && stack().ifaces.lookup_in_ns(NetIfaceId::from_raw(ifindex), net_ns).is_none() {
            return Err(NetError::Enodev);
        }
        let addr_iface = if ifindex == 0 && !addr.is_unspecified() {
            Some(iface_for_addr(net_ns, addr).ok_or(NetError::Enodev)?.raw())
        } else { None };
        let selected = if ifindex != 0 { Some(ifindex) } else { addr_iface };
        if bound != 0 && selected.is_some_and(|iface| iface != bound) { return Err(NetError::Einval); }
        self.opts.ip_mcast_ifaddr.store(addr.as_u32(), Ordering::Release);
        self.opts.ip_mcast_ifindex.store(ifindex, Ordering::Release);
        Ok(())
    }

    /// Set IPv6 multicast interface after validating device ownership. # C: O(N)
    pub fn set_v6_mcast_iface(&self, ifindex: u32) -> NetResult<()> {
        use core::sync::atomic::Ordering;
        let net_ns = self.net_ns.load(Ordering::Acquire);
        let bound = self.opts.bound_ifindex.load(Ordering::Acquire);
        if ifindex != 0 && stack().ifaces.lookup_in_ns(NetIfaceId::from_raw(ifindex), net_ns).is_none() {
            return Err(NetError::Enodev);
        }
        if bound != 0 && ifindex != 0 && ifindex != bound { return Err(NetError::Einval); }
        self.opts.ipv6_mcast_ifindex.store(ifindex, Ordering::Release);
        Ok(())
    }

    /// Join or leave IPv4 multicast without implicitly binding a port. # C: O(N)
    pub fn change_v4_mcast(&self, iface: NetIfaceId, group: Ipv4Addr,
                           report_src: Ipv4Addr, join: bool) -> NetResult<()> {
        let _guard = self.mcast_guard()?;
        let net_ns = self.net_ns.load(core::sync::atomic::Ordering::Acquire);
        self.mcast.change_v4_in(stack(), net_ns, iface, group, report_src, join)
    }

    /// Apply one IPv4 source-membership operation atomically. # C: O(N + S)
    pub fn source_v4_mcast(&self, iface: NetIfaceId, group: Ipv4Addr,
                           report_src: Ipv4Addr, source: Ipv4Addr, op: SourceOp) -> NetResult<()> {
        let _guard = self.mcast_guard()?;
        let net_ns = self.net_ns.load(core::sync::atomic::Ordering::Acquire);
        self.mcast.source_v4_in(stack(), net_ns, iface, group, report_src, source, op)
    }

    /// Replace one IPv4 multicast source filter atomically. # C: O(N + S)
    pub fn set_v4_mcast_filter(&self, iface: NetIfaceId, group: Ipv4Addr,
                               report_src: Ipv4Addr, mode: FilterMode,
                               sources: &[Ipv4Addr]) -> NetResult<()> {
        let _guard = self.mcast_guard()?;
        let net_ns = self.net_ns.load(core::sync::atomic::Ordering::Acquire);
        self.mcast.set_v4_in(stack(), net_ns, iface, group, report_src, mode, sources)
    }

    /// Snapshot one IPv4 multicast source filter. # C: O(log N + S)
    pub fn v4_mcast_filter(&self, iface: NetIfaceId, group: Ipv4Addr) -> SourceFilter {
        self.mcast.get_v4(iface, group).expect("membership checked by caller")
    }

    /// Resolve and change IPv4 membership inside the network owner. # C: O(N)
    pub fn change_v4_mcast_req(&self, requested: u32, ifaddr: Ipv4Addr,
                               group: Ipv4Addr, join: bool) -> NetResult<()> {
        let _guard = self.mcast_guard()?;
        let iface = resolve_v4_iface(self, requested, ifaddr, group)?;
        let report_src = *self.local_ip.lock();
        let net_ns = self.net_ns.load(core::sync::atomic::Ordering::Acquire);
        self.mcast.change_v4_in(stack(), net_ns, iface, group, report_src, join)
    }

    /// Resolve and apply one IPv4 source operation in the network owner. # C: O(N + S)
    pub fn source_v4_mcast_req(&self, requested: u32, ifaddr: Ipv4Addr, group: Ipv4Addr,
                               source: Ipv4Addr, op: SourceOp) -> NetResult<()> {
        let _guard = self.mcast_guard()?;
        let iface = resolve_v4_iface(self, requested, ifaddr, group)?;
        let net_ns = self.net_ns.load(core::sync::atomic::Ordering::Acquire);
        self.mcast.source_v4_in(stack(), net_ns, iface, group, *self.local_ip.lock(), source, op)
    }

    /// Resolve and replace one IPv4 filter in the network owner. # C: O(N + S)
    pub fn set_v4_mcast_filter_req(&self, requested: u32, ifaddr: Ipv4Addr, group: Ipv4Addr,
                                   mode: FilterMode, sources: &[Ipv4Addr]) -> NetResult<()> {
        let _guard = self.mcast_guard()?;
        let iface = resolve_v4_iface(self, requested, ifaddr, group)?;
        let net_ns = self.net_ns.load(core::sync::atomic::Ordering::Acquire);
        self.mcast.set_v4_in(stack(), net_ns, iface, group, *self.local_ip.lock(), mode, sources)
    }

    /// Resolve and snapshot one IPv4 filter in the network owner. # C: O(N + S)
    pub fn get_v4_mcast_filter_req(&self, requested: u32, ifaddr: Ipv4Addr,
                                   group: Ipv4Addr) -> NetResult<SourceFilter> {
        let _guard = self.mcast_guard()?;
        let iface = resolve_v4_iface(self, requested, ifaddr, group)?;
        self.mcast.get_v4(iface, group)
    }

    fn resolve_v6_mcast_iface(&self, requested: u32, group: Ipv6Addr) -> NetResult<NetIfaceId> {
        use core::sync::atomic::Ordering;
        crate::mcast_filter::resolve_v6_iface(stack(), self.net_ns.load(Ordering::Acquire), requested,
            self.opts.bound_ifindex.load(Ordering::Acquire),
            self.opts.ipv6_mcast_ifindex.load(Ordering::Acquire), group)
    }

    /// Join or leave IPv6 multicast without implicitly binding a port. # C: O(N)
    pub fn change_v6_mcast(&self, requested: u32, group: Ipv6Addr, join: bool) -> NetResult<()> {
        let _guard = self.mcast_guard()?;
        let iface = self.resolve_v6_mcast_iface(requested, group)?;
        let local = *self.local_ip6.lock();
        let net_ns = self.net_ns.load(core::sync::atomic::Ordering::Acquire);
        let report_src = if !local.is_unspecified() { local } else {
            stack().mld_src_on_iface(iface)
                .or_else(|| stack().routes6.lookup_in(net_ns, group)
                    .filter(|route| route.iface == iface).and_then(|route| route.src_hint))
                .unwrap_or(Ipv6Addr::ANY)
        };
        self.mcast.change_v6_in(stack(), net_ns, iface, group, report_src, join)
    }

    fn v6_report_src(&self, iface: NetIfaceId, group: Ipv6Addr) -> Ipv6Addr {
        let local = *self.local_ip6.lock();
        let net_ns = self.net_ns.load(core::sync::atomic::Ordering::Acquire);
        if !local.is_unspecified() { return local; }
        stack().mld_src_on_iface(iface)
            .or_else(|| stack().routes6.lookup_in(net_ns, group)
                .filter(|route| route.iface == iface).and_then(|route| route.src_hint))
            .unwrap_or(Ipv6Addr::ANY)
    }

    /// Resolve and apply one IPv6 source operation in the network owner. # C: O(N + S)
    pub fn source_v6_mcast(&self, requested: u32, group: Ipv6Addr,
                           source: Ipv6Addr, op: SourceOp) -> NetResult<()> {
        let _guard = self.mcast_guard()?;
        let iface = self.resolve_v6_mcast_iface(requested, group)?;
        let net_ns = self.net_ns.load(core::sync::atomic::Ordering::Acquire);
        self.mcast.source_v6_in(stack(), net_ns, iface, group, self.v6_report_src(iface, group), source, op)
    }

    /// Resolve and replace one IPv6 filter in the network owner. # C: O(N + S)
    pub fn set_v6_mcast_filter(&self, requested: u32, group: Ipv6Addr,
                               mode: FilterMode, sources: &[Ipv6Addr]) -> NetResult<()> {
        let _guard = self.mcast_guard()?;
        let iface = self.resolve_v6_mcast_iface(requested, group)?;
        let net_ns = self.net_ns.load(core::sync::atomic::Ordering::Acquire);
        self.mcast.set_v6_in(stack(), net_ns, iface, group, self.v6_report_src(iface, group), mode, sources)
    }

    /// Resolve and snapshot one IPv6 filter in the network owner. # C: O(N + S)
    pub fn get_v6_mcast_filter(&self, requested: u32, group: Ipv6Addr) -> NetResult<SourceFilter6> {
        let _guard = self.mcast_guard()?;
        let iface = self.resolve_v6_mcast_iface(requested, group)?;
        self.mcast.get_v6(iface, group)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;

    #[test]
    fn implicit_udp_bind_rejects_foreign_namespace_device() {
        const SOCK_NS: u64 = 71_001;
        const FOREIGN_NS: u64 = 71_002;
        let stack = crate::global_stack();
        let (foreign, _) = stack.register_loopback_in(FOREIGN_NS);
        let sock = InetSocket::new_udp();
        sock.net_ns.store(SOCK_NS, Ordering::Release);
        sock.set_bound_iface(Some(foreign)).unwrap();
        assert_eq!(sock.ensure_bound(), Err(NetError::Enodev));
        assert!(stack.unregister_iface_in(FOREIGN_NS, foreign));
    }
}
