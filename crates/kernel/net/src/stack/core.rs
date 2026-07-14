use super::*;

impl NetStack {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            ifaces: IfaceRegistry::new(),
            routes: RouteTable::new(),
            routes6: Route6Table::new(),
            inet: Spinlock::new(BTreeMap::new()),
            next_ip_id: Spinlock::new(1),
            next_isn:   Spinlock::new(0x1000_0000),
            ndp:        Spinlock::new(BTreeMap::new()),
            ipv4_reasm: crate::ipv4_reasm::ReasmTable::new(),
            ipv6_reasm: crate::ipv6_reasm::ReasmTable::new(),
            v6_addrs:   Spinlock::new(BTreeMap::new()),
            v6_mcast:   Spinlock::new(BTreeMap::new()), v4_mcast: Spinlock::new(BTreeMap::new()),
        }
    }

    /// F184: MSS for `dst` = egress iface MTU − (v4:40, v6:60). 0 if
    /// no iface — caller falls back to OWN_MSS_DEFAULT. # C: O(log N).
    pub fn mss_for_dst(&self, dst: IpAddr) -> u16 {
        self.mss_for_dst_in(0, dst)
    }

    /// MSS for a destination in one network namespace. # C: O(N routes)
    pub fn mss_for_dst_in(&self, net_ns: u64, dst: IpAddr) -> u16 {
        let mtu = match dst {
            IpAddr::V4(d) => self.routes.lookup_in(net_ns, d)
                .and_then(|r| self.ifaces.lookup_in_ns(r.iface, net_ns))
                .map(|i| i.mtu()),
            IpAddr::V6(d) => self.route6_iface_in(net_ns, d).map(|(_, i)| i.mtu()),
        };
        let overhead = if matches!(dst, IpAddr::V6(_)) { 60 } else { 40 };
        mtu.map(|m| (m.saturating_sub(overhead)).min(0xFFFF) as u16).unwrap_or(0)
    }

    /// Resolve the IPv6 egress interface using longest-prefix match.
    /// # C: O(N routes)
    pub(crate) fn route6_iface(&self, dst: Ipv6Addr) -> Option<(NetIfaceId, Arc<dyn NetDev>)> {
        self.route6_iface_in(0, dst)
    }

    /// Resolve IPv6 egress within one network namespace. # C: O(N routes + N ifaces)
    pub(crate) fn route6_iface_in(&self, net_ns: u64, dst: Ipv6Addr)
        -> Option<(NetIfaceId, Arc<dyn NetDev>)>
    {
        let route = self.routes6.lookup_in(net_ns, dst)?;
        let iface = self.ifaces.lookup_in_ns(route.iface, net_ns)?;
        Some((route.iface, iface))
    }

    /// F180c: is `ip` bound on `iface`? # C: O(N addrs)
    pub fn v6_addr_owned_by(&self, iface: NetIfaceId, ip: crate::addr::Ipv6Addr) -> bool { self.v6_addrs.lock().get(&iface).map(|v| v.iter().any(|a| a.addr == ip)).unwrap_or(false) }
    /// True when an interface has active ownership of an IPv6 multicast group. # C: O(N groups)
    fn v6_mcast_owned_by(&self, iface: NetIfaceId, group: crate::addr::Ipv6Addr) -> bool {
        if group == crate::ndp::IPV6_ALL_NODES { return true; }
        self.v6_mcast.lock().get(&iface).is_some_and(|groups| groups.iter()
            .any(|state| state.group == group && !state.is_empty()))
    }
    /// IPv6 local-input decision with link-local interface scoping. # C: O(N addrs)
    pub(crate) fn v6_dst_is_local(&self, iface: NetIfaceId, ip: crate::addr::Ipv6Addr) -> bool {
        if ip.is_multicast() { return self.v6_mcast_owned_by(iface, ip); }
        if ip.is_link_local() { return self.v6_addr_owned_by(iface, ip); }
        let Some(net_ns) = self.ifaces.namespace(iface) else { return false };
        self.v6_addrs.lock().iter().any(|(id, addrs)| {
            self.ifaces.namespace(*id) == Some(net_ns)
                && addrs.iter().any(|addr| addr.addr == ip)
        })
    }
    /// Pick an IPv6 source address bound to `iface`, if one exists. # C: O(N addrs)
    pub(crate) fn v6_src_on_iface(&self, iface: NetIfaceId) -> Option<crate::addr::Ipv6Addr> { self.v6_addrs.lock().get(&iface).and_then(|v| v.first().map(|a| a.addr)) }

    /// Learn or update an IPv6 neighbor binding scoped to `iface`.
    /// # C: O(log N)
    pub fn ndp_insert(&self, iface: NetIfaceId, ip: Ipv6Addr, mac: MacAddr) {
        self.ndp.lock().insert((iface, ip), mac);
    }

    /// Lookup an IPv6 neighbor binding scoped to `iface`.
    /// # C: O(log N)
    pub fn ndp_lookup(&self, iface: NetIfaceId, ip: Ipv6Addr) -> Option<MacAddr> {
        self.ndp.lock().get(&(iface, ip)).copied()
    }

    /// Boot-time wiring: create + register a loopback netdev,
    /// add canonical loopback routes through it. Returns
    /// the assigned iface id.
    /// # C: O(1)
    pub fn register_loopback(&self) -> (NetIfaceId, Arc<LoopbackDev>) {
        self.register_loopback_in(0)
    }

    /// Register canonical loopback device, addresses, and routes in one namespace. # C: O(N)
    pub fn register_loopback_in(&self, net_ns: u64) -> (NetIfaceId, Arc<LoopbackDev>) {
        let lo = Arc::new(LoopbackDev::new());
        let id = self.ifaces.register_in_ns(lo.clone() as Arc<dyn NetDev>, net_ns);
        self.routes.add_in(net_ns, crate::route::RouteEntry {
            table:      crate::policy_rule::RT_TABLE_LOCAL,
            dst:        Ipv4Addr::new(127, 0, 0, 0),
            prefix_len: 8,
            iface:      id,
            gateway:    None,
            src_hint:   Some(Ipv4Addr::LOOPBACK),
        });
        self.routes6.add_in(net_ns, crate::route6::Route6Entry {
            dst:        Ipv6Addr::LOOPBACK,
            prefix_len: 128,
            iface:      id,
            gateway:    None,
            src_hint:   Some(Ipv6Addr::LOOPBACK),
        });
        self.add_v6_addr(id, Ipv6Addr::LOOPBACK);
        (id, lo)
    }

    /// Remove per-interface network state and unregister the netdev.
    /// # C: O(N routes + N addrs + N groups + N ndp)
    pub fn unregister_iface(&self, iface: NetIfaceId) -> bool {
        self.unregister_iface_in(0, iface)
    }

    /// Remove one namespace-owned interface and all attached network state. # C: O(N)
    pub fn unregister_iface_in(&self, net_ns: u64, iface: NetIfaceId) -> bool {
        if self.ifaces.namespace(iface) != Some(net_ns) { return false; }
        self.routes.retain_in(net_ns, |e| e.iface != iface);
        self.routes6.retain_in(net_ns, |e| e.iface != iface);
        let _ = crate::iface_addr::remove_iface(net_ns, iface);
        self.v6_addrs.lock().remove(&iface);
        self.v6_mcast.lock().remove(&iface);
        self.v4_mcast.lock().remove(&iface);
        self.ndp.lock().retain(|(id, _), _| *id != iface);
        self.ifaces.unregister(iface).is_some()
    }

    /// UDP bind. Eaddrinuse if taken. # C: O(log N)
    pub fn bind_udp(&self, bind_ip: Ipv4Addr, port: u16) -> NetResult<Arc<UdpRxQueue>> {
        self.bind_udp_with_iface(bind_ip, port, None)
    }

    /// UDP bind with an optional SO_BINDTODEVICE filter. # C: O(log N)
    pub fn bind_udp_with_iface(&self, bind_ip: Ipv4Addr, port: u16,
                               iface: Option<NetIfaceId>) -> NetResult<Arc<UdpRxQueue>> {
        self.bind_udp_with_iface_error(bind_ip, port, iface, Arc::new(crate::SocketError::new()))
    }

    /// Bind an IPv4 UDP queue to one socket's canonical error state. # C: O(log N)
    pub fn bind_udp_with_iface_error(&self, bind_ip: Ipv4Addr, port: u16,
                               iface: Option<NetIfaceId>, error: Arc<crate::SocketError>)
        -> NetResult<Arc<UdpRxQueue>> {
        self.bind_udp_socket(bind_ip, port, iface, error,
                             Arc::new(::core::sync::atomic::AtomicI32::new(0)),
                             Arc::new(::core::sync::atomic::AtomicI32::new(0)),
                             Arc::new(::core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
                             0, Arc::new(Spinlock::new(None)),
                             Arc::new(crate::bpf_filter::SocketFilter::new()),
                             Arc::new(crate::mcast_filter::SocketMcast::new()))
    }

    /// Bind and return the exact socket-owned IPv4 UDP endpoint. # C: O(N_port)
    pub fn bind_udp_socket(&self, bind_ip: Ipv4Addr, port: u16,
                           iface: Option<NetIfaceId>, error: Arc<crate::SocketError>,
                           reuseaddr: Arc<::core::sync::atomic::AtomicI32>,
                           reuseport: Arc<::core::sync::atomic::AtomicI32>,
                           ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
                           owner_uid: u32,
                           peer: Arc<Spinlock<Option<(Ipv4Addr, u16)>, StackLockClass>>,
                           bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
                           mcast: Arc<crate::mcast_filter::SocketMcast>)
        -> NetResult<Arc<UdpRxQueue>> {
        self.bind_udp_socket_in(0, bind_ip, port, iface, error, reuseaddr, reuseport,
            ip_mtu_discover, owner_uid, peer, bpf_filter, mcast)
    }

    /// Bind an IPv4 UDP endpoint in its owning network namespace. # C: O(N_port)
    pub fn bind_udp_socket_in(&self, net_ns: u64, bind_ip: Ipv4Addr, port: u16,
                           iface: Option<NetIfaceId>, error: Arc<crate::SocketError>,
                           reuseaddr: Arc<::core::sync::atomic::AtomicI32>,
                           reuseport: Arc<::core::sync::atomic::AtomicI32>,
                           ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
                           owner_uid: u32,
                           peer: Arc<Spinlock<Option<(Ipv4Addr, u16)>, StackLockClass>>,
                           bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
                           mcast: Arc<crate::mcast_filter::SocketMcast>)
        -> NetResult<Arc<UdpRxQueue>> {
        let reuseport_member = reuseport.load(::core::sync::atomic::Ordering::Acquire) != 0;
        let tables = self.inet_tables(net_ns);
        let mut g = tables.udp.lock();
        let udp6 = tables.udp6.lock();
        if let Some(v6_group) = udp6.get(&port) {
            let iface_raw = iface.map(|i| i.raw()).unwrap_or(0);
            for old in v6_group {
                if old.v6only.load(::core::sync::atomic::Ordering::Acquire) != 0 { continue; }
                let addr_overlap = old.bound_ip == Ipv6Addr::ANY
                    || old.bound_ip.to_v4_mapped().is_some_and(|ip| {
                        bind_ip.is_unspecified() || ip == bind_ip
                    });
                if !addr_overlap { continue; }
                let old_iface = old.bound_ifindex.load(::core::sync::atomic::Ordering::Acquire);
                let iface_overlap = old_iface == 0 || iface_raw == 0 || old_iface == iface_raw;
                let shared = old.reuseport_member() && reuseport_member
                        && old.owner_uid == owner_uid
                    || old.reuseaddr.load(::core::sync::atomic::Ordering::Acquire) != 0
                        && reuseaddr.load(::core::sync::atomic::Ordering::Acquire) != 0;
                if iface_overlap && !shared { return Err(NetError::Eaddrinuse); }
            }
        }
        let group = g.entry(port).or_default();
        let iface_raw = iface.map(|i| i.raw()).unwrap_or(0);
        for old in group.iter() {
            let old_iface = old.bound_ifindex.load(::core::sync::atomic::Ordering::Acquire);
            let iface_overlap = old_iface == 0 || iface_raw == 0 || old_iface == iface_raw;
            let addr_overlap = old.bound_ip.is_unspecified() || bind_ip.is_unspecified()
                || old.bound_ip == bind_ip;
            let old_reuseport = old.reuseport_member();
            let old_reuseaddr = old.reuseaddr.load(::core::sync::atomic::Ordering::Acquire) != 0;
            let shared = old_reuseport && reuseport_member
                    && old.owner_uid == owner_uid
                || old_reuseaddr && reuseaddr.load(::core::sync::atomic::Ordering::Acquire) != 0;
            if iface_overlap && addr_overlap && !shared { return Err(NetError::Eaddrinuse); }
        }
        let q = Arc::new(UdpRxQueue::new_socket(
            net_ns, bind_ip, port, error, reuseaddr,
            Arc::new(::core::sync::atomic::AtomicI32::new(i32::from(reuseport_member))),
            ip_mtu_discover,
            owner_uid, peer, bpf_filter, mcast,
        ));
        q.bound_ifindex.store(iface.map(|i| i.raw()).unwrap_or(0), ::core::sync::atomic::Ordering::Release);
        group.push(q.clone());
        Ok(q)
    }

    /// Select socket-owned endpoints for one received IPv4 datagram. # C: O(N_port)
    #[cfg(test)]
    pub(crate) fn udp_demux(&self, src: Ipv4Addr, sport: u16, dst: Ipv4Addr,
                            dport: u16, iface: NetIfaceId) -> Vec<Arc<UdpRxQueue>> {
        self.udp_demux_in(0, src, sport, dst, dport, iface)
    }

    /// Select endpoints in the ingress interface's network namespace. # C: O(N_port)
    pub(crate) fn udp_demux_in(&self, net_ns: u64, src: Ipv4Addr, sport: u16, dst: Ipv4Addr,
                            dport: u16, iface: NetIfaceId) -> Vec<Arc<UdpRxQueue>> {
        let tables = self.inet_tables(net_ns);
        let group = tables.udp.lock().get(&dport).cloned().unwrap_or_default();
        let mut matched = Vec::new();
        let mut best = 0u8;
        let fanout = dst.is_multicast() || dst.is_broadcast();
        for q in group {
            let bound_iface = q.bound_ifindex.load(::core::sync::atomic::Ordering::Acquire);
            if bound_iface != 0 && bound_iface != iface.raw() { continue; }
            if !q.bound_ip.is_unspecified() && q.bound_ip != dst { continue; }
            let peer = *q.peer.lock();
            if peer.is_some() && peer != Some((src, sport)) { continue; }
            let score = u8::from(peer.is_some()) * 4
                + u8::from(!q.bound_ip.is_unspecified()) * 2
                + u8::from(bound_iface != 0);
            if fanout { matched.push(q); continue; }
            if score > best { matched.clear(); best = score; }
            if score == best { matched.push(q); }
        }
        if matched.len() <= 1 || fanout { return matched; }
        let winner = matched.last().cloned().expect("matched is nonempty");
        if !winner.reuseport_member() {
            return alloc::vec![winner];
        }
        let winner_iface = winner.bound_ifindex.load(::core::sync::atomic::Ordering::Acquire);
        matched.retain(|q| {
            q.reuseport_member()
                && q.owner_uid == winner.owner_uid && q.bound_ip == winner.bound_ip
                && q.bound_ifindex.load(::core::sync::atomic::Ordering::Acquire) == winner_iface
        });
        let hash = src.as_u32().rotate_left(7) ^ dst.as_u32().rotate_left(19)
            ^ u32::from(sport).rotate_left(11) ^ u32::from(dport);
        let selected = matched.swap_remove(hash as usize % matched.len());
        alloc::vec![selected]
    }

    /// Find the exact IPv4 UDP sender named by an ICMP-echoed tuple. # C: O(N_port)
    pub(crate) fn udp_error_endpoint(&self, net_ns: u64, iface: NetIfaceId, src: Ipv4Addr, sport: u16,
                                     dst: Ipv4Addr, dport: u16) -> Option<Arc<UdpRxQueue>> {
        self.udp_demux_in(net_ns, dst, dport, src, sport, iface).pop()
    }

    /// Remove exactly one IPv4 UDP endpoint, preserving port peers. # C: O(N_port)
    pub fn unbind_udp_endpoint(&self, endpoint: &Arc<UdpRxQueue>) {
        let port = endpoint.bound_port;
        let tables = self.inet_tables(endpoint.net_ns);
        let mut map = tables.udp.lock();
        if let Some(group) = map.get_mut(&port) {
            group.retain(|q| !Arc::ptr_eq(q, endpoint));
            if group.is_empty() { map.remove(&port); }
        }
        endpoint.deactivate();
    }

    /// Atomically change one endpoint's device scope after conflict validation. # C: O(N_port)
    pub fn rebind_udp_endpoint_iface(&self, endpoint: &Arc<UdpRxQueue>, iface: Option<NetIfaceId>)
        -> NetResult<()> {
        let tables = self.inet_tables(endpoint.net_ns);
        let map = tables.udp.lock();
        let map6 = tables.udp6.lock();
        let group = map.get(&endpoint.bound_port).ok_or(NetError::Einval)?;
        let new_iface = iface.map(|i| i.raw()).unwrap_or(0);
        if let Some(group6) = map6.get(&endpoint.bound_port) {
            for old in group6 {
                if old.v6only.load(::core::sync::atomic::Ordering::Acquire) != 0 { continue; }
                let addr_overlap = old.bound_ip == Ipv6Addr::ANY
                    || old.bound_ip.to_v4_mapped().is_some_and(|ip| {
                        endpoint.bound_ip.is_unspecified() || ip == endpoint.bound_ip
                    });
                if !addr_overlap { continue; }
                let old_iface = old.bound_ifindex.load(::core::sync::atomic::Ordering::Acquire);
                let iface_overlap = old_iface == 0 || new_iface == 0 || old_iface == new_iface;
                let shared = old.reuseport_member() && endpoint.reuseport_member()
                        && old.owner_uid == endpoint.owner_uid
                    || old.reuseaddr.load(::core::sync::atomic::Ordering::Acquire) != 0
                        && endpoint.reuseaddr.load(::core::sync::atomic::Ordering::Acquire) != 0;
                if iface_overlap && !shared { return Err(NetError::Eaddrinuse); }
            }
        }
        for old in group {
            if Arc::ptr_eq(old, endpoint) { continue; }
            let old_iface = old.bound_ifindex.load(::core::sync::atomic::Ordering::Acquire);
            let iface_overlap = old_iface == 0 || new_iface == 0 || old_iface == new_iface;
            let addr_overlap = old.bound_ip.is_unspecified() || endpoint.bound_ip.is_unspecified()
                || old.bound_ip == endpoint.bound_ip;
            let shared = old.reuseport_member() && endpoint.reuseport_member()
                    && old.owner_uid == endpoint.owner_uid
                || old.reuseaddr.load(::core::sync::atomic::Ordering::Acquire) != 0
                    && endpoint.reuseaddr.load(::core::sync::atomic::Ordering::Acquire) != 0;
            if iface_overlap && addr_overlap && !shared { return Err(NetError::Eaddrinuse); }
        }
        endpoint.bound_ifindex.store(new_iface, ::core::sync::atomic::Ordering::Release);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn udp_map(&self) -> Arc<Spinlock<BTreeMap<u16, Vec<Arc<UdpRxQueue>>>, StackLockClass>> {
        self.inet_tables(0).udp.clone()
    }

    #[cfg(test)]
    pub(crate) fn udp6_map(&self) -> Arc<Spinlock<BTreeMap<u16, Vec<Arc<crate::stack_ipv6::Udp6RxQueue>>>, StackLockClass>> {
        self.inet_tables(0).udp6.clone()
    }

    #[cfg(test)]
    pub(crate) fn tcp_conns_map(&self) -> Arc<Spinlock<BTreeMap<TcpKey, Arc<TcpEntry>>, StackLockClass>> {
        self.inet_tables(0).tcp_conns.clone()
    }

    /// F161: pub send_l4_over_ipv4 wrapper. # C: O(payload + route)
    pub fn send_l4_over_ipv4_pub(&self, src: Ipv4Addr, dst: Ipv4Addr, l4: &[u8])
        -> NetResult<()>
    {
        self.send_l4_over_ipv4(src, dst, IpProto::Tcp, l4)
    }

    /// Build + xmit UDP datagram. # C: O(payload + route lookup)
    pub fn send_udp_to(&self, src_ip: Ipv4Addr, src_port: u16,
                        dst_ip: Ipv4Addr, dst_port: u16, payload: &[u8])
        -> NetResult<()>
    {
        // F122: 255.255.255.255 has no specific route entry (DHCP
        // DISCOVER fires before any route is installed). Fall back
        // to the first non-loopback iface so the broadcast lands.
        // Once route tables track scope (LOCAL_BROADCAST etc.), the
        // fallback retires.
        let (iface_id, iface, next_hop) = match self.routes.lookup_result_in(0, dst_ip) {
            Ok(r) => (r.iface, self.ifaces.lookup(r.iface)
                            .ok_or(NetError::Enetunreach)?, r.gateway.unwrap_or(dst_ip)),
            Err(NetError::Enetunreach) if dst_ip.is_broadcast()
                && self.routes.lookup_record_in(0, dst_ip).is_none() => {
                let devs = self.ifaces.snapshot_devs();
                let pick = devs.iter()
                    .find(|(_, d)| d.name() != "lo")
                    .ok_or(NetError::Enetunreach)?;
                (pick.0, pick.1.clone(), dst_ip)
            }
            Err(error) => return Err(error),
        };
        let total = crate::udp::UDP_HDR_LEN + payload.len();
        let mut p = Pkt::with_capacity(IPV4_HDR_LEN, total + IPV4_HDR_LEN);
        let udp_total = crate::udp::UDP_HDR_LEN + payload.len();
        let slot = p.put(udp_total).map_err(|_| NetError::Enobufs)?;
        UdpHdr::build_into(src_port, dst_port, src_ip, dst_ip, payload, slot);
        let id = {
            let mut s = self.next_ip_id.lock();
            *s = s.wrapping_add(1);
            *s
        };
        self.xmit_ipv4_l4_on_iface(
            iface_id, iface, next_hop, src_ip, dst_ip, IpProto::Udp, p.data(), 0, id,
        )
    }
}
