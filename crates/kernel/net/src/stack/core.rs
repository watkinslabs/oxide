use super::*;

impl NetStack {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            ifaces: IfaceRegistry::new(),
            routes: RouteTable::new(),
            routes6: Route6Table::new(),
            udp:    Spinlock::new(BTreeMap::new()),
            udp6:   Spinlock::new(BTreeMap::new()),
            tcp_conns:   Spinlock::new(BTreeMap::new()),
            tcp_listens: Spinlock::new(BTreeMap::new()),
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
        let mtu = match dst {
            IpAddr::V4(d) => self.routes.lookup(d)
                .and_then(|r| self.ifaces.lookup(r.iface))
                .map(|i| i.mtu()),
            IpAddr::V6(d) => self.route6_iface(d).map(|(_, i)| i.mtu()),
        };
        let overhead = if matches!(dst, IpAddr::V6(_)) { 60 } else { 40 };
        mtu.map(|m| (m.saturating_sub(overhead)).min(0xFFFF) as u16).unwrap_or(0)
    }

    /// Resolve the IPv6 egress interface using longest-prefix match.
    /// # C: O(N routes)
    pub(crate) fn route6_iface(&self, dst: Ipv6Addr) -> Option<(NetIfaceId, Arc<dyn NetDev>)> {
        let route = self.routes6.lookup(dst)?;
        let iface = self.ifaces.lookup(route.iface)?;
        Some((route.iface, iface))
    }

    /// F180c: is `ip` bound on `iface`? # C: O(N addrs)
    pub fn v6_addr_owned_by(&self, iface: NetIfaceId, ip: crate::addr::Ipv6Addr) -> bool { self.v6_addrs.lock().get(&iface).map(|v| v.iter().any(|a| a.addr == ip)).unwrap_or(false) }
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
        let lo = Arc::new(LoopbackDev::new());
        let id = self.ifaces.register(lo.clone() as Arc<dyn NetDev>);
        self.routes.add(crate::route::RouteEntry {
            table:      crate::policy_rule::RT_TABLE_LOCAL,
            dst:        Ipv4Addr::new(127, 0, 0, 0),
            prefix_len: 8,
            iface:      id,
            gateway:    None,
            src_hint:   Some(Ipv4Addr::LOOPBACK),
        });
        self.routes6.add(crate::route6::Route6Entry {
            dst:        Ipv6Addr::LOOPBACK,
            prefix_len: 128,
            iface:      id,
            gateway:    None,
            src_hint:   Some(Ipv6Addr::LOOPBACK),
        });
        (id, lo)
    }

    /// Remove per-interface network state and unregister the netdev.
    /// # C: O(N routes + N addrs + N groups)
    pub fn unregister_iface(&self, iface: NetIfaceId) -> bool {
        let ns = crate::netdev::current_net_ns();
        self.routes.retain(|e| e.iface != iface);
        self.routes6.retain(|e| e.iface != iface);
        let _ = crate::iface_addr::remove_iface(ns, iface);
        self.v6_addrs.lock().remove(&iface);
        self.v6_mcast.lock().remove(&iface);
        self.v4_mcast.lock().remove(&iface);
        self.ifaces.unregister(iface).is_some()
    }

    /// SO_ATTACH_BPF / SO_DETACH_BPF: set/clear the UDP port's socket filter
    /// (false if nothing is bound there). # C: O(log N)
    pub fn set_udp_bpf_filter(&self, port: u16, insns: Option<Vec<u8>>) -> bool {
        let q = { self.udp.lock().get(&port).cloned() };
        match q { Some(q) => { *q.bpf_filter.lock() = insns; true } None => false }
    }

    /// UDP bind. Eaddrinuse if taken. # C: O(log N)
    pub fn bind_udp(&self, bind_ip: Ipv4Addr, port: u16) -> NetResult<()> {
        self.bind_udp_with_iface(bind_ip, port, None)
    }

    /// UDP bind with an optional SO_BINDTODEVICE filter. # C: O(log N)
    pub fn bind_udp_with_iface(&self, bind_ip: Ipv4Addr, port: u16,
                               iface: Option<NetIfaceId>) -> NetResult<()> {
        let mut g = self.udp.lock();
        if g.contains_key(&port) { return Err(NetError::Eaddrinuse); }
        let q = Arc::new(UdpRxQueue::new(bind_ip, port));
        q.bound_ifindex.store(iface.map(|i| i.raw()).unwrap_or(0), ::core::sync::atomic::Ordering::Release);
        g.insert(port, q);
        Ok(())
    }

    /// Update the bound iface for an already-bound UDP port. # C: O(log N)
    pub fn set_udp_bound_iface(&self, port: u16, iface: Option<NetIfaceId>) -> bool {
        if let Some(q) = self.udp.lock().get(&port) {
            q.bound_ifindex.store(iface.map(|i| i.raw()).unwrap_or(0), ::core::sync::atomic::Ordering::Release);
            true
        } else { false }
    }

    /// Pop one queued datagram or None. # C: O(log N)
    pub fn recv_udp(&self, port: u16) -> Option<(Ipv4Addr, u16, Vec<u8>)> {
        self.recv_udp_opts(port, false)
    }

    /// Pop or peek one queued datagram or None. Peeking clones the
    /// front payload and leaves queue state unchanged.
    /// # C: O(log N + payload bytes when peeking)
    pub fn recv_udp_opts(&self, port: u16, peek: bool) -> Option<(Ipv4Addr, u16, Vec<u8>)> {
        let (src, sport, _, _, payload) = self.recv_udp_meta_opts(port, peek)?;
        Some((src, sport, payload))
    }

    /// Pop or peek one queued datagram with destination/interface metadata.
    /// # C: O(log N + payload bytes when peeking)
    pub fn recv_udp_meta_opts(&self, port: u16, peek: bool)
        -> Option<(Ipv4Addr, u16, Ipv4Addr, NetIfaceId, Vec<u8>)>
    {
        let q = { self.udp.lock().get(&port)?.clone() };
        let mut g = q.q.lock();
        if peek { g.front().cloned() } else { g.pop_front() }
    }

    /// F162: clone the per-port UdpRxQueue Arc out of the udp map so
    /// callers (sys_recvfrom) can park on its waitlist without holding
    /// the map lock. None when nothing's bound.
    /// # C: O(log N)
    pub fn udp_queue_arc(&self, port: u16) -> Option<Arc<UdpRxQueue>> {
        self.udp.lock().get(&port).cloned()
    }

    /// F161: release UDP port (from Drop). # C: O(log N)
    pub fn unbind_udp(&self, port: u16) { crate::mcast_filter::clear_port(port); self.udp.lock().remove(&port); }

    /// F180a: v6 UDP map accessor. # C: O(1)
    pub fn udp6_map(&self) -> &Spinlock<BTreeMap<u16, Arc<crate::stack_ipv6::Udp6RxQueue>>, StackLockClass> {
        &self.udp6
    }
    /// F174: expose udp v4 map for stack_icmp. # C: O(1)
    pub fn udp_map(&self) -> &Spinlock<BTreeMap<u16, Arc<UdpRxQueue>>, StackLockClass> { &self.udp }
    /// F174: expose tcp conn map for stack_icmp. # C: O(1)
    pub fn tcp_conns_map(&self) -> &Spinlock<BTreeMap<TcpKey, Arc<TcpEntry>>, StackLockClass> { &self.tcp_conns }
    /// # C: O(1) — caller locks before iterating
    pub fn tcp_listens_map(&self) -> &Spinlock<BTreeMap<TcpListenKey, Vec<Arc<TcpListenEntry>>>, StackLockClass> { &self.tcp_listens }

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
        let (iface_id, iface) = match self.routes.lookup(dst_ip) {
            Some(r) => (r.iface, self.ifaces.lookup(r.iface)
                            .ok_or(NetError::Enetunreach)?),
            None if dst_ip.is_broadcast() => {
                let devs = self.ifaces.snapshot_devs();
                let pick = devs.iter()
                    .find(|(_, d)| d.name() != "lo")
                    .ok_or(NetError::Enetunreach)?;
                (pick.0, pick.1.clone())
            }
            None => return Err(NetError::Enetunreach),
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
        self.xmit_ipv4_l4_on_iface(iface_id, iface, src_ip, dst_ip, IpProto::Udp, p.data(), 0, id)
    }
}
