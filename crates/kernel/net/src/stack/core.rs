use super::*;

impl NetStack {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            rtnl: crate::rtnl::Rtnl::new(),
            ifaces: IfaceRegistry::new(),
            routes: RouteTable::new(),
            routes6: Route6Table::new(),
            arp_proxy: crate::arp::proxy::ProxyTable::new(),
            bridges: crate::stack::bridge::BridgeTable::new(),
            bridge_pending: Spinlock::new(BTreeMap::new()),
            inet: super::inet_tables::InetTableLock::new(BTreeMap::new()),
            next_ip_id: Spinlock::new(1),
            ipv4_reasm: crate::ipv4_reasm::ReasmTable::new(),
            ipv6_reasm: crate::ipv6_reasm::ReasmTable::new(),
            v6_addrs:   super::types::StackBhLock::new(BTreeMap::new()),
            v6_anycast: super::types::StackBhLock::new(BTreeMap::new()),
            v6_ra_pending: super::types::StackBhLock::new(Vec::new()),
            softnet: [const { Spinlock::new(crate::backlog::queue::SoftnetData::new()) }; cpu::MAX_CPUS],
            rx_poll: Spinlock::new(Vec::new()),
            v6_mcast:   super::types::StackBhLock::new(BTreeMap::new()),
            v4_mcast:   super::types::StackBhLock::new(BTreeMap::new()),
            #[cfg(not(target_os = "oxide-kernel"))]
            ra_now_ns: ::core::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Acquire process-context serialization for RTNL control-plane mutations.
    /// # C: O(contention)
    /// # Ctx: schedulable process context
    /// # Lk: stack RTNL lock acquired
    /// # Sleeps: never
    pub fn rtnl_lock(&self) -> crate::RtnlGuard<'_> { self.rtnl.lock(self) }

    /// Linux `rtnl_trylock`. # C: O(1)
    pub fn rtnl_trylock(&self) -> Option<crate::RtnlGuard<'_>> { self.rtnl.try_lock(self) }

    /// Canonical policy-rule table owned by this network stack. # C: O(1)
    pub fn policy_rules(&self) -> &crate::policy_rule::PolicyRuleTable { self.routes.policy_rules() }

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

    /// Resolve IPv6 egress within one network namespace. # C: O(N routes + N ifaces)
    pub(crate) fn route6_iface_in(&self, net_ns: u64, dst: Ipv6Addr)
        -> Option<(NetIfaceId, crate::EgressLease)>
    {
        let route = self.routes6.lookup_policy_in(net_ns, dst, self.policy_rules())?;
        let iface = self.ifaces.acquire_egress_in_ns(route.iface, net_ns)?;
        Some((route.iface, iface))
    }

    /// F180c: is `ip` bound on `iface`? # C: O(N addrs)
    pub fn v6_addr_owned_by(&self, iface: NetIfaceId, ip: crate::addr::Ipv6Addr) -> bool {
        let now_ns = self.ra_now_ns();
        self.v6_addrs.lock().get(&iface)
            .map(|rows| rows.iter().any(|row| row.addr == ip && row.usable_at(now_ns)))
            .unwrap_or(false)
    }
    /// True when an interface has active ownership of an IPv6 multicast group. # C: O(N groups)
    fn v6_mcast_owned_by(&self, iface: NetIfaceId, group: crate::addr::Ipv6Addr) -> bool {
        if group == crate::ndp::IPV6_ALL_NODES { return true; }
        let now_ns = self.ra_now_ns();
        if self.v6_addrs.lock().get(&iface).is_some_and(|rows| rows.iter().any(|row| {
            row.valid_at(now_ns) && crate::ndp::solicited_node_multicast(row.addr) == group
        })) { return true; }
        self.v6_mcast.lock().get(&iface).is_some_and(|groups| groups.iter()
            .any(|state| state.group == group && !state.is_empty()))
    }
    /// True when an IPv4 multicast packet belongs to the ingress interface. # C: O(N groups + sources)
    pub(crate) fn v4_mcast_owned_by(&self, net_ns: u64, iface: NetIfaceId,
                                    group: crate::addr::Ipv4Addr, src: crate::addr::Ipv4Addr,
                                    proto: u8) -> bool {
        if group == crate::igmp::IPV4_ALL_HOSTS { return true; }
        let Some(generation) = self.ifaces.control_generation_in_ns_rx(iface, net_ns) else {
            return false;
        };
        self.v4_mcast.lock().get(&iface).is_some_and(|groups| groups.iter().any(|state|
            state.iface_generation() == generation && state.group == group
                && state.admits_rx(src, proto)))
    }
    /// IPv6 local-input decision with link-local interface scoping. # C: O(N addrs)
    pub(crate) fn v6_dst_is_local(&self, iface: NetIfaceId, ip: crate::addr::Ipv6Addr) -> bool {
        let now_ns = self.ra_now_ns();
        if ip.is_multicast() { return self.v6_mcast_owned_by(iface, ip); }
        if self.v6_anycast_owned_by(iface, ip) { return true; }
        if ip.is_link_local() { return self.v6_addr_owned_by(iface, ip); }
        let Some(net_ns) = self.ifaces.namespace(iface) else { return false };
        self.v6_addrs.lock().iter().any(|(id, addrs)| {
            self.ifaces.namespace(*id) == Some(net_ns)
                && addrs.iter().any(|addr| addr.addr == ip && addr.usable_at(now_ns))
        })
    }
    /// Pick an IPv6 source address bound to `iface`, if one exists. # C: O(N addrs)
    pub(crate) fn v6_src_on_iface(&self, iface: NetIfaceId) -> Option<crate::addr::Ipv6Addr> {
        self.v6_select_source(iface, crate::Ipv6Addr::ANY, None)
    }

    /// Resolve an advisory route source against live address preference. # C: O(N addrs)
    pub(crate) fn v6_select_source(&self, iface: NetIfaceId, dst: crate::addr::Ipv6Addr,
        hint: Option<crate::addr::Ipv6Addr>) -> Option<crate::addr::Ipv6Addr>
    {
        self.v6_select_source_with_prefs(iface, dst, hint, 0)
    }

    /// Select a source using this socket's `IPV6_ADDR_PREFERENCES` policy.
    /// # C: O(N addrs)
    pub(crate) fn v6_select_source_with_prefs(&self, iface: NetIfaceId,
        dst: crate::addr::Ipv6Addr, hint: Option<crate::addr::Ipv6Addr>, prefs: i32)
        -> Option<crate::addr::Ipv6Addr>
    {
        self.v6_select_source_current(iface, dst, hint, prefs)
    }

    /// Learn or update an IPv6 neighbor binding scoped to `iface`.
    /// # C: O(log N)
    pub fn ndp_insert(&self, iface: NetIfaceId, ip: Ipv6Addr, mac: MacAddr) {
        // Learning releases whatever was parked on this neighbour, exactly as
        // the IPv4 half does: the packets waiting for the address are handed
        // back with it attached rather than dropped.
        if let Some(cache) = self.ifaces.ndp_cache_for(iface) {
            for job in cache.learn_at(ip, mac, crate::neigh::NudState::Reachable,
                crate::stack::net_now_ns()) { job.resume(mac); }
        }
        self.bridge_neighbour_resolved(iface, IpAddr::V6(ip));
    }

    /// Lookup an IPv6 neighbor binding scoped to `iface`.
    /// # C: O(log N)
    pub fn ndp_lookup(&self, iface: NetIfaceId, ip: Ipv6Addr) -> Option<MacAddr> {
        self.ifaces.ndp_cache_for(iface).and_then(|cache| cache.lookup(ip))
    }

    /// Remove one IPv6 neighbor binding scoped to `iface`, returning its prior
    /// link address when present (RTM_DELNEIGH). # C: O(log N)
    pub fn ndp_remove(&self, iface: NetIfaceId, ip: Ipv6Addr) -> Option<MacAddr> {
        let cache = self.ifaces.ndp_cache_for(iface)?;
        let entry = cache.remove(ip)?;
        for job in entry.pending { job.complete(Err(crate::NetError::Ehostunreach)); }
        entry.mac
    }

    /// Snapshot every IPv6 neighbor binding live in `ns`, paired with each
    /// owning interface's namespace-local index (RTM_GETNEIGH). # C: O(N)
    pub fn ndp_snapshot_in_ns(&self, ns: u64) -> Vec<(u32, Ipv6Addr, MacAddr)> {
        let mut rows: Vec<(NetIfaceId, Ipv6Addr, MacAddr)> = Vec::new();
        for (iface, _) in self.ifaces.snapshot_devs_in_ns(ns) {
            let Some(cache) = self.ifaces.ndp_cache_for(iface) else { continue };
            for (ip, mac) in cache.snapshot_bindings() { rows.push((iface, ip, mac)); }
        }
        rows.into_iter().filter_map(|(iface, ip, mac)| {
            self.ifaces.ifindex_in_ns(iface, ns).map(|ifindex| (ifindex, ip, mac))
        }).collect()
    }

    /// Boot-time wiring: create + register a loopback netdev,
    /// add canonical loopback routes through it. Returns
    /// the assigned iface id.
    /// # C: O(1)
    pub fn register_loopback(&self) -> (NetIfaceId, Arc<LoopbackDev>) {
        let owner = network_namespace::initial();
        self.register_loopback_for(&owner)
    }

    /// Register canonical loopback state for one concrete namespace owner. # C: O(N)
    pub fn register_loopback_for(&self, owner: &network_namespace::NetworkNamespaceRef)
        -> (NetIfaceId, Arc<LoopbackDev>)
    {
        let _tables = self.inet_tables_for(owner);
        let rtnl = self.rtnl_lock();
        let (id, lo, ticket) = self.register_loopback_in_rtnl(&rtnl, owner);
        drop(rtnl);
        crate::control_event::publish(ticket);
        (id, lo)
    }

    /// Register canonical loopback device, addresses, and routes in one namespace. # C: O(N)
    #[cfg(not(target_os = "oxide-kernel"))]
    pub fn register_loopback_in(&self, net_ns: u64) -> (NetIfaceId, Arc<LoopbackDev>) {
        let owner = if net_ns == 0 { network_namespace::initial() }
            else { network_namespace::lookup_u64(net_ns)
                .expect("hosted loopback namespace must remain live") };
        let _tables = self.inet_tables_for(&owner);
        let lo = Arc::new(LoopbackDev::new());
        let id = self.ifaces.register_in_ns(lo.clone() as Arc<dyn NetDev>, net_ns);
        let rtnl = self.rtnl_lock();
        self.configure_loopback_in_rtnl(&rtnl, net_ns, id);
        self.register_rx_poll(id, &lo);
        (id, lo)
    }

    /// Materialize and publish canonical loopback state under stack RTNL. # C: O(N)
    /// # Lk: matching stack RTNL held by `rtnl`
    pub(crate) fn register_loopback_in_rtnl(&self, rtnl: &crate::RtnlGuard<'_>,
                                            owner: &network_namespace::NetworkNamespaceRef)
        -> (NetIfaceId, Arc<LoopbackDev>, u64)
    {
        let _tables = self.inet_tables_for(owner);
        let net_ns = owner.id().as_u64();
        let (reg, lo) = self.prepare_loopback_in_rtnl(rtnl, owner);
        let id = reg.id();
        assert!(self.ifaces.publish(rtnl, reg));
        self.register_rx_poll(id, &lo);
        self.configure_loopback_in_rtnl(rtnl, net_ns, id);
        let properties = crate::control_event::LinkProperties {
            name: alloc::string::String::from("lo"), mac: crate::MacAddr::ZERO,
            broadcast: crate::PacketLinkAddress { len: 6, bytes: [0; crate::PACKET_LINK_ADDRESS_MAX] },
            mtu: 65_535, is_loopback: true, stats: crate::NetStats::default(),
        };
        let event = self.live_link_event(
            rtnl, crate::control_event::NamespaceOwner::Live(owner.clone()), id,
            properties, crate::control_event::EventKind::New).unwrap();
        let _link_ticket = crate::control_event::stage(
            rtnl, crate::control_event::ControlEvent::Link(event));
        let generation = self.ifaces.control_generation_in_ns(rtnl, id, net_ns).unwrap();
        let iface_owner = crate::control_event::IfaceOwner { iface: id, generation };
        let namespace = crate::control_event::NamespaceOwner::Live(owner.clone());
        let row4 = crate::iface_addr::snapshot_ns(net_ns).into_iter().find(|row| {
            row.iface == id && row.addr == Ipv4Addr::LOOPBACK && row.prefixlen == 8
        }).unwrap();
        let _addr4_ticket = crate::control_event::stage(rtnl,
            crate::control_event::ControlEvent::Addr(crate::control_event::AddrEvent {
                kind: crate::control_event::EventKind::New, namespace: namespace.clone(),
                owner: iface_owner, label: alloc::string::String::from("lo"), row: row4,
            }));
        let route4 = self.routes.snapshot_records_in(net_ns).into_iter().find(|record| {
            let route = record.route;
            route.iface == id && route.table == crate::policy_rule::RT_TABLE_LOCAL
                && route.dst == Ipv4Addr::new(127, 0, 0, 0) && route.prefix_len == 8
        }).unwrap();
        let _route4_ticket = crate::control_event::stage(rtnl,
            crate::control_event::ControlEvent::Route(crate::control_event::RouteEvent {
                kind: crate::control_event::EventKind::New, namespace: namespace.clone(),
                owners: alloc::vec![iface_owner], leases: alloc::vec::Vec::new(),
                records: alloc::vec![route4],
            }));
        let row = self.v6_addrs.lock().get(&id).and_then(|rows| rows.iter()
            .find(|row| row.addr == Ipv6Addr::LOOPBACK)).cloned().unwrap();
        let _addr_ticket = crate::control_event::stage(rtnl,
            crate::control_event::ControlEvent::Addr6(crate::control_event::Addr6Event {
                kind: crate::control_event::EventKind::New, namespace: namespace.clone(),
                owner: iface_owner, label: alloc::string::String::from("lo"), row,
            }));
        let route = self.routes6.snapshot_in(net_ns).into_iter().find(|route| {
            route.iface == id && route.dst == Ipv6Addr::LOOPBACK && route.prefix_len == 128
        }).unwrap();
        let ticket = crate::control_event::stage(rtnl,
            crate::control_event::ControlEvent::Route6(crate::control_event::Route6Event {
                kind: crate::control_event::EventKind::New, namespace,
                owners: alloc::vec![iface_owner], rows: alloc::vec![route],
            }));
        (id, lo, ticket)
    }

    /// Prepare an unpublished loopback generation. # C: O(1)
    /// # Lk: matching stack RTNL held by `rtnl`
    pub(crate) fn prepare_loopback_in_rtnl(&self, rtnl: &crate::RtnlGuard<'_>,
                                           owner: &network_namespace::NetworkNamespaceRef)
        -> (crate::netdev::IfaceRegistration<'_>, Arc<LoopbackDev>)
    {
        let lo = Arc::new(LoopbackDev::new());
        let reg = self.ifaces.prepare_in_ns(rtnl, lo.clone() as Arc<dyn NetDev>, owner)
            .expect("matching stack RTNL");
        (reg, lo)
    }

    /// Configure canonical loopback state after interface publication. # C: O(N)
    /// # Lk: matching stack RTNL held by `rtnl`
    fn configure_loopback_in_rtnl(&self, _rtnl: &crate::RtnlGuard<'_>, net_ns: u64,
                                   id: NetIfaceId) {
        // LOCAL type, not the unicast default: every address 127.0.0.0/8
        // covers is delivered to this host, and the bind screen reads the
        // type rather than the table it sits in.
        self.routes.add_record_in(net_ns, crate::route::RouteRecord::local(
            crate::route::RouteEntry {
                table:      crate::policy_rule::RT_TABLE_LOCAL,
                dst:        Ipv4Addr::new(127, 0, 0, 0),
                prefix_len: 8,
                iface:      id,
                gateway:    None,
                src_hint:   Some(Ipv4Addr::LOOPBACK),
            }));
        self.routes6.add_in(net_ns, crate::route6::Route6Entry {
            table:      crate::policy_rule::RT_TABLE_LOCAL,
            dst:        Ipv6Addr::LOOPBACK,
            prefix_len: 128,
            iface:      id,
            gateway:    None,
            src_hint:   Some(Ipv6Addr::LOOPBACK),
            origin:     crate::route6::Route6Origin::Static,
        });
        self.add_v6_addr(id, Ipv6Addr::LOOPBACK);
        // The reference sets `IFAPROT_KERNEL_LO` on the loopback address it
        // installs itself, so a reader can tell it from one an agent added.
        let mut meta = crate::iface_addr::Ipv4AddrMeta::permanent(crate::iface_addr::RT_SCOPE_HOST);
        meta.proto = crate::iface_addr::IFAPROT_KERNEL_LO;
        crate::iface_addr::set_prefix_meta_row(net_ns, id, Ipv4Addr::LOOPBACK, None, 8, meta);
    }

    /// Select socket-owned endpoints for one received IPv4 datagram. # C: O(N_port)
    #[cfg(test)]
    pub(crate) fn udp_demux(&self, src: Ipv4Addr, sport: u16, dst: Ipv4Addr,
                            dport: u16, iface: NetIfaceId) -> Vec<Arc<UdpRxQueue>> {
        self.udp_demux_in(0, src, sport, dst, dport, iface, &[])
    }

    /// Select endpoints in the ingress interface's network namespace. `payload`
    /// is the received datagram body, which a reuseport selection program
    /// classifies. # C: O(N_port)
    pub(crate) fn udp_demux_in(&self, net_ns: u64, src: Ipv4Addr, sport: u16, dst: Ipv4Addr,
                            dport: u16, iface: NetIfaceId, payload: &[u8]) -> Vec<Arc<UdpRxQueue>> {
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
        let index = crate::reuseport::slot::group(&winner.reuseport_group)
            .and_then(|group| group.select(hash, matched.len(), payload))
            .unwrap_or(hash as usize % matched.len());
        let selected = matched.swap_remove(index);
        alloc::vec![selected]
    }

    /// Remove exactly one IPv4 UDP endpoint, preserving port peers. # C: O(N_port)
    pub fn unbind_udp_endpoint(&self, endpoint: &Arc<UdpRxQueue>) {
        let port = endpoint.bound_port;
        let Some(tables) = self.try_inet_tables(endpoint.net_ns()) else {
            endpoint.deactivate();
            return;
        };
        let mut map = tables.udp.lock();
        if let Some(group) = map.get_mut(&port) {
            group.retain(|q| !Arc::ptr_eq(q, endpoint));
            if group.is_empty() { map.remove(&port); }
        }
        crate::reuseport::slot::set_endpoint_group(&endpoint.reuseport_group, None);
        endpoint.deactivate();
    }

    /// Atomically change one endpoint's device scope after conflict validation. # C: O(N_port)
    pub fn rebind_udp_endpoint_iface(&self, endpoint: &Arc<UdpRxQueue>, iface: Option<NetIfaceId>)
        -> NetResult<()> {
        let tables = self.inet_tables(endpoint.net_ns());
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
    pub(crate) fn udp_map(&self) -> Arc<super::inet_tables::InetTableLock<BTreeMap<u16, Vec<Arc<UdpRxQueue>>>>> {
        self.inet_tables(0).udp.clone()
    }

    #[cfg(test)]
    pub(crate) fn udp6_map(&self) -> Arc<super::inet_tables::InetTableLock<BTreeMap<u16, Vec<Arc<crate::stack_ipv6::Udp6RxQueue>>>>> {
        self.inet_tables(0).udp6.clone()
    }

    #[cfg(test)]
    pub(crate) fn tcp_conns_map(&self) -> Arc<super::inet_tables::InetTableLock<BTreeMap<TcpKey, Arc<TcpEntry>>>> {
        self.inet_tables(0).tcp_conns.clone()
    }

    /// F161: pub TCP-over-IPv4 send wrapper. # C: O(payload + route)
    pub fn send_l4_over_ipv4_pub(&self, src: Ipv4Addr, dst: Ipv4Addr, l4: &[u8])
        -> NetResult<()>
    {
        self.send_tcp_ipv4_segment_in(
            0, src, dst, l4, 0, None, crate::uapi::IP_PMTUDISC_WANT, None, None,
            crate::stack_binddev::UNMARKED,
        ).map(|_| ())
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
        let (route, iface, next_hop) = self.route_v4_xmit_in(0, dst_ip, None, crate::stack_binddev::UNMARKED)?;
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
            route, iface, next_hop, src_ip, dst_ip, IpProto::Udp, p.data(), 0, id,
        )
    }
}
