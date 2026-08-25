#![allow(unused_imports)]
use super::super::*;

impl NetStack {
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

    /// Select endpoints in the ingress interface's network namespace.
    /// `datagram` is the received UDP datagram from its header onward, which
    /// is where a reuseport selection program's view of the packet starts.
    /// # C: O(N_port)
    pub(crate) fn udp_demux_in(&self, net_ns: u64, src: Ipv4Addr, sport: u16, dst: Ipv4Addr,
                            dport: u16, iface: NetIfaceId, datagram: &[u8])
        -> Vec<Arc<UdpRxQueue>> {
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
        let Some(index) = crate::reuseport::select_udp(&winner.reuseport_group, hash,
            matched.len(), datagram, crate::addr::eth_p::IPV4,
            |handle| crate::reuseport::prog::member_index(handle, &matched))
            else { return Vec::new(); };
        let selected = matched.swap_remove(index);
        alloc::vec![selected]
    }

}

