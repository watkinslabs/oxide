use super::*;

impl NetStack {
    fn namespace_owner(net_ns: u64) -> Option<crate::control_event::NamespaceOwner> {
        if net_ns == 0 {
            return Some(crate::control_event::NamespaceOwner::Live(
                network_namespace::initial()));
        }
        if let Some(owner) = network_namespace::lookup_u64(net_ns) {
            return Some(crate::control_event::NamespaceOwner::Live(owner));
        }
        #[cfg(any(test, feature = "hosted"))]
        return Some(crate::control_event::NamespaceOwner::Hosted(net_ns));
        #[cfg(not(any(test, feature = "hosted")))]
        None
    }

    /// Snapshot one control-ready link generation under RTNL. # C: O(N)
    pub fn live_link_event(&self, rtnl: &crate::RtnlGuard<'_>,
                       namespace: crate::control_event::NamespaceOwner,
                       iface: NetIfaceId, properties: crate::control_event::LinkProperties,
                       kind: crate::control_event::EventKind)
        -> Option<crate::control_event::LinkEvent>
    {
        let net_ns = namespace.id();
        self.ifaces.control_ready_in_ns(rtnl, iface, net_ns)?;
        let generation = self.ifaces.control_generation_in_ns(rtnl, iface, net_ns)?;
        let flags = self.ifaces.iface_flags(iface)?;
        Some(crate::control_event::LinkEvent {
            kind, namespace,
            owner: crate::control_event::IfaceOwner { iface, generation },
            name: properties.name, mac: properties.mac, mtu: properties.mtu,
            is_loopback: properties.is_loopback, flags, stats: properties.stats,
        })
    }

    fn teardown_link_event(&self, teardown: &crate::netdev::IfaceTeardown,
                           namespace: crate::control_event::NamespaceOwner,
                           properties: crate::control_event::LinkProperties,
                           kind: crate::control_event::EventKind)
        -> crate::control_event::LinkEvent
    {
        crate::control_event::LinkEvent {
            kind, namespace,
            owner: crate::control_event::IfaceOwner {
                iface: teardown.iface(), generation: teardown.generation(),
            },
            name: properties.name, mac: properties.mac, mtu: properties.mtu,
            is_loopback: properties.is_loopback, flags: teardown.flags(), stats: properties.stats,
        }
    }

    /// Prepare a hidden interface generation for driver initialization. # C: O(1)
    pub fn prepare_iface(&self, dev: Arc<dyn NetDev>,
                         owner: &network_namespace::NetworkNamespaceRef)
        -> Option<crate::netdev::IfaceRegistration<'_>>
    {
        let rtnl = self.rtnl_lock();
        self.ifaces.prepare_in_ns(&rtnl, dev, owner)
    }

    /// Publish a fully initialized interface generation. # C: O(N)
    pub fn publish_iface(&self, reg: crate::netdev::IfaceRegistration<'_>) -> bool {
        let namespace = crate::control_event::NamespaceOwner::Live(reg.namespace());
        let iface = reg.id();
        let Some(properties) = reg.link_properties() else { return false };
        let rtnl = self.rtnl_lock();
        if !self.ifaces.publish(&rtnl, reg) { return false; }
        let Some(event) = self.live_link_event(
            &rtnl, namespace, iface, properties,
            crate::control_event::EventKind::New) else { return false };
        let ticket = crate::control_event::stage(
            &rtnl, crate::control_event::ControlEvent::Link(event));
        drop(rtnl);
        crate::control_event::publish(ticket);
        true
    }

    /// Abort an interface generation that was never published. # C: O(N)
    pub fn abort_iface(&self, reg: crate::netdev::IfaceRegistration<'_>) -> bool {
        self.ifaces.abort(reg)
    }

    /// Remove per-interface network state and unregister the netdev.
    /// # C: O(N routes + N addrs + N groups + N ndp)
    pub fn unregister_iface(&self, iface: NetIfaceId) -> bool {
        self.unregister_iface_in(0, iface)
    }

    fn drain_teardown(&self, teardown: &crate::netdev::IfaceTeardown) {
        for job in teardown.arp.clear() { job.complete(Err(NetError::Enetdown)); }
        teardown.wait();
        teardown.mcast_report.retire();
        teardown.dev.retire_namespace();
    }

    /// Advance canonical IPv4 neighbour retries for every live interface. # C: O(N neighbours)
    pub(crate) fn arp_tick(&self, now_ns: u64) {
        for cache in self.ifaces.arp_caches() {
            let work = cache.tick(now_ns);
            for job in work.failed { job.complete(Err(NetError::Ehostunreach)); }
            for probe in work.probes {
                let _ = crate::netdev::tx_dispatch::TxDispatch::emit_arp_probe(probe);
            }
        }
    }

    fn remove_teardown_state(&self, rtnl: &crate::RtnlGuard<'_>,
                             iface: NetIfaceId, teardown: &crate::netdev::IfaceTeardown,
                             namespace: &crate::control_event::NamespaceOwner,
                             properties: &crate::control_event::LinkProperties)
        -> Option<u64> {
        let net_ns = teardown.net_ns();
        self.ipv4_reasm.remove_iface(net_ns, iface);
        self.ipv6_reasm.remove_iface(net_ns, iface);
        let owner = crate::control_event::IfaceOwner {
            iface, generation: teardown.generation(),
        };
        #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
        crate::sock::detach_packet_device(rtnl, teardown);
        let label = properties.name.clone();
        let mut ticket = None;
        for row in crate::iface_addr::take_iface(net_ns, iface) {
            ticket = Some(crate::control_event::stage(rtnl,
                crate::control_event::ControlEvent::Addr(crate::control_event::AddrEvent {
                    kind: crate::control_event::EventKind::Delete,
                    namespace: namespace.clone(), owner,
                    label: label.clone(), row,
                })));
        }
        if let Some(rows) = self.v6_addrs.lock().remove(&iface) {
            for row in rows {
                ticket = Some(crate::control_event::stage(rtnl,
                    crate::control_event::ControlEvent::Addr6(crate::control_event::Addr6Event {
                        kind: crate::control_event::EventKind::Delete,
                        namespace: namespace.clone(), owner,
                        label: label.clone(), row,
                    })));
            }
        }
        self.ndp.lock().retain(|(id, _), _| *id != iface);
        self.v6_mcast.lock().remove(&iface);
        self.v4_mcast.lock().remove(&iface);
        if let Some(tables) = self.try_inet_tables(net_ns) {
            tables.pmtu.remove_iface(iface);
        }
        let routes = self.routes.take_records_in(net_ns, |record| record.route.iface == iface);
        for records in crate::RouteTable::alias_groups(routes) {
            ticket = Some(crate::control_event::stage(rtnl,
                crate::control_event::ControlEvent::Route(crate::control_event::RouteEvent {
                    kind: crate::control_event::EventKind::Delete,
                    namespace: namespace.clone(),
                    owners: alloc::vec![owner], leases: alloc::vec::Vec::new(), records,
                })));
        }
        let rows = self.routes6.take_iface_in_rtnl(rtnl, net_ns, iface);
        if !rows.is_empty() {
            ticket = Some(crate::control_event::stage(rtnl,
                crate::control_event::ControlEvent::Route6(crate::control_event::Route6Event {
                    kind: crate::control_event::EventKind::Delete,
                    namespace: namespace.clone(), owners: alloc::vec![owner], rows,
                })));
        }
        ticket
    }

    fn claim_iface_in(&self, net_ns: u64, iface: NetIfaceId)
        -> Option<crate::netdev::IfaceTeardown>
    {
        loop {
            let claim = {
                let _rtnl = self.rtnl_lock();
                self.ifaces.claim_unregister_in(iface, Some(net_ns))
            };
            match claim {
                crate::netdev::IfaceUnregisterClaim::Gone => return None,
                crate::netdev::IfaceUnregisterClaim::WaitComplete(gate) => {
                    crate::netdev::IfaceRegistry::wait_unregister(&gate);
                }
                crate::netdev::IfaceUnregisterClaim::WaitResume(gate) => {
                    crate::netdev::IfaceRegistry::wait_resume(&gate);
                }
                crate::netdev::IfaceUnregisterClaim::Teardown(teardown) => return Some(teardown),
            }
        }
    }

    /// Remove one namespace-owned interface and all attached network state. # C: O(N)
    pub fn unregister_iface_in(&self, net_ns: u64, iface: NetIfaceId) -> bool {
        let Some(namespace) = Self::namespace_owner(net_ns) else { return false };
        let Some(teardown) = self.claim_iface_in(net_ns, iface) else { return false };
        self.drain_teardown(&teardown);
        let properties = crate::control_event::LinkProperties::from_dev(teardown.dev.as_ref());
        let removed = {
            let rtnl = self.rtnl_lock();
            let mut ticket = self.remove_teardown_state(
                &rtnl, iface, &teardown, &namespace, &properties);
            let removed = self.ifaces.finish_destroy(&teardown);
            if removed.is_some() {
                ticket = Some(crate::control_event::stage(&rtnl,
                    crate::control_event::ControlEvent::Link(self.teardown_link_event(
                        &teardown, namespace.clone(), properties.clone(),
                        crate::control_event::EventKind::Delete))));
            }
            (removed, ticket)
        };
        if let Some(ticket) = removed.1 { crate::control_event::publish(ticket); }
        if let Some(dev) = removed.0.as_ref() {
            crate::netdev::IfaceRegistry::notify_destroyed(dev);
        }
        if removed.0.is_some() { crate::netdev::IfaceRegistry::complete_destroy(&teardown); }
        removed.0.is_some()
    }

    /// Synchronously remove an interface from its canonical namespace generation. # C: O(N)
    /// # Ctx: schedulable process context; caller holds no ingress lease for `iface`.
    pub fn unregister_iface_current(&self, iface: NetIfaceId) -> bool {
        loop {
            let admitted = self.ifaces.acquire_ingress(iface);
            let namespace = admitted.as_ref().map(|lease|
                crate::control_event::NamespaceOwner::Live(lease.namespace()));
            let claim = {
                let _rtnl = self.rtnl_lock();
                self.ifaces.claim_unregister(iface)
            };
            drop(admitted);
            match claim {
                crate::netdev::IfaceUnregisterClaim::Gone => return true,
                crate::netdev::IfaceUnregisterClaim::WaitComplete(gate) => {
                    crate::netdev::IfaceRegistry::wait_unregister(&gate);
                }
                crate::netdev::IfaceUnregisterClaim::WaitResume(gate) => {
                    crate::netdev::IfaceRegistry::wait_resume(&gate);
                }
                crate::netdev::IfaceUnregisterClaim::Teardown(teardown) => {
                    let namespace = namespace.expect(
                        "live teardown claim must retain concrete namespace owner");
                    assert_eq!(namespace.id(), teardown.net_ns());
                    self.drain_teardown(&teardown);
                    let properties = crate::control_event::LinkProperties::from_dev(
                        teardown.dev.as_ref());
                    let removed = {
                        let rtnl = self.rtnl_lock();
                        let mut ticket = self.remove_teardown_state(
                            &rtnl, iface, &teardown, &namespace, &properties);
                        let removed = self.ifaces.finish_destroy(&teardown);
                        if removed.is_some() {
                            ticket = Some(crate::control_event::stage(&rtnl,
                                crate::control_event::ControlEvent::Link(self.teardown_link_event(
                                    &teardown, namespace.clone(), properties.clone(),
                                    crate::control_event::EventKind::Delete))));
                        }
                        (removed, ticket)
                    };
                    if let Some(ticket) = removed.1 { crate::control_event::publish(ticket); }
                    if let Some(dev) = removed.0.as_ref() {
                        crate::netdev::IfaceRegistry::notify_destroyed(dev);
                    }
                    if removed.0.is_some() {
                        crate::netdev::IfaceRegistry::complete_destroy(&teardown);
                        return true;
                    }
                }
            }
        }
    }

    /// Apply Linux namespace-exit disposition after quiescing interface state. # C: O(N)
    pub fn teardown_iface_in(&self, net_ns: u64, iface: NetIfaceId) -> bool {
        let Some(namespace) = Self::namespace_owner(net_ns) else { return false };
        self.teardown_iface_owned(namespace, iface)
    }

    pub(crate) fn teardown_iface_owned(&self,
        namespace: crate::control_event::NamespaceOwner, iface: NetIfaceId) -> bool {
        let net_ns = namespace.id();
        let Some(teardown) = self.claim_iface_in(net_ns, iface) else { return false };
        self.drain_teardown(&teardown);
        let properties = crate::control_event::LinkProperties::from_dev(teardown.dev.as_ref());
        match teardown.dev.namespace_drop_action() {
            crate::NamespaceDropAction::Destroy => {
                let removed = {
                    let rtnl = self.rtnl_lock();
                    let mut ticket = self.remove_teardown_state(
                        &rtnl, iface, &teardown, &namespace, &properties);
                    let removed = self.ifaces.finish_destroy(&teardown);
                    if removed.is_some() {
                        ticket = Some(crate::control_event::stage(&rtnl,
                            crate::control_event::ControlEvent::Link(self.teardown_link_event(
                                &teardown, namespace.clone(), properties.clone(),
                                crate::control_event::EventKind::Delete))));
                    }
                    (removed, ticket)
                };
                if let Some(ticket) = removed.1 { crate::control_event::publish(ticket); }
                if let Some(dev) = removed.0.as_ref() {
                    crate::netdev::IfaceRegistry::notify_destroyed(dev);
                }
                if removed.0.is_some() {
                    crate::netdev::IfaceRegistry::complete_destroy(&teardown);
                }
                removed.0.is_some()
            }
            crate::NamespaceDropAction::MoveToInitial => {
                let (next, old_ticket) = {
                    let rtnl = self.rtnl_lock();
                    let _ = self.remove_teardown_state(
                        &rtnl, iface, &teardown, &namespace, &properties);
                    let Some(next) = self.ifaces.begin_move_to_initial(&teardown) else { return false };
                    let ticket = crate::control_event::stage(&rtnl,
                        crate::control_event::ControlEvent::Link(self.teardown_link_event(
                            &teardown, namespace.clone(), properties.clone(),
                            crate::control_event::EventKind::Delete)));
                    (next, ticket)
                };
                crate::control_event::publish(old_ticket);
                teardown.dev.resume_namespace();
                let new_properties = crate::control_event::LinkProperties::from_dev(
                    teardown.dev.as_ref());
                let initial = crate::control_event::NamespaceOwner::Live(
                    network_namespace::initial());
                let rtnl = self.rtnl_lock();
                if !self.ifaces.finish_move_to_initial(&teardown, &next) { return false; }
                let Some(event) = self.live_link_event(
                    &rtnl, initial, iface, new_properties,
                    crate::control_event::EventKind::New) else {
                    return false;
                };
                let ticket = crate::control_event::stage(
                    &rtnl, crate::control_event::ControlEvent::Link(event));
                drop(rtnl);
                crate::control_event::publish(ticket);
                crate::netdev::IfaceRegistry::complete_move(&teardown);
                true
            }
        }
    }
}
