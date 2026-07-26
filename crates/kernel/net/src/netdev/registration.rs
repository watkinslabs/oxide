use super::*;

/// Opaque ownership of one unpublished interface generation.
pub struct IfaceRegistration<'a> {
    id:       NetIfaceId,
    gate:     Arc<IngressGate>,
    owner:    network_namespace::NetworkNamespaceRef,
    registry: &'a IfaceRegistry,
    armed:    bool,
}

impl IfaceRegistration<'_> {
    /// Assigned interface index. # C: O(1)
    pub fn id(&self) -> NetIfaceId { self.id }
    /// Owning namespace id. # C: O(1)
    pub fn net_ns(&self) -> u64 { self.owner.id().as_u64() }
    /// Retained concrete namespace owner. # C: O(1)
    pub fn namespace(&self) -> network_namespace::NetworkNamespaceRef { self.owner.clone() }

    /// Snapshot pending driver properties without RTNL held. # C: O(N)
    pub fn link_properties(&self) -> Option<crate::control_event::LinkProperties> {
        let dev = {
            let g = self.registry.inner.lock();
            g.entries.iter().find(|entry| entry.id == self.id
                && Arc::ptr_eq(&entry.ingress, &self.gate)).map(|entry| entry.dev.clone())?
        };
        Some(crate::control_event::LinkProperties::from_dev(dev.as_ref()))
    }

    fn disarm(&mut self) { self.armed = false; }
}

impl Drop for IfaceRegistration<'_> {
    fn drop(&mut self) {
        if self.armed { let _ = self.registry.abort_owned(self); }
    }
}

impl IfaceRegistry {
    fn insert_pending(&self, dev: Arc<dyn NetDev>,
                      owner: &network_namespace::NetworkNamespaceRef) -> IfaceRegistration<'_> {
        let mut g = self.inner.lock();
        let id = NetIfaceId::from_raw(g.alloc_id());
        let ns = owner.id().as_u64();
        let ifindex = g.entries.iter().filter(|entry| entry.ns == ns)
            .map(|entry| entry.ifindex).max().unwrap_or(0).saturating_add(1);
        let flags = if dev.hardware_type() == crate::uapi::ARPHRD_LOOPBACK {
            iff::IFF_UP | iff::IFF_RUNNING | iff::IFF_LOOPBACK
        } else {
            iff::IFF_UP | iff::IFF_RUNNING | iff::IFF_BROADCAST | iff::IFF_MULTICAST
        };
        let gate = Arc::new(IngressGate::registration_pending(ns, 1));
        let name = String::from(dev.name());
        g.entries.push(IfaceEntry { id, ifindex, ns, dev, name, flags: AtomicU32::new(flags),
            mcast_report: Arc::new(McastReportState::new()),
            packet_filter: Arc::new(PacketDeviceFilter::new()),
            arp: Arc::new(crate::arp::ArpCache::new()), ingress: gate.clone() });
        IfaceRegistration {
            id, gate, owner: owner.clone(), registry: self, armed: true,
        }
    }

    /// Prepare an interface generation hidden from control and data planes. # C: O(1)
    /// # Lk: matching stack RTNL held by `rtnl`
    pub(crate) fn prepare_in_ns(&self, rtnl: &crate::RtnlGuard<'_>, dev: Arc<dyn NetDev>,
                                owner: &network_namespace::NetworkNamespaceRef)
        -> Option<IfaceRegistration<'_>>
    {
        if !self.guard_matches(rtnl) { return None; }
        Some(self.insert_pending(dev, owner))
    }

    /// Publish one fully initialized interface generation. # C: O(N)
    /// # Lk: matching stack RTNL held by `rtnl`
    pub(crate) fn publish(&self, rtnl: &crate::RtnlGuard<'_>,
                          mut reg: IfaceRegistration<'_>) -> bool {
        if !self.guard_matches(rtnl) { return false; }
        let g = self.inner.lock();
        let Some(entry) = g.entries.iter().find(|entry| entry.id == reg.id
            && entry.ns == reg.owner.id().as_u64()
            && Arc::ptr_eq(&entry.ingress, &reg.gate) && entry.ingress.live()
            && !entry.ingress.ready()) else {
            return false;
        };
        entry.ingress.finish_resume();
        reg.disarm();
        true
    }

    fn abort_owned(&self, reg: &IfaceRegistration<'_>) -> bool {
        let removed = {
            let mut g = self.inner.lock();
            let Some(pos) = g.entries.iter().position(|entry| entry.id == reg.id
                && Arc::ptr_eq(&entry.ingress, &reg.gate) && !entry.ingress.ready()) else {
                return false;
            };
            reg.gate.close();
            g.entries.remove(pos);
            true
        };
        reg.gate.finish();
        removed
    }

    /// Abort every unpublished interface generation owned by one namespace. # C: O(N)
    /// # Lk: matching stack RTNL held by `rtnl`
    pub(crate) fn abort_pending_in_ns(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64) -> usize {
        if !self.guard_matches(rtnl) { return 0; }
        let gates = {
            let mut g = self.inner.lock();
            let mut gates = Vec::new();
            g.entries.retain(|entry| {
                if entry.ns != ns || entry.ingress.ready() { return true; }
                entry.ingress.close();
                gates.push(entry.ingress.clone());
                false
            });
            gates
        };
        let removed = gates.len();
        for gate in gates { gate.finish(); }
        removed
    }

    /// Abort and complete an unpublished interface generation. # C: O(N)
    pub(crate) fn abort(&self, mut reg: IfaceRegistration<'_>) -> bool {
        let removed = self.abort_owned(&reg);
        if removed { reg.disarm(); }
        removed
    }

    /// Hosted fully initialized registration convenience. # C: O(1)
    #[cfg(not(target_os = "oxide-kernel"))]
    pub fn register(&self, dev: Arc<dyn NetDev>) -> NetIfaceId {
        self.register_in_ns(dev, 0)
    }

    /// Hosted fully initialized namespace registration convenience. # C: O(1)
    #[cfg(not(target_os = "oxide-kernel"))]
    pub fn register_in_ns(&self, dev: Arc<dyn NetDev>, ns: u64) -> NetIfaceId {
        let mut g = self.inner.lock();
        let id = NetIfaceId::from_raw(g.alloc_id());
        let ifindex = g.entries.iter().filter(|entry| entry.ns == ns)
            .map(|entry| entry.ifindex).max().unwrap_or(0).saturating_add(1);
        let flags = if dev.hardware_type() == crate::uapi::ARPHRD_LOOPBACK {
            iff::IFF_UP | iff::IFF_RUNNING | iff::IFF_LOOPBACK
        } else {
            iff::IFF_UP | iff::IFF_RUNNING | iff::IFF_BROADCAST | iff::IFF_MULTICAST
        };
        let name = String::from(dev.name());
        g.entries.push(IfaceEntry { id, ifindex, ns, dev, name, flags: AtomicU32::new(flags),
            mcast_report: Arc::new(McastReportState::new()),
            packet_filter: Arc::new(PacketDeviceFilter::new()),
            arp: Arc::new(crate::arp::ArpCache::new()),
            ingress: Arc::new(IngressGate::new(ns, 1)) });
        id
    }
}
