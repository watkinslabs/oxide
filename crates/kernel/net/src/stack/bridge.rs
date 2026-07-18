//! RTNL-owned bridge port/FDB state and Ethernet ingress decisions.

use super::*;

pub(crate) struct BridgeTable {
    state: Spinlock<BTreeMap<NetIfaceId, Bridge>, StackLockClass>,
}

struct Bridge {
    net_ns: u64,
    mac: MacAddr,
    deleting: bool,
    ports: BTreeMap<NetIfaceId, BridgePort>,
    fdb: BTreeMap<(u16, [u8; 6]), FdbEntry>,
    arp: BTreeMap<crate::Ipv4Addr, MacAddr>,
}

struct BridgePort { number: u16 }

struct FdbEntry { port: NetIfaceId, learned_ns: u64 }

const FDB_AGEING_NS: u64 = 300_000_000_000;

pub(crate) struct BridgeIngress {
    pub(crate) bridge: NetIfaceId,
    pub(crate) local: bool,
    pub(crate) egress: Vec<NetIfaceId>,
}

impl BridgeTable {
    pub(crate) const fn new() -> Self { Self { state: Spinlock::new(BTreeMap::new()) } }

    /// Register one already-published bridge interface. # C: O(log N)
    /// # Lk: matching stack RTNL held by `rtnl`
    pub(crate) fn create(&self, rtnl: &crate::RtnlGuard<'_>, bridge: NetIfaceId,
                         net_ns: u64, mac: MacAddr) -> NetResult<()>
    {
        if rtnl.stack().ifaces.control_ready_in_ns(rtnl, bridge, net_ns).is_none() {
            return Err(NetError::Enodev);
        }
        let mut state = self.state.lock();
        if state.contains_key(&bridge) { return Err(NetError::Ebusy); }
        state.insert(bridge, Bridge { net_ns, mac, deleting: false, ports: BTreeMap::new(), fdb: BTreeMap::new(), arp: BTreeMap::new() });
        Ok(())
    }

    /// Attach a live same-namespace port to one bridge. # C: O(log N)
    /// # Lk: matching stack RTNL held by `rtnl`
    pub(crate) fn add_port(&self, rtnl: &crate::RtnlGuard<'_>, bridge: NetIfaceId,
                           port: NetIfaceId) -> NetResult<()>
    {
        let net_ns = rtnl.stack().ifaces.namespace(bridge).ok_or(NetError::Enodev)?;
        if bridge == port || rtnl.stack().ifaces.control_ready_in_ns(rtnl, port, net_ns).is_none() {
            return Err(NetError::Enodev);
        }
        let mut state = self.state.lock();
        if state.values().any(|row| row.ports.contains_key(&port)) { return Err(NetError::Ebusy); }
        let bridge = state.get_mut(&bridge).ok_or(NetError::Enodev)?;
        if bridge.net_ns != net_ns || bridge.deleting { return Err(NetError::Enodev); }
        let number = (1..=u16::MAX).find(|number|
            !bridge.ports.values().any(|existing| existing.number == *number))
            .ok_or(NetError::Enospc)?;
        bridge.ports.insert(port, BridgePort { number });
        Ok(())
    }

    /// Detach one port and discard every FDB row that named it. # C: O(N FDB)
    /// # Lk: matching stack RTNL held by `rtnl`
    pub(crate) fn del_port(&self, _rtnl: &crate::RtnlGuard<'_>, bridge: NetIfaceId,
                           port: NetIfaceId) -> NetResult<()>
    {
        let mut state = self.state.lock();
        let bridge = state.get_mut(&bridge).ok_or(NetError::Enodev)?;
        if bridge.ports.remove(&port).is_none() { return Err(NetError::Enodev); }
        bridge.fdb.retain(|_, learned| learned.port != port);
        Ok(())
    }

    /// Remove a departing bridge or port from canonical bridge state. # C: O(N bridges + FDB)
    /// # Lk: matching stack RTNL held by `rtnl`
    pub(crate) fn remove_iface(&self, _rtnl: &crate::RtnlGuard<'_>, net_ns: u64, iface: NetIfaceId) {
        let mut state = self.state.lock();
        state.remove(&iface);
        for bridge in state.values_mut() {
            if bridge.net_ns != net_ns { continue; }
            if bridge.ports.remove(&iface).is_some() {
                bridge.fdb.retain(|_, learned| learned.port != iface);
            }
        }
    }

    /// Learn source and choose bridge-local delivery plus physical egress ports. # C: O(N ports + log N)
    pub(crate) fn ingress(&self, lease: &crate::IngressLease, header: crate::ethernet::EthHdr,
                          frame: &[u8])
        -> Option<BridgeIngress>
    {
        let mut state = self.state.lock();
        let (&bridge_id, bridge) = state.iter_mut().find(|(_, bridge)| {
            bridge.net_ns == lease.net_ns() && bridge.ports.contains_key(&lease.iface())
        })?;
        let now = super::monotonic_ns_safe();
        if now != 0 { bridge.fdb.retain(|_, learned| now.saturating_sub(learned.learned_ns) <= FDB_AGEING_NS); }
        if !header.src.is_multicast() && header.src != MacAddr::ZERO {
            bridge.fdb.insert((header.vlan_tag.unwrap_or(0), header.src.0), FdbEntry {
                port: lease.iface(), learned_ns: now,
            });
        }
        if header.ethertype == crate::eth_p::ARP {
            if let Ok(arp) = crate::arp::ArpPkt::parse(&frame[header.hdr_len..]) {
                bridge.arp.insert(arp.sender_ip, arp.sender_mac);
            }
        }
        let key = (header.vlan_tag.unwrap_or(0), header.dst.0);
        let target = bridge.fdb.get(&key).map(|entry| entry.port);
        let local = header.dst == bridge.mac || header.dst.is_multicast();
        let egress = match target {
            Some(port) if port != lease.iface() => alloc::vec![port],
            Some(_) => Vec::new(),
            None => bridge.ports.keys().copied().filter(|port| *port != lease.iface()).collect(),
        };
        Some(BridgeIngress { bridge: bridge_id, local, egress })
    }

    /// True when an admitted interface is attached to a bridge. # C: O(N bridges)
    pub(crate) fn has_port(&self, net_ns: u64, port: NetIfaceId) -> bool {
        self.state.lock().values().any(|bridge|
            bridge.net_ns == net_ns && bridge.ports.contains_key(&port))
    }

    /// Whether `iface` names a live bridge owner in `net_ns`. # C: O(log N)
    pub(crate) fn contains(&self, net_ns: u64, iface: NetIfaceId) -> bool {
        self.state.lock().get(&iface).is_some_and(|bridge| bridge.net_ns == net_ns && !bridge.deleting)
    }

    /// Snapshot bridge ifindices in one namespace. # C: O(N bridges)
    pub(crate) fn ifindices(&self, net_ns: u64) -> Vec<NetIfaceId> {
        self.state.lock().iter().filter_map(|(&iface, bridge)|
            (bridge.net_ns == net_ns && !bridge.deleting).then_some(iface)).collect()
    }

    /// Choose egress ports for one locally transmitted bridge frame. # C: O(N ports + log N)
    pub(crate) fn egress_for_tx(&self, bridge: NetIfaceId, header: crate::ethernet::EthHdr)
        -> NetResult<(u64, Vec<NetIfaceId>)>
    {
        let mut state = self.state.lock();
        let row = state.get_mut(&bridge).ok_or(NetError::Enodev)?;
        if row.deleting { return Err(NetError::Enodev); }
        let now = super::monotonic_ns_safe();
        if now != 0 { row.fdb.retain(|_, learned| now.saturating_sub(learned.learned_ns) <= FDB_AGEING_NS); }
        let key = (header.vlan_tag.unwrap_or(0), header.dst.0);
        let ports = match row.fdb.get(&key).map(|entry| entry.port) {
            Some(port) => alloc::vec![port],
            None => row.ports.keys().copied().collect(),
        };
        Ok((row.net_ns, ports))
    }

    /// Resolve an IPv4 neighbor from bridge-owned ARP learning. # C: O(log N)
    pub(crate) fn arp_lookup(&self, bridge: NetIfaceId, target: crate::Ipv4Addr)
        -> NetResult<(u64, MacAddr, Option<MacAddr>)>
    {
        let state = self.state.lock();
        let row = state.get(&bridge).ok_or(NetError::Enodev)?;
        if row.deleting { return Err(NetError::Enodev); }
        Ok((row.net_ns, row.mac, row.arp.get(&target).copied()))
    }

    /// Produce Linux BRCTL_GET_PORT_LIST's port-number-indexed ifindex array. # C: O(N ports)
    pub(crate) fn port_list(&self, bridge: NetIfaceId, net_ns: u64, count: usize)
        -> NetResult<Vec<i32>>
    {
        let state = self.state.lock();
        let row = state.get(&bridge).ok_or(NetError::Enodev)?;
        if row.net_ns != net_ns || row.deleting { return Err(NetError::Enodev); }
        let mut rows = alloc::vec![0; count];
        for (&iface, port) in &row.ports {
            if (port.number as usize) < count { rows[port.number as usize] = iface.raw() as i32; }
        }
        Ok(rows)
    }

    /// Prevent further port changes and require an empty bridge before deletion. # C: O(1)
    pub(crate) fn begin_delete(&self, rtnl: &crate::RtnlGuard<'_>, bridge: NetIfaceId,
                               net_ns: u64) -> NetResult<()>
    {
        let mut state = self.state.lock();
        let row = state.get_mut(&bridge).ok_or(NetError::Enodev)?;
        if row.net_ns != net_ns || row.deleting { return Err(NetError::Enodev); }
        if !row.ports.is_empty() { return Err(NetError::Ebusy); }
        if rtnl.stack().ifaces.control_ready_in_ns(rtnl, bridge, net_ns).is_none() {
            return Err(NetError::Enodev);
        }
        row.deleting = true;
        Ok(())
    }

    /// Undo a failed deletion before its link generation has departed. # C: O(1)
    pub(crate) fn cancel_delete(&self, bridge: NetIfaceId) {
        if let Some(bridge) = self.state.lock().get_mut(&bridge) { bridge.deleting = false; }
    }
}

impl NetStack {
    /// Snapshot live bridge link ifindices for the legacy BRCTL enumeration ABI. # C: O(N bridges)
    pub fn bridge_ifindices(&self, net_ns: u64) -> Vec<NetIfaceId> { self.bridges.ifindices(net_ns) }

    /// Query one bridge's Linux port-number-indexed ifindex table. # C: O(N ports)
    pub fn bridge_port_list(&self, net_ns: u64, bridge: NetIfaceId, count: usize)
        -> NetResult<Vec<i32>>
    {
        self.bridges.port_list(bridge, net_ns, count)
    }

    /// Forward a complete locally generated Ethernet frame through its bridge FDB. # C: O(frame + N ports)
    pub fn bridge_xmit_raw(&self, bridge: NetIfaceId, frame: &[u8]) -> NetResult<()> {
        let header = crate::ethernet::EthHdr::parse(frame).map_err(|_| NetError::Einval)?;
        let (net_ns, ports) = self.bridges.egress_for_tx(bridge, header)?;
        if ports.is_empty() { return Err(NetError::Enetdown); }
        let mut error = None;
        for port in ports {
            match self.ifaces.acquire_egress_in_ns(port, net_ns) {
                Some(egress) => if let Err(next) = egress.xmit_raw(frame) { error = Some(next); },
                None => error = Some(NetError::Enodev),
            }
        }
        error.map_or(Ok(()), Err)
    }

    /// Create and publish a named bridge link in one live network namespace. # C: O(N ifaces)
    pub fn bridge_create_named(&self, net_ns: u64, name: &str) -> NetResult<NetIfaceId> {
        // Linux IFNAMSIZ includes the terminating NUL.
        if name.is_empty() || name.len() >= 16 || name.as_bytes().contains(&0) {
            return Err(NetError::Einval);
        }
        let owner = if net_ns == 0 { network_namespace::initial() }
            else { network_namespace::lookup_u64(net_ns).ok_or(NetError::Enodev)? };
        let dev = alloc::sync::Arc::new(super::bridge_dev::BridgeDev::new(name));
        let properties = crate::control_event::LinkProperties::from_dev(dev.as_ref());
        let rtnl = self.rtnl_lock();
        if self.ifaces.lookup_name_in_ns(name, net_ns).is_some() { return Err(NetError::Ebusy); }
        let reg = self.ifaces.prepare_in_ns(&rtnl, dev.clone(), &owner).ok_or(NetError::Enodev)?;
        let iface = reg.id();
        dev.set_iface(iface);
        if !self.ifaces.publish(&rtnl, reg) { return Err(NetError::Enodev); }
        self.bridges.create(&rtnl, iface, net_ns, dev.mac())?;
        let event = self.live_link_event(&rtnl,
            crate::control_event::NamespaceOwner::Live(owner), iface, properties,
            crate::control_event::EventKind::New).ok_or(NetError::Enodev)?;
        let ticket = crate::control_event::stage(&rtnl, crate::control_event::ControlEvent::Link(event));
        drop(rtnl);
        crate::control_event::publish(ticket);
        Ok(iface)
    }

    /// Attach a same-namespace interface by canonical names. # C: O(N ifaces)
    pub fn bridge_add_port_named(&self, net_ns: u64, bridge_name: &str, port_name: &str)
        -> NetResult<()>
    {
        let rtnl = self.rtnl_lock();
        let bridge = self.ifaces.lookup_name_in_ns(bridge_name, net_ns).ok_or(NetError::Enodev)?.0;
        let port = self.ifaces.lookup_name_in_ns(port_name, net_ns).ok_or(NetError::Enodev)?.0;
        self.bridges.add_port(&rtnl, bridge, port)
    }

    /// Attach a same-namespace interface selected by its Linux ifindex. # C: O(N ifaces)
    pub fn bridge_add_port_ifindex(&self, net_ns: u64, bridge_name: &str, port: NetIfaceId)
        -> NetResult<()>
    {
        let rtnl = self.rtnl_lock();
        let bridge = self.ifaces.lookup_name_in_ns(bridge_name, net_ns).ok_or(NetError::Enodev)?.0;
        if !self.bridges.contains(net_ns, bridge) { return Err(NetError::Eopnotsupp); }
        if self.ifaces.control_ready_in_ns(&rtnl, port, net_ns).is_none() { return Err(NetError::Einval); }
        self.bridges.add_port(&rtnl, bridge, port)
    }

    /// Detach a bridge port by canonical names. # C: O(N ifaces + N FDB)
    pub fn bridge_del_port_named(&self, net_ns: u64, bridge_name: &str, port_name: &str)
        -> NetResult<()>
    {
        let rtnl = self.rtnl_lock();
        let bridge = self.ifaces.lookup_name_in_ns(bridge_name, net_ns).ok_or(NetError::Enodev)?.0;
        let port = self.ifaces.lookup_name_in_ns(port_name, net_ns).ok_or(NetError::Enodev)?.0;
        self.bridges.del_port(&rtnl, bridge, port)
    }

    /// Detach an interface selected by its Linux ifindex. # C: O(N ifaces + N FDB)
    pub fn bridge_del_port_ifindex(&self, net_ns: u64, bridge_name: &str, port: NetIfaceId)
        -> NetResult<()>
    {
        let rtnl = self.rtnl_lock();
        let bridge = self.ifaces.lookup_name_in_ns(bridge_name, net_ns).ok_or(NetError::Enodev)?.0;
        if !self.bridges.contains(net_ns, bridge) { return Err(NetError::Eopnotsupp); }
        if self.ifaces.control_ready_in_ns(&rtnl, port, net_ns).is_none() { return Err(NetError::Einval); }
        self.bridges.del_port(&rtnl, bridge, port)
    }

    /// Destroy an empty bridge after excluding new attachments under RTNL. # C: O(N state)
    pub fn bridge_delete_named(&self, net_ns: u64, name: &str) -> NetResult<()> {
        let bridge = {
            let rtnl = self.rtnl_lock();
            let bridge = self.ifaces.lookup_name_in_ns(name, net_ns).ok_or(NetError::Enodev)?.0;
            self.bridges.begin_delete(&rtnl, bridge, net_ns)?;
            bridge
        };
        if self.unregister_iface_in(net_ns, bridge) { return Ok(()); }
        self.bridges.cancel_delete(bridge);
        Err(NetError::Enodev)
    }

    /// Create bridge state for a published bridge netdev. # C: O(log N)
    pub(crate) fn bridge_create_in_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, bridge: NetIfaceId,
                                        net_ns: u64, mac: MacAddr) -> NetResult<()>
    {
        self.bridges.create(rtnl, bridge, net_ns, mac)
    }

    /// Add a physical bridge port under RTNL. # C: O(log N)
    pub(crate) fn bridge_add_port_in_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, bridge: NetIfaceId,
                                          port: NetIfaceId) -> NetResult<()>
    {
        self.bridges.add_port(rtnl, bridge, port)
    }

    /// Remove one bridge port under RTNL. # C: O(N FDB)
    pub(crate) fn bridge_del_port_in_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, bridge: NetIfaceId,
                                          port: NetIfaceId) -> NetResult<()>
    {
        self.bridges.del_port(rtnl, bridge, port)
    }

    /// Report whether a live ingress interface is currently a bridge port. # C: O(N bridges)
    pub fn bridge_port_attached(&self, net_ns: u64, port: NetIfaceId) -> bool {
        self.bridges.has_port(net_ns, port)
    }
}

#[cfg(test)]
#[path = "bridge_tests.rs"]
mod tests;
