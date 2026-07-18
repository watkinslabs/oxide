//! RTNL-owned bridge port/FDB state and Ethernet ingress decisions.

use super::*;

pub(crate) struct BridgeTable {
    state: Spinlock<BTreeMap<NetIfaceId, Bridge>, StackLockClass>,
}

struct Bridge {
    net_ns: u64,
    mac: MacAddr,
    deleting: bool,
    ports: BTreeMap<NetIfaceId, ()>,
    fdb: BTreeMap<(u16, [u8; 6]), NetIfaceId>,
}

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
        state.insert(bridge, Bridge { net_ns, mac, deleting: false, ports: BTreeMap::new(), fdb: BTreeMap::new() });
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
        bridge.ports.insert(port, ());
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
        bridge.fdb.retain(|_, learned| *learned != port);
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
                bridge.fdb.retain(|_, learned| *learned != iface);
            }
        }
    }

    /// Learn source and choose bridge-local delivery plus physical egress ports. # C: O(N ports + log N)
    pub(crate) fn ingress(&self, lease: &crate::IngressLease, header: crate::ethernet::EthHdr)
        -> Option<BridgeIngress>
    {
        let mut state = self.state.lock();
        let (&bridge_id, bridge) = state.iter_mut().find(|(_, bridge)| {
            bridge.net_ns == lease.net_ns() && bridge.ports.contains_key(&lease.iface())
        })?;
        if !header.src.is_multicast() && header.src != MacAddr::ZERO {
            bridge.fdb.insert((header.vlan_tag.unwrap_or(0), header.src.0), lease.iface());
        }
        let key = (header.vlan_tag.unwrap_or(0), header.dst.0);
        let target = bridge.fdb.get(&key).copied();
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
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use std::sync::Mutex;

    struct CaptureDev { name: &'static str, mac: MacAddr, frames: Mutex<Vec<Vec<u8>>> }

    impl CaptureDev {
        fn new(name: &'static str, mac: MacAddr) -> Self {
            Self { name, mac, frames: Mutex::new(Vec::new()) }
        }
    }

    impl crate::NetDev for CaptureDev {
        fn name(&self) -> &str { self.name }
        fn mac(&self) -> MacAddr { self.mac }
        fn mtu(&self) -> u32 { 1500 }
        fn xmit(&self, packet: crate::Pkt) -> NetResult<()> {
            self.frames.lock().unwrap().push(packet.data().to_vec()); Ok(())
        }
        fn xmit_raw(&self, frame: &[u8]) -> NetResult<()> {
            self.frames.lock().unwrap().push(frame.to_vec()); Ok(())
        }
        fn retire_namespace(&self) {}
        fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
            crate::NamespaceDropAction::Destroy
        }
    }

    fn frame(dst: MacAddr, src: MacAddr) -> Vec<u8> {
        let mut frame = alloc::vec![0; crate::ethernet::ETH_HDR_LEN + 1];
        crate::ethernet::EthHdr::write_to(dst, src, crate::eth_p::ARP, &mut frame);
        frame
    }

    #[test]
    fn bridge_learns_and_forwards_without_returning_to_the_ingress_port() {
        let stack = NetStack::new();
        let owner = crate::net_ns::test_support::allocate_namespace();
        let bridge_dev = Arc::new(CaptureDev::new("br0", MacAddr([2, 0, 0, 0, 0, 1])));
        let first = Arc::new(CaptureDev::new("port0", MacAddr([2, 0, 0, 0, 0, 2])));
        let second = Arc::new(CaptureDev::new("port1", MacAddr([2, 0, 0, 0, 0, 3])));
        let bridge = stack.ifaces.register_in_ns(bridge_dev.clone(), owner.id().as_u64());
        let first_id = stack.ifaces.register_in_ns(first.clone(), owner.id().as_u64());
        let second_id = stack.ifaces.register_in_ns(second.clone(), owner.id().as_u64());
        let rtnl = stack.rtnl_lock();
        stack.bridge_create_in_rtnl(&rtnl, bridge, owner.id().as_u64(), bridge_dev.mac()).unwrap();
        stack.bridge_add_port_in_rtnl(&rtnl, bridge, first_id).unwrap();
        stack.bridge_add_port_in_rtnl(&rtnl, bridge, second_id).unwrap();
        drop(rtnl);

        let first_mac = MacAddr([2, 0, 0, 0, 0, 10]);
        let second_mac = MacAddr([2, 0, 0, 0, 0, 11]);
        let unknown = frame(second_mac, first_mac);
        stack.deliver_ethernet(first_id, &unknown).unwrap();
        assert!(first.frames.lock().unwrap().is_empty());
        assert_eq!(*second.frames.lock().unwrap(), alloc::vec![unknown.clone()]);

        let learned = frame(first_mac, second_mac);
        stack.deliver_ethernet(second_id, &learned).unwrap();
        assert_eq!(*first.frames.lock().unwrap(), alloc::vec![learned]);
        assert_eq!(second.frames.lock().unwrap().len(), 1);
    }

    #[test]
    fn bridge_port_removal_discards_learned_forwarding_state() {
        let stack = NetStack::new();
        let owner = crate::net_ns::test_support::allocate_namespace();
        let bridge_dev = Arc::new(CaptureDev::new("br0", MacAddr([2, 0, 0, 0, 1, 1])));
        let first = Arc::new(CaptureDev::new("port0", MacAddr([2, 0, 0, 0, 1, 2])));
        let second = Arc::new(CaptureDev::new("port1", MacAddr([2, 0, 0, 0, 1, 3])));
        let bridge = stack.ifaces.register_in_ns(bridge_dev.clone(), owner.id().as_u64());
        let first_id = stack.ifaces.register_in_ns(first.clone(), owner.id().as_u64());
        let second_id = stack.ifaces.register_in_ns(second.clone(), owner.id().as_u64());
        let rtnl = stack.rtnl_lock();
        stack.bridge_create_in_rtnl(&rtnl, bridge, owner.id().as_u64(), bridge_dev.mac()).unwrap();
        stack.bridge_add_port_in_rtnl(&rtnl, bridge, first_id).unwrap();
        stack.bridge_add_port_in_rtnl(&rtnl, bridge, second_id).unwrap();
        drop(rtnl);

        let learned = MacAddr([2, 0, 0, 0, 1, 10]);
        stack.deliver_ethernet(first_id, &frame(MacAddr::BROADCAST, learned)).unwrap();
        assert!(stack.unregister_iface_in(owner.id().as_u64(), first_id));
        second.frames.lock().unwrap().clear();
        stack.deliver_ethernet(second_id, &frame(learned, MacAddr([2, 0, 0, 0, 1, 11]))).unwrap();
        assert!(second.frames.lock().unwrap().is_empty());
    }

    #[test]
    fn bridge_mac_delivery_uses_the_bridge_as_the_l3_ingress_identity() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let stack = NetStack::new();
        let (_loopback, _lo) = stack.register_loopback();
        let bridge_mac = MacAddr([2, 0, 0, 0, 2, 1]);
        let bridge_dev = Arc::new(CaptureDev::new("br0", bridge_mac));
        let port = Arc::new(CaptureDev::new("port0", MacAddr([2, 0, 0, 0, 2, 2])));
        let bridge = stack.ifaces.register(bridge_dev.clone());
        let port_id = stack.ifaces.register(port);
        let rtnl = stack.rtnl_lock();
        stack.bridge_create_in_rtnl(&rtnl, bridge, 0, bridge_mac).unwrap();
        stack.bridge_add_port_in_rtnl(&rtnl, bridge, port_id).unwrap();
        drop(rtnl);
        let endpoint = stack.bind_udp(crate::Ipv4Addr::LOOPBACK, 43_212).unwrap();
        let body = b"bridge-local";
        let mut l3 = alloc::vec![0u8; crate::ipv4::IPV4_HDR_LEN + crate::udp::UDP_HDR_LEN + body.len()];
        crate::udp::UdpHdr::build_into(43_213, 43_212, crate::Ipv4Addr::LOOPBACK,
            crate::Ipv4Addr::LOOPBACK, body, &mut l3[crate::ipv4::IPV4_HDR_LEN..]);
        crate::ipv4::Ipv4Hdr::build(crate::Ipv4Addr::LOOPBACK, crate::Ipv4Addr::LOOPBACK,
            crate::IpProto::Udp, (crate::udp::UDP_HDR_LEN + body.len()) as u16, 1)
            .write_to(&mut l3[..crate::ipv4::IPV4_HDR_LEN]);
        let mut wire = alloc::vec![0u8; crate::ethernet::ETH_HDR_LEN + l3.len()];
        crate::ethernet::EthHdr::write_to(bridge_mac, MacAddr([2, 0, 0, 0, 2, 3]),
            crate::eth_p::IPV4, &mut wire);
        wire[crate::ethernet::ETH_HDR_LEN..].copy_from_slice(&l3);

        stack.deliver_ethernet(port_id, &wire).unwrap();
        let received = endpoint.recv(false).unwrap();
        assert_eq!(received.3, bridge);
        assert_eq!(received.5, body);
    }
}
