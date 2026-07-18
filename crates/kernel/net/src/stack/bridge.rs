//! RTNL-owned bridge port/FDB state and Ethernet ingress decisions.

use super::*;

pub(crate) struct BridgeTable {
    state: Spinlock<BTreeMap<NetIfaceId, Bridge>, StackLockClass>,
}

struct Bridge {
    net_ns: u64,
    mac: MacAddr,
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
        state.insert(bridge, Bridge { net_ns, mac, ports: BTreeMap::new(), fdb: BTreeMap::new() });
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
        if bridge.net_ns != net_ns { return Err(NetError::Enodev); }
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
}

impl NetStack {
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
