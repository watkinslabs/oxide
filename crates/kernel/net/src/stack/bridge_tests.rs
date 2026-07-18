use super::*;
use alloc::sync::Arc;
use std::sync::Mutex;

struct CaptureDev { name: &'static str, mac: MacAddr, frames: Mutex<Vec<Vec<u8>>> }

impl CaptureDev {
    fn new(name: &'static str, mac: MacAddr) -> Self { Self { name, mac, frames: Mutex::new(Vec::new()) } }
}

impl crate::NetDev for CaptureDev {
    fn name(&self) -> &str { self.name }
    fn mac(&self) -> MacAddr { self.mac }
    fn mtu(&self) -> u32 { 1500 }
    fn xmit(&self, packet: crate::Pkt) -> NetResult<()> { self.frames.lock().unwrap().push(packet.data().to_vec()); Ok(()) }
    fn xmit_raw(&self, frame: &[u8]) -> NetResult<()> { self.frames.lock().unwrap().push(frame.to_vec()); Ok(()) }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction { crate::NamespaceDropAction::Destroy }
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
    assert_eq!(stack.bridge_port_list(owner.id().as_u64(), bridge, 3).unwrap(),
        alloc::vec![0, first_id.raw() as i32, second_id.raw() as i32]);
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
fn bridge_fdb_snapshot_contains_local_and_learned_rows() {
    let stack = NetStack::new();
    let owner = crate::net_ns::test_support::allocate_namespace();
    let bridge_dev = Arc::new(CaptureDev::new("br0", MacAddr([2, 0, 0, 0, 2, 1])));
    let port = Arc::new(CaptureDev::new("port0", MacAddr([2, 0, 0, 0, 2, 2])));
    let bridge = stack.ifaces.register_in_ns(bridge_dev.clone(), owner.id().as_u64());
    let port_id = stack.ifaces.register_in_ns(port.clone(), owner.id().as_u64());
    let rtnl = stack.rtnl_lock();
    stack.bridge_create_in_rtnl(&rtnl, bridge, owner.id().as_u64(), bridge_dev.mac()).unwrap();
    stack.bridge_add_port_in_rtnl(&rtnl, bridge, port_id).unwrap();
    drop(rtnl);
    let learned = MacAddr([2, 0, 0, 0, 2, 3]);
    stack.deliver_ethernet(port_id, &frame(bridge_dev.mac(), learned)).unwrap();
    stack.bridge_set_ageing_time(owner.id().as_u64(), bridge, 7).unwrap();
    let rows = stack.bridge_fdb_entries(owner.id().as_u64(), bridge, 0, 8).unwrap();
    assert!(rows.iter().any(|row| row.mac == bridge_dev.mac() && row.local && row.port_no == 0));
    assert!(rows.iter().any(|row| row.mac == port.mac() && row.local && row.port_no == 1));
    assert!(rows.iter().any(|row| row.mac == learned && !row.local && row.port_no == 1 && row.ageing_ticks == 7));
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
fn bridge_raw_transmit_uses_the_learned_fdb_port() {
    let stack = NetStack::new();
    let owner = crate::net_ns::test_support::allocate_namespace();
    let bridge_dev = Arc::new(CaptureDev::new("br0", MacAddr([2, 0, 0, 0, 3, 1])));
    let first = Arc::new(CaptureDev::new("first", MacAddr([2, 0, 0, 0, 3, 2])));
    let second = Arc::new(CaptureDev::new("second", MacAddr([2, 0, 0, 0, 3, 3])));
    let bridge = stack.ifaces.register_in_ns(bridge_dev.clone(), owner.id().as_u64());
    let first_id = stack.ifaces.register_in_ns(first.clone(), owner.id().as_u64());
    let second_id = stack.ifaces.register_in_ns(second.clone(), owner.id().as_u64());
    let rtnl = stack.rtnl_lock();
    stack.bridge_create_in_rtnl(&rtnl, bridge, owner.id().as_u64(), bridge_dev.mac()).unwrap();
    stack.bridge_add_port_in_rtnl(&rtnl, bridge, first_id).unwrap();
    stack.bridge_add_port_in_rtnl(&rtnl, bridge, second_id).unwrap();
    drop(rtnl);
    let peer = MacAddr([2, 0, 0, 0, 3, 9]);
    stack.deliver_ethernet(second_id, &frame(bridge_dev.mac(), peer)).unwrap();
    first.frames.lock().unwrap().clear(); second.frames.lock().unwrap().clear();
    let outbound = frame(peer, bridge_dev.mac());
    stack.bridge_xmit_raw(bridge, &outbound).unwrap();
    assert!(first.frames.lock().unwrap().is_empty());
    assert_eq!(*second.frames.lock().unwrap(), alloc::vec![outbound]);
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
