//! ARP ingress reaches the one IPv4 neighbour owner (B1698).
//!
//! Every IPv4 transmit resolves the next hop through the per-interface
//! neighbour cache, and so do `ip neigh`, `/proc/net/arp` and the ARP ioctls.
//! A reply that landed in any other table left the neighbour INCOMPLETE and
//! stranded every packet queued behind it: the guest ARPed the gateway, the
//! gateway answered on the wire, and not one datagram ever followed.

use super::*;
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::sync::Mutex;

struct WireDev { mac: MacAddr, frames: Mutex<Vec<Vec<u8>>> }

impl crate::NetDev for WireDev {
    fn name(&self) -> &str { "eth-arp" }
    fn mac(&self) -> MacAddr { self.mac }
    fn mtu(&self) -> u32 { 1500 }
    fn xmit(&self, packet: crate::Pkt) -> NetResult<()> {
        self.frames.lock().unwrap().push(packet.data().to_vec());
        Ok(())
    }
    fn xmit_raw(&self, frame: &[u8]) -> NetResult<()> {
        self.frames.lock().unwrap().push(frame.to_vec());
        Ok(())
    }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
}

const LOCAL_MAC: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
const PEER_MAC: MacAddr = MacAddr([0x52, 0x55, 0x0a, 0x00, 0x02, 0x02]);

fn local_ip() -> Ipv4Addr { Ipv4Addr::new(10, 0, 2, 15) }
fn peer_ip() -> Ipv4Addr { Ipv4Addr::new(10, 0, 2, 2) }

fn arp_ethernet(dst: MacAddr, opcode: u16, sender_mac: MacAddr, sender_ip: Ipv4Addr,
                target_mac: MacAddr, target_ip: Ipv4Addr) -> Vec<u8>
{
    let body = crate::arp::ArpPkt { opcode, sender_mac, sender_ip, target_mac, target_ip };
    let mut frame = alloc::vec![0u8; crate::ethernet::ETH_HDR_LEN + crate::arp::ARP_LEN];
    crate::ethernet::EthHdr::write_to(dst, sender_mac, crate::eth_p::ARP, &mut frame);
    body.write_to(&mut frame[crate::ethernet::ETH_HDR_LEN..]);
    frame
}

/// The namespace ref is returned, not dropped: releasing it unregisters the
/// interface and every later admission fails with `Enodev`.
fn wire_iface(stack: &NetStack)
    -> (NetIfaceId, u64, Arc<WireDev>, network_namespace::NetworkNamespaceRef)
{
    let owner = crate::net_ns::test_support::allocate_namespace();
    let ns = owner.id().as_u64();
    let dev = Arc::new(WireDev { mac: LOCAL_MAC, frames: Mutex::new(Vec::new()) });
    let iface = stack.ifaces.register_in_ns(dev.clone(), ns);
    assert!(stack.set_primary_ipv4_in(ns, iface, local_ip(), 0));
    (iface, ns, dev, owner)
}

#[test]
fn an_arp_reply_binds_the_neighbour_every_ipv4_transmit_reads() {
    let stack = NetStack::new();
    let (iface, ns, _dev, _owner) = wire_iface(&stack);
    let cache = stack.ifaces.arp_cache_in_ns(iface, ns).unwrap();
    assert_eq!(cache.lookup(peer_ip()), None, "no binding before the reply");

    stack.deliver_ethernet(iface, &arp_ethernet(LOCAL_MAC, crate::arp::ARP_OP_REPLY,
        PEER_MAC, peer_ip(), LOCAL_MAC, local_ip())).unwrap();

    assert_eq!(cache.lookup(peer_ip()), Some(PEER_MAC));
    assert_eq!(cache.neighbour(peer_ip()), Some((PEER_MAC, crate::arp::NudState::Reachable)));
}

#[test]
fn an_arp_request_binds_its_sender_as_stale_and_is_answered_for_a_local_address() {
    let stack = NetStack::new();
    let (iface, ns, dev, _owner) = wire_iface(&stack);

    stack.deliver_ethernet(iface, &arp_ethernet(MacAddr::BROADCAST, crate::arp::ARP_OP_REQUEST,
        PEER_MAC, peer_ip(), MacAddr([0; 6]), local_ip())).unwrap();

    let cache = stack.ifaces.arp_cache_in_ns(iface, ns).unwrap();
    assert_eq!(cache.neighbour(peer_ip()), Some((PEER_MAC, crate::arp::NudState::Stale)),
        "a request teaches the sender, but only a reply is Reachable");

    let sent = dev.frames.lock().unwrap();
    assert_eq!(sent.len(), 1, "the request for a local address is answered");
    let header = crate::ethernet::EthHdr::parse(&sent[0]).unwrap();
    assert_eq!((header.dst, header.src, header.ethertype),
        (PEER_MAC, LOCAL_MAC, crate::eth_p::ARP));
    let arp = crate::arp::ArpPkt::parse(&sent[0][header.hdr_len..]).unwrap();
    assert_eq!(arp.opcode, crate::arp::ARP_OP_REPLY);
    assert_eq!((arp.sender_mac, arp.sender_ip), (LOCAL_MAC, local_ip()));
    assert_eq!((arp.target_mac, arp.target_ip), (PEER_MAC, peer_ip()));
}

#[test]
fn an_arp_request_for_an_address_we_do_not_own_is_learned_but_not_answered() {
    let stack = NetStack::new();
    let (iface, ns, dev, _owner) = wire_iface(&stack);

    stack.deliver_ethernet(iface, &arp_ethernet(MacAddr::BROADCAST, crate::arp::ARP_OP_REQUEST,
        PEER_MAC, peer_ip(), MacAddr([0; 6]), Ipv4Addr::new(10, 0, 2, 99))).unwrap();

    assert_eq!(stack.ifaces.arp_cache_in_ns(iface, ns).unwrap().lookup(peer_ip()), Some(PEER_MAC));
    assert!(dev.frames.lock().unwrap().is_empty());
}

#[test]
fn a_malformed_arp_payload_is_dropped_rather_than_failing_the_frame() {
    let stack = NetStack::new();
    let (iface, ns, _dev, _owner) = wire_iface(&stack);
    let mut frame = alloc::vec![0u8; crate::ethernet::ETH_HDR_LEN + 4];
    crate::ethernet::EthHdr::write_to(LOCAL_MAC, PEER_MAC, crate::eth_p::ARP, &mut frame);

    assert_eq!(stack.deliver_ethernet(iface, &frame), Ok(()));
    assert_eq!(stack.ifaces.arp_cache_in_ns(iface, ns).unwrap().lookup(peer_ip()), None);
}

#[test]
fn an_ipv4_frame_does_not_teach_the_neighbour_cache() {
    let stack = NetStack::new();
    let (iface, ns, _dev, _owner) = wire_iface(&stack);
    let mut frame = alloc::vec![0u8; crate::ethernet::ETH_HDR_LEN + crate::ipv4::IPV4_HDR_LEN];
    crate::ethernet::EthHdr::write_to(LOCAL_MAC, PEER_MAC, crate::eth_p::IPV4, &mut frame);
    crate::ipv4::Ipv4Hdr::build(peer_ip(), local_ip(), crate::IpProto::Udp, 0, 1)
        .write_to(&mut frame[crate::ethernet::ETH_HDR_LEN..]);

    let _ = stack.deliver_ethernet(iface, &frame);

    assert_eq!(stack.ifaces.arp_cache_in_ns(iface, ns).unwrap().lookup(peer_ip()), None,
        "the reference learns IPv4 neighbours from ARP, not from arbitrary ingress");
}
