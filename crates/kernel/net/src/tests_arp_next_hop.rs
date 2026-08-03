// The ARP request a transmit emits must ask for the next hop the route chose.
//
// A request naming the wrong target is never answered, so the neighbour never
// resolves and no unicast traffic to that destination ever leaves — while the
// interface, its address and the route table all read as healthy, and the
// transmit counter still climbs for every frame sent. Observed on a guest as
// `ARP, Request who-has 0.0.0.0 tell 10.0.2.15` for every ping.

use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Socket as LockClass, Spinlock};

use crate::iface_addr::{Ipv4AddrCacheInfo, Ipv4IfaceAddr};
use crate::route::RouteEntry;

use crate::stack::NetStack;
use crate::{Ipv4Addr, MacAddr, NetDev, NetIfaceId, NetResult, Pkt};

const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
const SUBNET: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 0);
const OFFLINK: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

struct Wire { frames: Spinlock<Vec<Vec<u8>>, LockClass> }

impl NetDev for Wire {
    fn name(&self) -> &str { "eth0" }
    fn mac(&self) -> MacAddr { MacAddr([0x52, 0x54, 0, 0x12, 0x34, 0x56]) }
    fn mtu(&self) -> u32 { 1500 }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
    fn xmit(&self, _packet: Pkt) -> NetResult<()> { Ok(()) }
    fn xmit_raw(&self, frame: &[u8]) -> NetResult<()> {
        self.frames.lock().push(frame.to_vec());
        Ok(())
    }
}

/// The guest's exact configuration: one ethernet device with a DHCP address,
/// the on-link prefix route, and a default route through the gateway.
fn guest_like() -> (NetStack, Arc<Wire>, NetIfaceId) {
    let stack = NetStack::new();
    let dev = Arc::new(Wire { frames: Spinlock::new(Vec::new()) });
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn NetDev>);
    crate::iface_addr::insert(Ipv4IfaceAddr {
        ns: 0, iface, addr: LOCAL, peer: None, prefixlen: 24, mask: 0xffff_ff00,
        broadcast: None, scope: 0, flags: 0, proto: 0, rt_priority: 0,
        cacheinfo: Ipv4AddrCacheInfo::PERMANENT,
    });
    stack.routes.add_record_in(0, crate::route::RouteRecord::kernel(
        RouteEntry::main(SUBNET, 24, iface, None, Some(LOCAL))));
    stack.routes.add_record_in(0, crate::route::RouteRecord::kernel(
        RouteEntry::main(Ipv4Addr::ANY, 0, iface, Some(GATEWAY), Some(LOCAL))));
    (stack, dev, iface)
}

/// Target protocol address of the first ARP request the device transmitted.
fn arp_target(dev: &Wire) -> Option<Ipv4Addr> {
    for frame in dev.frames.lock().iter() {
        if frame.len() < crate::ethernet::ETH_HDR_LEN + crate::arp::ARP_LEN { continue; }
        let body = &frame[crate::ethernet::ETH_HDR_LEN..];
        let pkt = crate::arp::ArpPkt::parse(body).ok()?;
        if pkt.opcode == crate::arp::ARP_OP_REQUEST { return Some(pkt.target_ip); }
    }
    None
}

#[test]
fn an_on_link_destination_is_solicited_by_its_own_address() {
    let (stack, dev, iface) = guest_like();
    let (route, _lease, next_hop) = stack.route_v4_iface_in(0, GATEWAY, None).expect("a route");
    assert_eq!(route.iface, iface);
    assert_eq!(next_hop, GATEWAY,
        "an on-link destination is its own next hop; a zero here is solicited as 0.0.0.0");
    let _ = dev;
}

#[test]
fn an_off_link_destination_is_solicited_by_the_gateway() {
    let (stack, _dev, _iface) = guest_like();
    let (_route, _lease, next_hop) = stack.route_v4_iface_in(0, OFFLINK, None).expect("a route");
    assert_eq!(next_hop, GATEWAY, "the default route's gateway carries the frame");
}

#[test]
fn the_solicited_target_is_never_the_unspecified_address() {
    // Whatever the route table says, a request for 0.0.0.0 cannot be answered.
    let (stack, _dev, _iface) = guest_like();
    for dst in [GATEWAY, OFFLINK, Ipv4Addr::new(10, 0, 2, 99)] {
        let (_r, _l, next_hop) = stack.route_v4_iface_in(0, dst, None).expect("a route");
        assert!(!next_hop.is_unspecified(), "dst {dst:?} resolved to an unspecified next hop");
    }
}

/// The guest's real defect: the on-link prefix route arrived from a network
/// manager carrying `RTA_GATEWAY` set to `0.0.0.0`, and a stored gateway of
/// zero made every next hop zero. Every ping then emitted
/// `ARP, Request who-has 0.0.0.0`, which nothing answers, so the interface
/// transmitted forever and resolved nothing.
#[test]
fn a_zero_gateway_route_still_solicits_the_destination() {
    let stack = NetStack::new();
    let dev = Arc::new(Wire { frames: Spinlock::new(Vec::new()) });
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn NetDev>);
    crate::iface_addr::insert(Ipv4IfaceAddr {
        ns: 0, iface, addr: LOCAL, peer: None, prefixlen: 24, mask: 0xffff_ff00,
        broadcast: None, scope: 0, flags: 0, proto: 0, rt_priority: 0,
        cacheinfo: Ipv4AddrCacheInfo::PERMANENT,
    });
    // Exactly what the guest's table held.
    stack.routes.add_record_in(0, crate::route::RouteRecord::kernel(
        RouteEntry::main(SUBNET, 24, iface, Some(Ipv4Addr::ANY), Some(LOCAL))));
    let (_r, _l, next_hop) = stack.route_v4_iface_in(0, GATEWAY, None).expect("a route");
    assert_eq!(next_hop, GATEWAY, "a zero gateway means on-link, not a gateway of 0.0.0.0");
}

#[test]
fn the_next_hop_rule_reads_a_zero_gateway_as_no_gateway() {
    use crate::route::RouteRecord;
    let dst = Ipv4Addr::new(198, 51, 100, 7);
    assert_eq!(RouteRecord::next_hop_for(None, dst), dst);
    assert_eq!(RouteRecord::next_hop_for(Some(Ipv4Addr::ANY), dst), dst);
    assert_eq!(RouteRecord::next_hop_for(Some(GATEWAY), dst), GATEWAY);
}

#[test]
fn the_ipv6_next_hop_rule_reads_a_zero_gateway_as_no_gateway() {
    let dst = crate::Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let gw = crate::Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(crate::route6::next_hop6_for(None, dst), dst);
    assert_eq!(crate::route6::next_hop6_for(Some(crate::Ipv6Addr([0u8; 16])), dst), dst);
    assert_eq!(crate::route6::next_hop6_for(Some(gw), dst), gw);
}
