use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, Socket as LockClass};

use crate::{Ipv4Addr, MacAddr, NetDev, NetError, NetResult, Pkt};
use crate::iface_addr::{Ipv4AddrCacheInfo, Ipv4IfaceAddr};
use crate::bpf_filter::SocketFilter;
use crate::mcast_filter::SocketMcast;
use crate::route::{RouteEntry, RouteRecord, RTN_UNICAST};
use crate::send_control::{Ipv4Options, Raw4Control};
use crate::stack::NetStack;

use super::{Raw4Endpoint, Raw4TxOptions};

const SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 44);
const DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 8);

fn endpoint(protocol: u8) -> Arc<Raw4Endpoint> {
    Raw4Endpoint::new(protocol, network_namespace::initial(), Arc::new(SocketFilter::new()),
        Arc::new(SocketMcast::new()), Arc::new(crate::SocketError::new()))
}

struct Capture { mtu: u32, packets: Spinlock<Vec<Vec<u8>>, LockClass> }
impl NetDev for Capture {
    fn name(&self) -> &str { "raw4ctl0" }
    fn mac(&self) -> MacAddr { MacAddr::ZERO }
    fn mtu(&self) -> u32 { self.mtu }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
    fn xmit(&self, packet: Pkt) -> NetResult<()> { self.packets.lock().push(packet.data().to_vec()); Ok(()) }
}

fn setup(scope: u8, gateway: Option<Ipv4Addr>) -> (NetStack, Arc<Capture>, crate::NetIfaceId) {
    let stack = NetStack::new();
    let dev = Arc::new(Capture { mtu: 1500, packets: Spinlock::new(Vec::new()) });
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn NetDev>);
    stack.routes.add_record_in(0, RouteRecord { route: RouteEntry::main(DST, 32, iface, gateway, Some(SRC)),
        protocol: 2, scope, kind: RTN_UNICAST, metric: 0, mtu: None, flags: 0, weight: 1, nh_flags: 0 });
    crate::iface_addr::insert(Ipv4IfaceAddr { ns: 0, iface, addr: SRC, peer: None, prefixlen: 24,
        mask: 0xffff_ff00, broadcast: None, scope: 0, flags: 0, cacheinfo: Ipv4AddrCacheInfo::PERMANENT });
    (stack, dev, iface)
}

#[test]
fn one_message_controls_build_ipv4_header_without_endpoint_mutation() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let (stack, dev, iface) = setup(253, None);
    let endpoint = endpoint(253);
    let control = Raw4Control { source: Some(SRC), iface: Some(iface), ttl: Some(9),
        tos: Some(0x2e), protocol: Some(17), options: Some(Ipv4Options {
            bytes: alloc::vec![1, 1, 0, 0], first_hop: None, strict_route: false,
        }), ..Raw4Control::default() };
    stack.send_raw4(&endpoint, DST, b"body", Raw4TxOptions::default(), &control).unwrap();
    let packet = &dev.packets.lock()[0];
    assert_eq!(packet[0] & 0x0f, 6);
    assert_eq!(packet[1], 0x2e);
    assert_eq!(packet[8], 9);
    assert_eq!(packet[9], 253);
    assert_eq!(&packet[12..16], &SRC.octets());
    assert_eq!(&packet[20..24], &[1, 1, 0, 0]);
    assert_eq!(endpoint.protocol(), 253);
}

#[test]
fn source_route_uses_first_hop_route_source_and_mtu() {
    let stack = NetStack::new();
    let first_hop = Ipv4Addr::new(192, 0, 2, 1);
    let hop_source = Ipv4Addr::new(192, 0, 2, 99);
    let final_dev = Arc::new(Capture { mtu: 1500, packets: Spinlock::new(Vec::new()) });
    let hop_dev = Arc::new(Capture { mtu: 68, packets: Spinlock::new(Vec::new()) });
    let final_iface = stack.ifaces.register(final_dev.clone() as Arc<dyn NetDev>);
    let hop_iface = stack.ifaces.register(hop_dev.clone() as Arc<dyn NetDev>);
    stack.routes.add(RouteEntry::main(DST, 32, final_iface, None, Some(SRC)));
    stack.routes.add(RouteEntry::main(first_hop, 32, hop_iface, None, Some(hop_source)));
    let control = Raw4Control { options: Some(Ipv4Options {
        bytes: alloc::vec![131, 7, 4, 192, 0, 2, 1],
        first_hop: Some(first_hop), strict_route: false,
    }), ..Raw4Control::default() };
    let options = Raw4TxOptions { pmtudisc: crate::uapi::IP_PMTUDISC_DONT,
        ..Raw4TxOptions::default() };

    stack.send_raw4(&endpoint(17), DST, &[0x5a; 80], options, &control).unwrap();

    assert!(final_dev.packets.lock().is_empty());
    let packets = hop_dev.packets.lock();
    assert!(packets.len() > 1);
    assert_eq!(&packets[0][12..16], &hop_source.octets());
    assert_eq!(&packets[0][16..20], &first_hop.octets());
    assert_eq!(&packets[0][23..27], &DST.octets());
}

#[test]
fn non_copy_options_are_nops_after_fragment_zero() {
    let stack = NetStack::new();
    let dev = Arc::new(Capture { mtu: 68, packets: Spinlock::new(Vec::new()) });
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn NetDev>);
    stack.routes.add(RouteEntry::main(DST, 32, iface, None, Some(SRC)));
    let control = Raw4Control { options: Some(Ipv4Options {
        bytes: alloc::vec![7, 7, 4, 0, 0, 0, 0, 0],
        first_hop: None, strict_route: false,
    }), ..Raw4Control::default() };
    let options = Raw4TxOptions { pmtudisc: crate::uapi::IP_PMTUDISC_DONT,
        ..Raw4TxOptions::default() };

    stack.send_raw4(&endpoint(17), DST, &[0x5a; 80], options, &control).unwrap();

    let packets = dev.packets.lock();
    assert_eq!(&packets[0][20..27], &[7, 7, 8, 192, 0, 2, 44]);
    assert!(packets[1..].iter().all(|packet| packet[20..27] == [1; 7]));
}

#[test]
fn timestamp_address_mode_advances_pointer_and_writes_route_source() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let (stack, dev, _) = setup(253, None);
    let control = Raw4Control { options: Some(Ipv4Options {
        bytes: alloc::vec![68, 12, 5, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        first_hop: None, strict_route: false,
    }), ..Raw4Control::default() };

    stack.send_raw4(&endpoint(17), DST, b"x", Raw4TxOptions::default(), &control).unwrap();

    let packets = dev.packets.lock();
    assert_eq!(packets[0][22], 13);
    assert_eq!(&packets[0][24..28], &SRC.octets());
}

#[test]
fn message_pktinfo_iface_overrides_socket_multicast_iface() {
    let stack = NetStack::new();
    let socket_dev = Arc::new(Capture { mtu: 1500, packets: Spinlock::new(Vec::new()) });
    let message_dev = Arc::new(Capture { mtu: 1500, packets: Spinlock::new(Vec::new()) });
    let socket_iface = stack.ifaces.register(socket_dev.clone() as Arc<dyn NetDev>);
    let message_iface = stack.ifaces.register(message_dev.clone() as Arc<dyn NetDev>);
    stack.routes.add(RouteEntry::main(DST, 32, socket_iface, None, Some(SRC)));
    stack.routes.add(RouteEntry::main(DST, 32, message_iface, None, Some(SRC)));
    let control = Raw4Control { iface: Some(message_iface), ..Raw4Control::default() };
    let options = Raw4TxOptions { iface: Some(socket_iface), ..Raw4TxOptions::default() };

    stack.send_raw4(&endpoint(17), DST, b"x", options, &control).unwrap();

    assert!(socket_dev.packets.lock().is_empty());
    assert_eq!(message_dev.packets.lock().len(), 1);
}

#[test]
fn dont_route_rejects_gateway_and_non_link_scope() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let endpoint = endpoint(17);
    let control = Raw4Control { dont_route: true, ..Raw4Control::default() };
    let (gateway, _, _) = setup(0, Some(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(gateway.send_raw4(&endpoint, DST, b"x", Raw4TxOptions::default(), &control),
        Err(NetError::Enetunreach));
    let (universe, _, _) = setup(0, None);
    assert_eq!(universe.send_raw4(&endpoint, DST, b"x", Raw4TxOptions::default(), &control),
        Err(NetError::Enetunreach));
    let (link, dev, _) = setup(253, None);
    link.send_raw4(&endpoint, DST, b"x", Raw4TxOptions::default(), &control).unwrap();
    assert_eq!(dev.packets.lock().len(), 1);
}

#[test]
fn dont_route_with_explicit_iface_sends_on_link_without_route() {
    let stack = NetStack::new();
    let dev = Arc::new(Capture { mtu: 1500, packets: Spinlock::new(Vec::new()) });
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn NetDev>);
    let control = Raw4Control { iface: Some(iface), dont_route: true,
        ..Raw4Control::default() };

    stack.send_raw4(&endpoint(17), DST, b"x", Raw4TxOptions::default(), &control).unwrap();

    assert_eq!(dev.packets.lock().len(), 1);
}
