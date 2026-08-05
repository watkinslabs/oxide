use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use sync::{Spinlock, Socket as LockClass};

use crate::addr::{IpProto, Ipv6Addr, MacAddr};
use crate::netdev::{NetDev, NetError, NetResult};
use crate::pkt::Pkt;
use crate::route6::Route6Entry;
use crate::stack::NetStack;

use super::{Raw6Endpoint, Raw6SendMode};

const LOCAL: Ipv6Addr = Ipv6Addr([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
const ROUTE_DST: Ipv6Addr = Ipv6Addr([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
const HEADER_DST: Ipv6Addr = Ipv6Addr([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);

struct CaptureDev {
    mtu: u32,
    packets: Spinlock<Vec<Vec<u8>>, LockClass>,
}

impl NetDev for CaptureDev {
    fn name(&self) -> &str { "raw6test0" }
    fn mac(&self) -> MacAddr { MacAddr::ZERO }
    fn mtu(&self) -> u32 { self.mtu }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
    fn xmit(&self, packet: Pkt) -> NetResult<()> {
        self.packets.lock().push(packet.data().to_vec());
        Ok(())
    }
}

fn routed_capture(mtu: u32) -> (NetStack, Arc<CaptureDev>) {
    let stack = NetStack::new();
    let dev = Arc::new(CaptureDev { mtu, packets: Spinlock::new(Vec::new()) });
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn NetDev>);
    stack.add_v6_addr(iface, LOCAL);
    stack.routes6.add(Route6Entry {
        table: crate::policy_rule::RT_TABLE_MAIN,
        dst: ROUTE_DST, prefix_len: 128, iface, gateway: None, src_hint: Some(LOCAL),
        origin: crate::route6::Route6Origin::Static,
    });
    stack.routes6.add(Route6Entry {
        table: crate::policy_rule::RT_TABLE_MAIN,
        dst: HEADER_DST, prefix_len: 128, iface, gateway: None, src_hint: Some(LOCAL),
        origin: crate::route6::Route6Origin::Static,
    });
    (stack, dev)
}

fn routed_capture_without_source(mtu: u32) -> (NetStack, Arc<CaptureDev>) {
    let stack = NetStack::new();
    let dev = Arc::new(CaptureDev { mtu, packets: Spinlock::new(Vec::new()) });
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn NetDev>);
    stack.routes6.add(Route6Entry {
        table: crate::policy_rule::RT_TABLE_MAIN,
        dst: ROUTE_DST, prefix_len: 128, iface, gateway: None, src_hint: None,
        origin: crate::route6::Route6Origin::Static,
    });
    (stack, dev)
}

fn caller_packet(len: usize) -> Vec<u8> {
    let mut bytes = vec![0xa5; len];
    if len < crate::ipv6::IPV6_HDR_LEN { return bytes; }
    bytes[0] = 0x16;
    bytes[4..6].copy_from_slice(&0xdead_u16.to_be_bytes());
    bytes[6] = 253;
    bytes[7] = 9;
    bytes[8..24].copy_from_slice(&Ipv6Addr::ANY.0);
    bytes[24..40].copy_from_slice(&HEADER_DST.0);
    bytes
}

#[test]
fn hdrincl_transmits_caller_bytes_without_header_validation_or_rewriting() {
    let (stack, dev) = routed_capture(96);
    let endpoint = Raw6Endpoint::standalone(network_namespace::initial(), IpProto::Raw as u8);
    let bytes = caller_packet(64);

    stack.send_raw6(&endpoint, ROUTE_DST, None, None, &bytes, 64,
        crate::uapi::IPV6_PMTUDISC_WANT, &crate::send_control::Raw6Control::default()).unwrap();

    assert_eq!(&*dev.packets.lock(), &[bytes]);
}

#[test]
fn socket_fragment_size_caps_raw6_after_route_selection() {
    let (stack, dev) = routed_capture(1500);
    let endpoint = Raw6Endpoint::standalone(network_namespace::initial(), 253);

    stack.send_raw6_with_frag_size(&endpoint, ROUTE_DST, None, None, &[0x5a; 2_000], 64,
        crate::uapi::IPV6_PMTUDISC_WANT, 1280,
        &crate::send_control::Raw6Control::default(), 0).unwrap();

    let packets = dev.packets.lock();
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].len(), 1280);
}

#[test]
fn hdrincl_enforces_only_base_header_minimum_and_route_mtu() {
    let (stack, dev) = routed_capture(64);
    let endpoint = Raw6Endpoint::standalone(network_namespace::initial(), IpProto::Raw as u8);

    assert_eq!(stack.send_raw6(&endpoint, ROUTE_DST, None, None,
        &caller_packet(crate::ipv6::IPV6_HDR_LEN - 1), 64,
        crate::uapi::IPV6_PMTUDISC_WANT, &crate::send_control::Raw6Control::default()), Err(NetError::Einval));
    assert_eq!(stack.send_raw6(&endpoint, ROUTE_DST, None, None,
        &caller_packet(65), 64, crate::uapi::IPV6_PMTUDISC_WANT,
        &crate::send_control::Raw6Control::default()), Err(NetError::Emsgsize));
    assert!(dev.packets.lock().is_empty());
}

#[test]
fn missing_source_rejects_kernel_header_but_not_caller_header() {
    let (stack, dev) = routed_capture_without_source(96);
    let kernel = Raw6Endpoint::standalone(network_namespace::initial(), IpProto::Udp as u8);
    assert_eq!(stack.send_raw6(&kernel, ROUTE_DST, None, None, b"payload", 64,
        crate::uapi::IPV6_PMTUDISC_WANT, &crate::send_control::Raw6Control::default()),
        Err(NetError::Eaddrnotavail));

    let caller = Raw6Endpoint::standalone(network_namespace::initial(), IpProto::Raw as u8);
    let bytes = caller_packet(64);
    stack.send_raw6(&caller, ROUTE_DST, None, None, &bytes, 64,
        crate::uapi::IPV6_PMTUDISC_WANT, &crate::send_control::Raw6Control::default()).unwrap();
    assert_eq!(&*dev.packets.lock(), &[bytes]);
}

#[test]
fn enabled_udp_checksum_zero_is_transmitted_as_ffff() {
    let endpoint = Raw6Endpoint::standalone(network_namespace::initial(), IpProto::Udp as u8);
    endpoint.set_checksum(6).unwrap();
    let payload = [0xbf, 0xe1, 0, 0, 0, 0, 0, 0];

    let prepared = endpoint.prepare_send(LOCAL, ROUTE_DST, None, &payload).unwrap();

    assert_eq!(prepared.mode, Raw6SendMode::KernelHeader);
    assert_eq!(&prepared.bytes[6..8], &[0xff, 0xff]);
}

#[test]
fn one_message_controls_drive_route_and_extension_header_construction() {
    let (stack, dev) = routed_capture(256);
    let endpoint = Raw6Endpoint::standalone(network_namespace::initial(), IpProto::Udp as u8);
    let hop = vec![0, 0, 1, 0, 0, 0, 0, 0];
    let dst0 = vec![0, 0, 2, 0, 0, 0, 0, 0];
    let dst1 = vec![0, 0, 3, 0, 0, 0, 0, 0];
    let mut route = vec![0, 2, 2, 1, 0, 0, 0, 0];
    route.extend_from_slice(&HEADER_DST.0);
    let control = crate::send_control::Raw6Control { source: Some(LOCAL), hop_limit: Some(9),
        traffic_class: Some(0xab), flowinfo: Some(0x54321), hop_options: Some(hop),
        dst_before_routing: Some(dst0), routing: Some(route), dst_after_routing: Some(dst1),
        ..crate::send_control::Raw6Control::default() };

    stack.send_raw6(&endpoint, ROUTE_DST, None, None, b"data", 64,
        crate::uapi::IPV6_PMTUDISC_WANT, &control).unwrap();

    let packet = &dev.packets.lock()[0];
    let header = crate::ipv6::Ipv6Hdr::parse(packet).unwrap();
    assert_eq!(header.dst, HEADER_DST);
    assert_eq!(header.traffic_class, 0xab);
    assert_eq!(header.flow_label, 0x54321);
    assert_eq!(header.hop_limit, 9);
    assert_eq!(header.next_header, 0);
    assert_eq!(packet[40], 60);
    assert_eq!(packet[48], 43);
    assert_eq!(packet[56], 60);
    assert_eq!(&packet[64..80], &ROUTE_DST.0);
    assert_eq!(packet[80], IpProto::Udp as u8);
    assert_eq!(&packet[88..], b"data");
}

#[test]
fn per_message_dontfrag_rejects_packet_over_route_mtu() {
    let (stack, dev) = routed_capture(64);
    let endpoint = Raw6Endpoint::standalone(network_namespace::initial(), IpProto::Udp as u8);
    let control = crate::send_control::Raw6Control {
        dontfrag: Some(true), ..crate::send_control::Raw6Control::default()
    };
    assert_eq!(stack.send_raw6(&endpoint, ROUTE_DST, None, None, &[0; 40], 64,
        crate::uapi::IPV6_PMTUDISC_DONT, &control), Err(NetError::Emsgsize));
    assert!(dev.packets.lock().is_empty());
}

#[test]
fn pktinfo_iface_without_matching_route_returns_unreachable() {
    let (stack, dev) = routed_capture(256);
    let other = stack.ifaces.register(Arc::new(CaptureDev {
        mtu: 256, packets: Spinlock::new(Vec::new()),
    }) as Arc<dyn NetDev>);
    let endpoint = Raw6Endpoint::standalone(network_namespace::initial(), IpProto::Udp as u8);
    let control = crate::send_control::Raw6Control {
        iface: Some(other), ..crate::send_control::Raw6Control::default()
    };

    assert_eq!(stack.send_raw6(&endpoint, ROUTE_DST, None, None, &[0; 8], 64,
        crate::uapi::IPV6_PMTUDISC_WANT, &control), Err(NetError::Enetunreach));
    assert!(dev.packets.lock().is_empty());
}

#[test]
fn fragmented_chain_keeps_headers_and_udp_header_in_fragment_zero() {
    let (stack, dev) = routed_capture(104);
    let endpoint = Raw6Endpoint::standalone(network_namespace::initial(), IpProto::Udp as u8);
    let mut route = vec![0, 2, 2, 1, 0, 0, 0, 0];
    route.extend_from_slice(&HEADER_DST.0);
    let control = crate::send_control::Raw6Control {
        hop_options: Some(vec![0; 8]), dst_before_routing: Some(vec![0; 8]),
        routing: Some(route), dst_after_routing: Some(vec![0; 8]),
        ..crate::send_control::Raw6Control::default()
    };
    let mut udp = vec![0; 48];
    let udp_len = udp.len() as u16;
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());

    stack.send_raw6(&endpoint, ROUTE_DST, None, None, &udp, 64,
        crate::uapi::IPV6_PMTUDISC_WANT, &control).unwrap();

    let packets = dev.packets.lock();
    assert!(packets.len() > 1);
    let first = &packets[0];
    let header = crate::ipv6::Ipv6Hdr::parse(first).unwrap();
    assert_eq!(header.dst, HEADER_DST);
    assert_eq!(header.next_header, 0);
    assert_eq!(first[40], 60);
    assert_eq!(first[48], 43);
    assert_eq!(first[56], 44);
    assert_eq!(&first[64..80], &ROUTE_DST.0);
    assert_eq!(first[80], 60);
    assert_eq!(first[88], IpProto::Udp as u8);
    assert_eq!(first.len(), 104);
}

#[test]
fn oversized_post_fragment_header_chain_returns_emsgsize() {
    let (stack, dev) = routed_capture(96);
    let endpoint = Raw6Endpoint::standalone(network_namespace::initial(), IpProto::Udp as u8);
    let mut destination_options = vec![0; 48];
    destination_options[1] = 5;
    let control = crate::send_control::Raw6Control {
        dst_after_routing: Some(destination_options),
        ..crate::send_control::Raw6Control::default()
    };

    assert_eq!(stack.send_raw6(&endpoint, ROUTE_DST, None, None, &[0; 24], 64,
        crate::uapi::IPV6_PMTUDISC_WANT, &control), Err(NetError::Emsgsize));
    assert!(dev.packets.lock().is_empty());
}

#[test]
fn arbitrary_protocol_payload_can_fragment() {
    let (stack, dev) = routed_capture(96);
    let endpoint = Raw6Endpoint::standalone(network_namespace::initial(), 253);

    stack.send_raw6(&endpoint, ROUTE_DST, None, None, &[0x5a; 96], 64,
        crate::uapi::IPV6_PMTUDISC_WANT, &crate::send_control::Raw6Control::default()).unwrap();

    assert!(dev.packets.lock().len() > 1);
}

#[test]
fn oversized_reassembled_payload_returns_emsgsize() {
    let (stack, dev) = routed_capture(1500);
    let endpoint = Raw6Endpoint::standalone(network_namespace::initial(), 253);

    assert_eq!(stack.send_raw6(&endpoint, ROUTE_DST, None, None, &[0; 65_536], 64,
        crate::uapi::IPV6_PMTUDISC_WANT, &crate::send_control::Raw6Control::default()),
        Err(NetError::Emsgsize));
    assert!(dev.packets.lock().is_empty());
}

#[test]
fn multicast_loop_disabled_never_enqueues_on_loopback() {
    let _domain = crate::hosted_fixture::init_net_domain();
    const GROUP: Ipv6Addr = Ipv6Addr([0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    stack.routes6.add(Route6Entry {
        table: crate::policy_rule::RT_TABLE_MAIN,
        dst: GROUP, prefix_len: 128, iface, gateway: None, src_hint: Some(Ipv6Addr::LOOPBACK),
        origin: crate::route6::Route6Origin::Static,
    });
    let endpoint = Raw6Endpoint::standalone(network_namespace::initial(), IpProto::Udp as u8);
    let control = crate::send_control::Raw6Control {
        multicast_loop: Some(false), ..crate::send_control::Raw6Control::default()
    };

    stack.send_raw6(&endpoint, GROUP, None, None, &[0; 8], 1,
        crate::uapi::IPV6_PMTUDISC_WANT, &control).unwrap();
    assert_eq!(lo.rx_len(), 0);
}
