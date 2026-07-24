use crate::{IpProto, Ipv6Addr, NetStack};

fn udp_packet(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16) -> alloc::vec::Vec<u8> {
    let mut packet = alloc::vec![0u8; crate::ipv6::IPV6_HDR_LEN + crate::udp::UDP_HDR_LEN + 1];
    crate::ipv6::Ipv6Hdr::build(src, dst, IpProto::Udp, (crate::udp::UDP_HDR_LEN + 1) as u16)
        .write_to(&mut packet[..crate::ipv6::IPV6_HDR_LEN]);
    crate::udp::build_into_v6(
        sport, dport, src, dst, &[1], &mut packet[crate::ipv6::IPV6_HDR_LEN..],
    );
    packet
}

#[test]
fn ipv6_nonlocal_unicast_never_reaches_wildcard_udp() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let endpoint = stack.bind_udp6(Ipv6Addr::ANY, 42_321).unwrap();
    let foreign = Ipv6Addr::from_segments([0x2001, 0xdb8, 9, 0, 0, 0, 0, 1]);

    stack.deliver_rx_ipv6(
        iface, &udp_packet(Ipv6Addr::LOOPBACK, foreign, 9_000, 42_321),
    ).unwrap();

    assert!(endpoint.recv(false).is_none());
}

#[test]
fn ipv6_owned_unicast_reaches_wildcard_udp() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let endpoint = stack.bind_udp6(Ipv6Addr::ANY, 42_322).unwrap();

    stack.deliver_rx_ipv6(
        iface, &udp_packet(Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK, 9_001, 42_322),
    ).unwrap();

    assert_eq!(endpoint.recv(false).unwrap().6, alloc::vec![1]);
}

#[test]
fn ipv6_multicast_locality_tracks_ingress_interface_membership() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (joined_iface, _) = stack.register_loopback();
    let other_iface = stack.ifaces.register(alloc::sync::Arc::new(crate::LoopbackDev::new()));
    let group = Ipv6Addr::from_segments([0xff02, 0, 0, 0, 0, 0, 0, 0x1234]);

    assert!(!stack.v6_dst_is_local(joined_iface, group));
    stack.join_ipv6_multicast(joined_iface, group, Ipv6Addr::LOOPBACK).unwrap();
    assert!(stack.v6_dst_is_local(joined_iface, group));
    assert!(!stack.v6_dst_is_local(other_iface, group));

    stack.leave_ipv6_multicast(joined_iface, group, Ipv6Addr::LOOPBACK).unwrap();
    assert!(!stack.v6_dst_is_local(joined_iface, group));
}

#[test]
fn ipv6_all_nodes_is_always_local_on_a_registered_interface() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();

    assert!(stack.v6_dst_is_local(iface, crate::ndp::IPV6_ALL_NODES));
}
