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
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let endpoint = stack.bind_udp6(Ipv6Addr::ANY, 42_322).unwrap();

    stack.deliver_rx_ipv6(
        iface, &udp_packet(Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK, 9_001, 42_322),
    ).unwrap();

    assert_eq!(endpoint.recv(false).unwrap().5, alloc::vec![1]);
}
