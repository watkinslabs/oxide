use super::*;
use alloc::vec;

fn udp4_packet(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 28];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(28u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = IpProto::Udp as u8;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt[20..22].copy_from_slice(&sport.to_be_bytes());
    pkt[22..24].copy_from_slice(&dport.to_be_bytes());
    pkt[24..26].copy_from_slice(&(8u16).to_be_bytes());
    pkt
}

#[test]
fn live_socket_lookup_reads_udp_owner_and_transparent_target() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let endpoint = stack.bind_udp_with_iface(Ipv4Addr::ANY, 5_300, Some(iface))
        .expect("bind UDP endpoint");
    endpoint.set_transparent(true);
    let pkt = udp4_packet(Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(198, 51, 100, 20), 40_000, 5_300);
    let info = stack.socket_lookup_in(0, NFPROTO_IPV4, &pkt, Some(iface))
        .expect("socket lookup");
    assert_eq!(info, SocketLookup { full: true, transparent: true, mark: 0, wildcard: true,
        uid: Some(0), gid: Some(0), cgroup: Some(cgroup::ROOT_CGROUP) });
    assert!(stack.transparent_udp4_in(0, Ipv4Addr::new(203, 0, 113, 7), 5_300,
        Some(iface)));
}

#[test]
fn ipv6_socket_transport_walks_extension_headers() {
    let mut pkt = vec![0u8; 56];
    pkt[0] = 0x60;
    pkt[6] = 0;
    pkt[40] = IpProto::Udp as u8;
    pkt[41] = 0;
    assert_eq!(ipv6_socket_transport(&pkt), Some((IpProto::Udp as u8, 48)));
}

#[test]
fn transparent_tcp_target_uses_the_listener_bind_owner() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let bind = stack.tcp_reserve(IpAddr::V4(Ipv4Addr::ANY), 5_401, Some(iface),
        false, false, 0, false).expect("reserve TCP bind");
    bind.set_transparent(true);
    stack.tcp_listen_reserved(&bind).expect("publish listener");
    assert!(stack.transparent_tcp4_in(0, Ipv4Addr::new(203, 0, 113, 7), 5_401,
        Some(iface)));
}
