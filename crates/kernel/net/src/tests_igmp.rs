use super::*;

fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let mut pkt = alloc::vec![0u8; crate::ipv4::IPV4_HDR_LEN + payload.len()];
    let hdr = crate::ipv4::Ipv4Hdr::build(src, dst, IpProto::Igmp, payload.len() as u16, 1);
    hdr.write_to(&mut pkt[..crate::ipv4::IPV4_HDR_LEN]);
    pkt[crate::ipv4::IPV4_HDR_LEN..].copy_from_slice(payload);
    pkt
}

fn udp_packet(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let l4_len = crate::udp::UDP_HDR_LEN + payload.len();
    let mut pkt = alloc::vec![0u8; crate::ipv4::IPV4_HDR_LEN + l4_len];
    crate::udp::UdpHdr::build_into(sport, dport, src, dst, payload, &mut pkt[crate::ipv4::IPV4_HDR_LEN..]);
    let hdr = crate::ipv4::Ipv4Hdr::build(src, dst, IpProto::Udp, l4_len as u16, 7);
    hdr.write_to(&mut pkt[..crate::ipv4::IPV4_HDR_LEN]);
    pkt
}

#[test]
fn igmp_join_leave_emit_report_and_leave() {
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let src = Ipv4Addr::LOOPBACK;
    let group = Ipv4Addr::new(224, 1, 2, 3);

    stack.join_ipv4_multicast(id, group, src).unwrap();
    let report = lo.rx_pop().expect("IGMP report");
    let hdr = crate::ipv4::Ipv4Hdr::parse(report.data()).unwrap();
    assert_eq!(hdr.src, src);
    assert_eq!(hdr.dst, group);
    assert_eq!(hdr.proto, IpProto::Igmp as u8);
    assert_eq!(hdr.ttl, 1);
    let body = &report.data()[crate::ipv4::IPV4_HDR_LEN..];
    assert_eq!(body[0], crate::igmp::IGMP_TYPE_V2_REPORT);
    assert_eq!(&body[4..8], &group.octets());

    stack.leave_ipv4_multicast(id, group, src).unwrap();
    let leave = lo.rx_pop().expect("IGMP leave");
    let hdr = crate::ipv4::Ipv4Hdr::parse(leave.data()).unwrap();
    assert_eq!(hdr.dst, crate::igmp::IPV4_ALL_ROUTERS);
    let body = &leave.data()[crate::ipv4::IPV4_HDR_LEN..];
    assert_eq!(body[0], crate::igmp::IGMP_TYPE_LEAVE);
    assert_eq!(&body[4..8], &group.octets());
}

#[test]
fn igmp_general_query_reports_joined_group() {
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let src = Ipv4Addr::LOOPBACK;
    let router = Ipv4Addr::new(127, 0, 0, 2);
    let group = Ipv4Addr::new(224, 9, 8, 7);

    stack.join_ipv4_multicast(id, group, src).unwrap();
    let _ = lo.rx_pop().expect("initial IGMP report");

    let query = crate::igmp::build_igmp_query(Ipv4Addr::ANY, 10);
    let packet = ipv4_packet(router, crate::igmp::IPV4_ALL_HOSTS, &query);
    stack.deliver_rx(id, &packet).unwrap();

    let report = lo.rx_pop().expect("query response");
    let hdr = crate::ipv4::Ipv4Hdr::parse(report.data()).unwrap();
    assert_eq!(hdr.src, src);
    assert_eq!(hdr.dst, group);
    let body = &report.data()[crate::ipv4::IPV4_HDR_LEN..];
    assert_eq!(body[0], crate::igmp::IGMP_TYPE_V2_REPORT);
    assert_eq!(&body[4..8], &group.octets());
    assert!(lo.rx_pop().is_none());
}

#[test]
fn ipv4_multicast_source_filter_drops_denied_udp_source() {
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    let group = Ipv4Addr::new(239, 8, 7, 6);
    let allowed = Ipv4Addr::new(10, 0, 0, 1);
    let denied = Ipv4Addr::new(10, 0, 0, 2);
    let port = 47117;

    stack.bind_udp(Ipv4Addr::ANY, port).unwrap();
    crate::mcast_filter::set(port, id, group, crate::mcast_filter::FilterMode::Include, &[allowed]);

    let blocked = udp_packet(denied, group, 32000, port, b"blocked");
    stack.deliver_rx(id, &blocked).unwrap();
    assert!(stack.recv_udp_meta_opts(port, false).is_none());

    let accepted = udp_packet(allowed, group, 32001, port, b"accepted");
    stack.deliver_rx(id, &accepted).unwrap();
    let (src, sport, dst, iface, body) = stack.recv_udp_meta_opts(port, false).unwrap();
    assert_eq!(src, allowed);
    assert_eq!(sport, 32001);
    assert_eq!(dst, group);
    assert_eq!(iface, id);
    assert_eq!(&body, b"accepted");
}
