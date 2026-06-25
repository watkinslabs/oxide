use super::*;

fn ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
    let mut pkt = alloc::vec![0u8; crate::ipv6::IPV6_HDR_LEN + payload.len()];
    let hdr = crate::ipv6::Ipv6Hdr::build(src, dst, IpProto::Icmpv6, payload.len() as u16);
    hdr.write_to(&mut pkt[..crate::ipv6::IPV6_HDR_LEN]);
    pkt[crate::ipv6::IPV6_HDR_LEN..].copy_from_slice(payload);
    pkt
}

#[test]
fn mld_general_query_reports_joined_group() {
    use crate::icmpv6::{
        build_mldv1_query, ICMPV6_TYPE_MLDV2_REPORT,
    };
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let src = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,2]);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x1234]);
    stack.add_v6_addr(id, src);

    stack.join_ipv6_multicast(id, group, src).unwrap();
    let _ = lo.rx_pop().expect("initial MLD report");

    let query = build_mldv1_query(router, crate::ndp::IPV6_ALL_NODES, Ipv6Addr::ANY, 1000);
    let packet = ipv6_packet(router, crate::ndp::IPV6_ALL_NODES, &query);
    stack.deliver_rx_ipv6(id, &packet).unwrap();

    let report = lo.rx_pop().expect("query response");
    let hdr = crate::ipv6::Ipv6Hdr::parse(report.data()).unwrap();
    assert_eq!(hdr.src, src);
    assert_eq!(hdr.dst, crate::icmpv6::IPV6_MLDV2_ROUTERS);
    let body = &report.data()[crate::ipv6::IPV6_HDR_LEN..];
    assert_eq!(body[0], ICMPV6_TYPE_MLDV2_REPORT);
    assert_eq!(u16::from_be_bytes([body[6], body[7]]), 1);
    assert_eq!(body[8], crate::icmpv6::MLDV2_RECORD_MODE_IS_EXCLUDE);
    assert_eq!(u16::from_be_bytes([body[10], body[11]]), 0);
    assert_eq!(&body[12..28], &group.0);
    assert!(lo.rx_pop().is_none());
}
