use super::*;

fn udp6_segment(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut l4 = alloc::vec![0u8; crate::udp::UDP_HDR_LEN + payload.len()];
    crate::udp::build_into_v6(sport, dport, src, dst, payload, &mut l4);
    l4
}

fn ipv6_frame(src: Ipv6Addr, dst: Ipv6Addr, next: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = alloc::vec![0u8; crate::ipv6::IPV6_HDR_LEN + payload.len()];
    let mut hdr = crate::ipv6::Ipv6Hdr::build(src, dst, IpProto::Udp, payload.len() as u16);
    hdr.next_header = next;
    hdr.write_to(&mut frame[..crate::ipv6::IPV6_HDR_LEN]);
    frame[crate::ipv6::IPV6_HDR_LEN..].copy_from_slice(payload);
    frame
}

#[test]
fn ipv6_hbh_routing_destopts_demux_to_udp() {
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    let src = Ipv6Addr::LOOPBACK;
    let dst = Ipv6Addr::LOOPBACK;
    let sport = 48100;
    let dport = 48101;
    let body = b"ext-udp";
    let l4 = udp6_segment(src, dst, sport, dport, body);
    let mut payload = alloc::vec![0u8; 24 + l4.len()];
    payload[0] = crate::ipv6_ext::NH_ROUTING;
    payload[8] = crate::ipv6_ext::NH_DEST_OPTS;
    payload[10] = 4;
    payload[11] = 0;
    payload[16] = IpProto::Udp as u8;
    payload[24..].copy_from_slice(&l4);

    stack.bind_udp6(dst, dport).unwrap();
    let frame = ipv6_frame(src, dst, crate::ipv6_ext::NH_HOP_BY_HOP, &payload);
    stack.deliver_rx_ipv6(id, &frame).unwrap();

    let (peer, port, got) = stack.recv_udp6(dport).expect("extension-header UDP delivered");
    assert_eq!(peer, src);
    assert_eq!(port, sport);
    assert_eq!(got, body);
}

#[test]
fn ipv6_hbh_then_fragment_reassembles_to_udp() {
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    let src = Ipv6Addr::LOOPBACK;
    let dst = Ipv6Addr::LOOPBACK;
    let sport = 48110;
    let dport = 48111;
    let body = b"fragment-after-hbh";
    let l4 = udp6_segment(src, dst, sport, dport, body);

    fn frag_frame(src: Ipv6Addr, dst: Ipv6Addr, id: u32, offset: usize, more: bool, bytes: &[u8]) -> Vec<u8> {
        let mut payload = alloc::vec![0u8; 16 + bytes.len()];
        payload[0] = crate::ipv6_ext::NH_FRAGMENT;
        payload[8] = IpProto::Udp as u8;
        let off_more = (((offset / 8) as u16) << 3) | u16::from(more);
        payload[10..12].copy_from_slice(&off_more.to_be_bytes());
        payload[12..16].copy_from_slice(&id.to_be_bytes());
        payload[16..].copy_from_slice(bytes);
        ipv6_frame(src, dst, crate::ipv6_ext::NH_HOP_BY_HOP, &payload)
    }

    stack.bind_udp6(dst, dport).unwrap();
    let first_len = 16;
    let f1 = frag_frame(src, dst, 0xfeed_baad, 0, true, &l4[..first_len]);
    let f2 = frag_frame(src, dst, 0xfeed_baad, first_len, false, &l4[first_len..]);

    stack.deliver_rx_ipv6(id, &f2).unwrap();
    assert!(stack.recv_udp6(dport).is_none());
    stack.deliver_rx_ipv6(id, &f1).unwrap();

    let (peer, port, got) = stack.recv_udp6(dport).expect("reassembled extension-header UDP delivered");
    assert_eq!(peer, src);
    assert_eq!(port, sport);
    assert_eq!(got, body);
}
