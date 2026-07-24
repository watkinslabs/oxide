use super::*;
// Module manifest: ndp owns IPv6 Neighbor Discovery correctness tests.
#[path = "tcp_ipv6/ndp.rs"]
mod ndp;
// ----- F180a: IPv6 UDP bind + recv path -----------------------------

#[test]
fn f180a_ipv6_udp_bind_then_recv_routes_via_udp6() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::addr::Ipv6Addr;
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    use crate::udp::{UDP_HDR_LEN, build_into_v6};
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    // bind a v6 UDP socket on port 5060.
    let endpoint = stack.bind_udp6(Ipv6Addr::LOOPBACK, 5060).unwrap();
    // Build a v6/UDP frame: 40 IPv6 hdr + 8 UDP hdr + 5 payload.
    let payload = b"oxv6!";
    let l4_len  = UDP_HDR_LEN + payload.len();
    let total   = IPV6_HDR_LEN + l4_len;
    let mut frame = alloc::vec![0u8; total];
    build_into_v6(33000, 5060, Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK,
        payload, &mut frame[IPV6_HDR_LEN..]);
    let h = Ipv6Hdr::build(Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK,
        crate::addr::IpProto::Udp, l4_len as u16);
    h.write_to(&mut frame[..IPV6_HDR_LEN]);
    stack.deliver_rx_ipv6(id, &frame).unwrap();
    // The exact bound endpoint yields the IPv6 sender and payload.
    let (src, sport, _, _, _, _, body) = endpoint.recv(false).expect("v6 UDP must route to bound queue");
    assert_eq!(src, Ipv6Addr::LOOPBACK);
    assert_eq!(sport, 33000);
    assert_eq!(body, payload);
}

#[test]
fn f180a_ipv6_udp_no_bind_silent_drop() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::addr::Ipv6Addr;
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    use crate::udp::{UDP_HDR_LEN, build_into_v6};
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    let payload = b"x";
    let l4_len  = UDP_HDR_LEN + payload.len();
    let total   = IPV6_HDR_LEN + l4_len;
    let mut frame = alloc::vec![0u8; total];
    build_into_v6(1234, 9999, Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK,
        payload, &mut frame[IPV6_HDR_LEN..]);
    let h = Ipv6Hdr::build(Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK,
        crate::addr::IpProto::Udp, l4_len as u16);
    h.write_to(&mut frame[..IPV6_HDR_LEN]);
    // No socket bound → cleanly drop, no error.
    assert!(stack.deliver_rx_ipv6(id, &frame).is_ok());
    assert!(stack.udp6_demux(Ipv6Addr::LOOPBACK, 1234, Ipv6Addr::LOOPBACK, 9999, id).is_empty());
}

// SW2: IPv6 recvmsg ancillary — RX captures (dst, iface, hop_limit) so
// recvmsg can emit IPV6_PKTINFO + IPV6_HOPLIMIT (avahi enforces hop==255).
#[test]
fn sw2_ipv6_udp_rx_captures_pktinfo_and_hoplimit() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::addr::Ipv6Addr;
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    use crate::udp::{UDP_HDR_LEN, build_into_v6};
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    let endpoint = stack.bind_udp6(Ipv6Addr::LOOPBACK, 5353).unwrap();
    let payload = b"mdns";
    let l4_len  = UDP_HDR_LEN + payload.len();
    let total   = IPV6_HDR_LEN + l4_len;
    let mut frame = alloc::vec![0u8; total];
    build_into_v6(5353, 5353, Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK,
        payload, &mut frame[IPV6_HDR_LEN..]);
    let mut h = Ipv6Hdr::build(Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK,
        crate::addr::IpProto::Udp, l4_len as u16);
    h.hop_limit = 255; // on-link mDNS
    h.write_to(&mut frame[..IPV6_HDR_LEN]);
    stack.deliver_rx_ipv6(id, &frame).unwrap();
    let (src, sport, dst, iface, hop, _tclass, body) =
        endpoint.recv(false).expect("meta datagram delivered");
    assert_eq!(src, Ipv6Addr::LOOPBACK);
    assert_eq!(sport, 5353);
    assert_eq!(dst, Ipv6Addr::LOOPBACK);
    assert_eq!(iface, id);
    assert_eq!(hop, 255);
    assert_eq!(body, payload);
}

// SW2: IPV6_MULTICAST_HOPS / IPV6_UNICAST_HOPS reach the wire — the TX
// header carries the requested hop limit rather than the fixed default.
#[test]
fn sw2_ipv6_tx_header_carries_requested_hop_limit() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::addr::{Ipv6Addr, IpProto};
    use crate::ipv6::{push_ipv6_header_hop, IPV6_DEFAULT_HOP_LIMIT};
    use crate::pkt::Pkt;
    let mut p = Pkt::with_capacity(crate::ipv6::IPV6_HDR_LEN, 64);
    p.put(4).unwrap().copy_from_slice(b"abcd");
    push_ipv6_header_hop(&mut p, Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK, IpProto::Udp, 255).unwrap();
    // hop_limit is byte 7 of the IPv6 header (front of the packet).
    assert_eq!(p.data()[7], 255);
    assert_ne!(255, IPV6_DEFAULT_HOP_LIMIT, "test is meaningful only if 255 != default");
}

// ----- netfilter hook wiring: PRE_ROUTING/LOCAL_IN (RX), LOCAL_OUT/
//        POST_ROUTING (TX) must fire on the real IPv4 AND IPv6 paths -----

#[test]
fn netfilter_hooks_fire_on_rx_and_tx_both_families() {
    let domain = crate::hosted_fixture::init_net_domain();
    use core::sync::atomic::{AtomicU32, Ordering};
    use crate::stack::{NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN,
        NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING};
    use crate::netfilter_hook::{NFPROTO_IPV4, NFPROTO_IPV6};
    use crate::ipv4::{push_ipv4_header, IPV4_HDR_LEN};
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    use crate::udp::{UDP_HDR_LEN, build_into_v6};
    use crate::addr::Ipv6Addr;

    // Per-family recorder: OR each hook id into the family's mask. Returns
    // NF_ACCEPT(1) so the path behaves exactly as the no-hook default.
    static SEEN_V4: AtomicU32 = AtomicU32::new(0);
    static SEEN_V6: AtomicU32 = AtomicU32::new(0);
    fn rec(h: u32, _p: &[u8], fam: u8) -> u32 {
        let slot = if fam == NFPROTO_IPV6 { &SEEN_V6 } else { &SEEN_V4 };
        slot.fetch_or(1u32 << h, Ordering::AcqRel);
        1
    }
    domain.set_nf_hook(rec);
    SEEN_V4.store(0, Ordering::Release);
    SEEN_V6.store(0, Ordering::Release);

    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();

    // --- IPv4 RX (PRE_ROUTING + LOCAL_IN) + TX (LOCAL_OUT + POST_ROUTING).
    let lo4 = Ipv4Addr::LOOPBACK;
    let payload = b"nf!";
    let mut p = Pkt::with_capacity(IPV4_HDR_LEN, IPV4_HDR_LEN + UDP_HDR_LEN + payload.len() + IPV4_HDR_LEN);
    let slot = p.put(UDP_HDR_LEN + payload.len()).unwrap();
    crate::udp::UdpHdr::build_into(40000, 5555, lo4, lo4, payload, slot);
    push_ipv4_header(&mut p, lo4, lo4, IpProto::Udp, 1).unwrap();
    let frame = p.data().to_vec();
    stack.bind_udp(lo4, 5555).unwrap();
    stack.deliver_rx(id, &frame).unwrap();
    stack.send_l4_over_ipv4_pub(lo4, lo4, b"hello").unwrap();

    // --- IPv6 RX + TX over the same loopback iface.
    let lo6 = Ipv6Addr::LOOPBACK;
    let l4_len = UDP_HDR_LEN + payload.len();
    let mut frame6 = alloc::vec![0u8; IPV6_HDR_LEN + l4_len];
    build_into_v6(40001, 5556, lo6, lo6, payload, &mut frame6[IPV6_HDR_LEN..]);
    Ipv6Hdr::build(lo6, lo6, IpProto::Udp, l4_len as u16).write_to(&mut frame6[..IPV6_HDR_LEN]);
    stack.deliver_rx_ipv6(id, &frame6).unwrap();
    stack.send_l4_over_ipv6(lo6, lo6, IpProto::Udp, b"hello6").unwrap();

    for (fam, seen) in [("v4", SEEN_V4.load(Ordering::Acquire)),
                        ("v6", SEEN_V6.load(Ordering::Acquire))] {
        assert!(seen & (1 << NF_INET_PRE_ROUTING)  != 0, "{fam} PRE_ROUTING did not fire");
        assert!(seen & (1 << NF_INET_LOCAL_IN)     != 0, "{fam} LOCAL_IN did not fire");
        assert!(seen & (1 << NF_INET_LOCAL_OUT)    != 0, "{fam} LOCAL_OUT did not fire");
        assert!(seen & (1 << NF_INET_POST_ROUTING) != 0, "{fam} POST_ROUTING did not fire");
    }
}

#[test]
fn f180a_ipv6_udp_eaddrinuse_on_dup_bind() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::addr::Ipv6Addr;
    let stack = NetStack::new();
    stack.bind_udp6(Ipv6Addr::LOOPBACK, 8888).unwrap();
    assert_eq!(stack.bind_udp6(Ipv6Addr::LOOPBACK, 8888).err().unwrap(),
               NetError::Eaddrinuse);
}


#[test]
fn ipv6_mld_join_and_leave_emit_reports() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::icmpv6::{
        ICMPV6_TYPE_MLDV2_REPORT, MLDV2_RECORD_CHANGE_TO_EXCLUDE,
        MLDV2_RECORD_CHANGE_TO_INCLUDE,
    };
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let src = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x1234]);

    stack.join_ipv6_multicast(id, group, src).unwrap();
    let report = lo.rx_pop().expect("MLD report");
    let report_h = Ipv6Hdr::parse(report.data()).unwrap();
    assert_eq!(report_h.dst, crate::icmpv6::IPV6_MLDV2_ROUTERS);
    assert_eq!(report_h.next_header, crate::ipv6_ext::NH_HOP_BY_HOP);
    let body = &report.data()[IPV6_HDR_LEN + 8..];
    assert_eq!(body[0], ICMPV6_TYPE_MLDV2_REPORT);
    assert_eq!(body[8], MLDV2_RECORD_CHANGE_TO_EXCLUDE);
    assert_eq!(&body[12..28], &group.0);

    stack.leave_ipv6_multicast(id, group, src).unwrap();
    let done = lo.rx_pop().expect("MLD done");
    let done_h = Ipv6Hdr::parse(done.data()).unwrap();
    assert_eq!(done_h.dst, crate::icmpv6::IPV6_MLDV2_ROUTERS);
    assert_eq!(done_h.next_header, crate::ipv6_ext::NH_HOP_BY_HOP);
    let body = &done.data()[IPV6_HDR_LEN + 8..];
    assert_eq!(body[0], ICMPV6_TYPE_MLDV2_REPORT);
    assert_eq!(body[8], MLDV2_RECORD_CHANGE_TO_INCLUDE);
    assert_eq!(&body[12..28], &group.0);
}

// ----- F180b: TCP over IPv6 -----------------------------------------

#[test]
fn f180b_tcp_listen_then_connect_over_ipv6_via_lo() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::addr::{IpAddr, Ipv6Addr};
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let listener = stack.tcp_listen_ip(IpAddr::V6(Ipv6Addr::LOOPBACK), 4444, true).unwrap();
    let client = stack.tcp_connect_ip(
        IpAddr::V6(Ipv6Addr::LOOPBACK), 50001,
        IpAddr::V6(Ipv6Addr::LOOPBACK), 4444,
    ).unwrap();
    // SYN → SYN-ACK → ACK via v6 deliver path.
    for _ in 0..3 { stack.drain_loopback(id, &lo); }
    let server = stack.tcp_accept(&listener).expect("v6 accept");
    assert_eq!(client.conn.lock().state, TcpState::Established);
    assert_eq!(server.conn.lock().state, TcpState::Established);
}

#[test]
fn f180b_tcp_demux_keys_v6_independently_of_v4() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::addr::{IpAddr, Ipv4Addr, Ipv6Addr};
    let stack = NetStack::new();
    let _ = stack.register_loopback();
    // Same port on both families must not collide.
    stack.tcp_listen_ip(IpAddr::V4(Ipv4Addr::LOOPBACK), 7777, true).unwrap();
    stack.tcp_listen_ip(IpAddr::V6(Ipv6Addr::LOOPBACK), 7777, true).unwrap();
}

// ----- F180: IPv6 minimum-viable deliver_rx_ipv6 --------------------

#[test]
fn f180_ipv6_echo_request_produces_echo_reply_on_lo() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::addr::Ipv6Addr;
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    use crate::icmpv6::{Icmp6Echo, ICMPV6_TYPE_ECHO_REQUEST, IPPROTO_ICMPV6, ICMPV6_HDR_LEN};
    let stack = NetStack::new();
    let (id, lo_dev) = stack.register_loopback();
    // Build an Echo Request: 40-byte IPv6 header + 8-byte ICMPv6
    // + 4-byte payload.
    let src = Ipv6Addr::LOOPBACK;
    let dst = Ipv6Addr::LOOPBACK;
    let payload = b"oxv6";
    let icmp_len = ICMPV6_HDR_LEN + payload.len();
    let total = IPV6_HDR_LEN + icmp_len;
    let mut frame = alloc::vec![0u8; total];
    // ICMPv6 first (so build_into can compute checksum over the body).
    let mut h = Icmp6Echo { typ: ICMPV6_TYPE_ECHO_REQUEST, code: 0, checksum: 0, id: 1, seq: 42 };
    let mut icmp_buf = alloc::vec![0u8; icmp_len];
    h.build_into(src, dst, payload, &mut icmp_buf);
    frame[IPV6_HDR_LEN..].copy_from_slice(&icmp_buf);
    // IPv6 header.
    let v6 = Ipv6Hdr::build(src, dst, crate::addr::IpProto::Icmpv6, icmp_len as u16);
    v6.write_to(&mut frame[..IPV6_HDR_LEN]);
    // Deliver — should xmit an Echo Reply onto lo.
    stack.deliver_rx_ipv6(id, &frame).unwrap();
    // Pop the reply from lo's xmit queue.
    let reply = lo_dev.rx_pop().expect("echo reply should land on lo");
    let reply_v6 = Ipv6Hdr::parse(reply.data()).unwrap();
    assert_eq!(reply_v6.next_header, IPPROTO_ICMPV6);
    let reply_icmp = &reply.data()[IPV6_HDR_LEN..];
    assert_eq!(reply_icmp[0], crate::icmpv6::ICMPV6_TYPE_ECHO_REPLY);
}

#[test]
fn f180_ipv6_udp_dropped_silently() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::addr::Ipv6Addr;
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    // 40-byte IPv6 header advertising UDP next-header + zero payload.
    let mut frame = alloc::vec![0u8; IPV6_HDR_LEN];
    let v6 = Ipv6Hdr::build(Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK,
        crate::addr::IpProto::Udp, 0);
    v6.write_to(&mut frame);
    // No socket bound for IPv6; should drop cleanly (no error, no panic).
    let r = stack.deliver_rx_ipv6(id, &frame);
    assert!(r.is_ok(), "IPv6 UDP without socket: drop, not error");
}

#[test]
fn ipv6_fragments_reassemble_to_udp_socket() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::addr::{IpProto, Ipv6Addr};
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    use crate::udp::UDP_HDR_LEN;

    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    let src = Ipv6Addr::LOOPBACK;
    let dst = Ipv6Addr::LOOPBACK;
    let src_port = 40100;
    let dst_port = 40101;
    let payload = b"fragmented-ipv6-udp-payload";
    let l4_len = UDP_HDR_LEN + payload.len();
    let mut l4 = alloc::vec![0u8; l4_len];
    crate::udp::build_into_v6(src_port, dst_port, src, dst, payload, &mut l4);

    fn frag_frame(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        id: u32,
        offset: usize,
        more: bool,
        bytes: &[u8],
    ) -> Vec<u8> {
        let payload_len = 8 + bytes.len();
        let total = IPV6_HDR_LEN + payload_len;
        let mut frame = alloc::vec![0u8; total];
        let hdr = Ipv6Hdr::build(src, dst, IpProto::Fragment, payload_len as u16);
        hdr.write_to(&mut frame[..IPV6_HDR_LEN]);
        let frag = &mut frame[IPV6_HDR_LEN..IPV6_HDR_LEN + 8];
        frag[0] = IpProto::Udp as u8;
        let off_more = (((offset / 8) as u16) << 3) | u16::from(more);
        frag[2..4].copy_from_slice(&off_more.to_be_bytes());
        frag[4..8].copy_from_slice(&id.to_be_bytes());
        frame[IPV6_HDR_LEN + 8..].copy_from_slice(bytes);
        frame
    }

    let endpoint = stack.bind_udp6(dst, dst_port).unwrap();
    let first_len = 16;
    let f1 = frag_frame(src, dst, 0x1234_5678, 0, true, &l4[..first_len]);
    let f2 = frag_frame(src, dst, 0x1234_5678, first_len, false, &l4[first_len..]);

    stack.deliver_rx_ipv6(id, &f2).unwrap();
    assert!(endpoint.recv(false).is_none(), "last fragment alone is incomplete");
    stack.deliver_rx_ipv6(id, &f1).unwrap();

    let (peer, port, _, _, _, _, body) = endpoint.recv(false).expect("reassembled datagram delivered");
    assert_eq!(peer, src);
    assert_eq!(port, src_port);
    assert_eq!(body, payload);
}
