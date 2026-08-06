use super::*;

fn ipv4_query_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8], ttl: u8,
                     router_alert: bool) -> Vec<u8> {
    let header_len = if router_alert { 24 } else { 20 };
    let mut packet = alloc::vec![0u8; header_len + payload.len()];
    let hdr = crate::ipv4::Ipv4Hdr::build(src, dst, IpProto::Igmp, payload.len() as u16, 1);
    hdr.write_to(&mut packet[..crate::ipv4::IPV4_HDR_LEN]);
    packet[0] = 0x40 | (header_len / 4) as u8;
    packet[2..4].copy_from_slice(&((header_len + payload.len()) as u16).to_be_bytes());
    packet[8] = ttl;
    packet[10..12].copy_from_slice(&0u16.to_be_bytes());
    if router_alert { packet[20..24].copy_from_slice(&[0x94, 0x04, 0, 0]); }
    let checksum = crate::ipv4::ip_checksum(&packet[..header_len]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[header_len..].copy_from_slice(payload);
    packet
}

fn ipv6_query_packet(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8], hop_limit: u8,
                     router_alert: bool) -> Vec<u8> {
    let mut extension = [IpProto::Icmpv6 as u8, 0, 5, 2, 0, 0, 1, 0];
    if !router_alert { extension[4] = 1; }
    let mut packet = alloc::vec![0u8; crate::ipv6::IPV6_HDR_LEN + extension.len() + payload.len()];
    let mut hdr = crate::ipv6::Ipv6Hdr::build(src, dst, IpProto::Raw,
        (extension.len() + payload.len()) as u16);
    hdr.next_header = 0;
    hdr.hop_limit = hop_limit;
    hdr.write_to(&mut packet[..crate::ipv6::IPV6_HDR_LEN]);
    packet[40..48].copy_from_slice(&extension);
    packet[48..].copy_from_slice(payload);
    packet
}

fn finish_changes(stack: &NetStack, lo: &crate::LoopbackDev) {
    stack.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS);
    let _ = lo.rx_pop().expect("multicast retransmission");
}

#[test]
fn igmp_query_timer_is_bounded_and_pending_queries_combine() {
    let group = Ipv4Addr::new(232, 1, 2, 3);
    let a = Ipv4Addr::new(192, 0, 2, 1);
    let b = Ipv4Addr::new(192, 0, 2, 2);
    let mut state = crate::mcast_state::V4IfaceGroup::new(7, group, Ipv4Addr::LOOPBACK);
    state.queue_query(3, &[a], 100, 1_000, 250);
    assert_eq!(state.queries[0].deadline_ns, 1_048);
    state.queue_query(3, &[b], 100, 1_010, 5);
    assert_eq!(state.queries.len(), 1);
    assert_eq!(state.queries[0].deadline_ns, 1_015);
    assert_eq!(state.queries[0].sources, [a, b]);
    state.queue_query(2, &[], 100, 1_020, 99);
    assert_eq!(state.queries[0].version, 2);
    assert!(state.queries[0].sources.is_empty());
    assert_eq!(state.queries[0].deadline_ns, 1_015);
}

#[test]
fn mld_query_timer_uses_pinned_clock_and_random_sample() {
    let group = Ipv6Addr::from_segments([0xff3e,0,0,0,0,0,0,0x1234]);
    let a = Ipv6Addr::from_segments([0x2001,0xdb8,0,0,0,0,0,1]);
    let b = Ipv6Addr::from_segments([0x2001,0xdb8,0,0,0,0,0,2]);
    let mut state = crate::mcast_state::V6IfaceGroup::new(9, group, Ipv6Addr::ANY);
    state.queue_query(2, &[a], 1_000, 20_000, 2_501);
    assert_eq!(state.queries[0].deadline_ns, 20_499);
    state.queue_query(2, &[b], 1_000, 20_100, 700);
    assert_eq!(state.queries[0].deadline_ns, 20_499);
    assert_eq!(state.queries[0].sources, [a, b]);
    state.queue_query(1, &[], 1_000, 20_200, 0);
    assert_eq!(state.queries[0].deadline_ns, 20_200);
    assert_eq!(state.queries[0].version, 1);
    assert!(state.queries[0].sources.is_empty());
}

#[test]
fn igmp_admission_requires_ttl_one_and_router_alert() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let group = Ipv4Addr::new(239, 1, 2, 4);
    let router = Ipv4Addr::new(127, 0, 0, 2);
    stack.join_ipv4_multicast(iface, group, Ipv4Addr::LOOPBACK).unwrap();
    let _ = lo.rx_pop().unwrap();
    finish_changes(&stack, &lo);
    let query = crate::igmp::build_igmp_query(group, 10);
    stack.deliver_rx(iface, &ipv4_query_packet(router, group, &query, 2, true)).unwrap();
    stack.deliver_rx(iface, &ipv4_query_packet(router, group, &query, 1, false)).unwrap();
    assert!(lo.rx_pop().is_none());
    stack.deliver_rx(iface, &ipv4_query_packet(router, group, &query, 1, true)).unwrap();
    assert!(lo.rx_pop().is_some());
}

#[test]
fn igmp_query_accepts_assigned_interface_destination_only() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let group = Ipv4Addr::new(239, 1, 2, 7);
    let router = Ipv4Addr::new(127, 0, 0, 2);
    stack.join_ipv4_multicast(iface, group, Ipv4Addr::LOOPBACK).unwrap();
    let _ = lo.rx_pop().unwrap();
    finish_changes(&stack, &lo);

    let general = crate::igmp::build_igmp_query(Ipv4Addr::ANY, 10);
    stack.deliver_rx(iface, &ipv4_query_packet(router, Ipv4Addr::LOOPBACK,
        &general, 1, true)).unwrap();
    assert!(lo.rx_pop().is_some());
    let specific = crate::igmp::build_igmp_query(group, 10);
    stack.deliver_rx(iface, &ipv4_query_packet(router, Ipv4Addr::LOOPBACK,
        &specific, 1, true)).unwrap();
    assert!(lo.rx_pop().is_some());
    stack.deliver_rx(iface, &ipv4_query_packet(router, Ipv4Addr::new(192, 0, 2, 99),
        &general, 1, true)).unwrap();
    assert!(lo.rx_pop().is_none());
}

#[test]
fn mld_admission_requires_link_local_source_hl_one_and_router_alert() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let host = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,2]);
    let global = Ipv6Addr::from_segments([0x2001,0xdb8,0,0,0,0,0,2]);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x1235]);
    stack.add_v6_addr(iface, host);
    stack.join_ipv6_multicast(iface, group, host).unwrap();
    let _ = lo.rx_pop().unwrap();
    finish_changes(&stack, &lo);
    let global_query = crate::icmpv6::build_mldv1_query(global, group, group, 1000);
    stack.deliver_rx_ipv6(iface, &ipv6_query_packet(global, group, &global_query, 1, true)).unwrap();
    let query = crate::icmpv6::build_mldv1_query(router, group, group, 1000);
    stack.deliver_rx_ipv6(iface, &ipv6_query_packet(router, group, &query, 2, true)).unwrap();
    stack.deliver_rx_ipv6(iface, &ipv6_query_packet(router, group, &query, 1, false)).unwrap();
    assert!(lo.rx_pop().is_none());
    stack.deliver_rx_ipv6(iface, &ipv6_query_packet(router, group, &query, 1, true)).unwrap();
    assert!(lo.rx_pop().is_some());
}

#[test]
fn mld_query_accepts_assigned_interface_destination_only() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let host = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,2]);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x1237]);
    stack.add_v6_addr(iface, host);
    stack.join_ipv6_multicast(iface, group, host).unwrap();
    let _ = lo.rx_pop().unwrap();
    finish_changes(&stack, &lo);

    let general = crate::icmpv6::build_mldv1_query(router, host, Ipv6Addr::ANY, 1000);
    stack.deliver_rx_ipv6(iface, &ipv6_query_packet(router, host, &general, 1, true)).unwrap();
    assert!(lo.rx_pop().is_some());
    let specific = crate::icmpv6::build_mldv1_query(router, host, group, 1000);
    stack.deliver_rx_ipv6(iface, &ipv6_query_packet(router, host, &specific, 1, true)).unwrap();
    assert!(lo.rx_pop().is_some());
    let unrelated = Ipv6Addr::from_segments([0x2001,0xdb8,0,0,0,0,0,99]);
    let general = crate::icmpv6::build_mldv1_query(router, unrelated, Ipv6Addr::ANY, 1000);
    stack.deliver_rx_ipv6(iface, &ipv6_query_packet(router, unrelated, &general, 1, true)).unwrap();
    assert!(lo.rx_pop().is_none());
}

#[test]
fn older_querier_mode_is_interface_generation_scoped() {
    let v4 = alloc::vec![crate::mcast_state::V4IfaceGroup::new(
        11, Ipv4Addr::new(239, 1, 3, 1), Ipv4Addr::LOOPBACK)];
    v4[0].observe_general_query(0, 0, 1_000, 2, 10);
    let inherited4 = crate::mcast_state::V4IfaceGroup::inherited(
        &v4, 11, Ipv4Addr::new(239, 1, 3, 2), Ipv4Addr::LOOPBACK);
    assert_eq!(inherited4.report_version(11), 2);
    let fresh4 = crate::mcast_state::V4IfaceGroup::inherited(
        &v4, 12, Ipv4Addr::new(239, 1, 3, 3), Ipv4Addr::LOOPBACK);
    assert_eq!(fresh4.report_version(11), 3);
    let v6 = alloc::vec![crate::mcast_state::V6IfaceGroup::new(21,
        Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x1301]), Ipv6Addr::ANY)];
    v6[0].observe_general_query(0, 0, 1_000, 1, 10);
    let inherited6 = crate::mcast_state::V6IfaceGroup::inherited(&v6, 21,
        Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x1302]), Ipv6Addr::ANY);
    assert_eq!(inherited6.report_version(11), 1);
}

#[test]
fn first_membership_inherits_older_general_query_mode() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _lo) = stack.register_loopback();
    let ingress = stack.ifaces.acquire_ingress(iface).unwrap();
    let general4 = crate::igmp::build_igmp_query(Ipv4Addr::ANY, 0);
    stack.handle_igmp(&ingress, Ipv4Addr::new(127, 0, 0, 2),
        crate::igmp::IPV4_ALL_HOSTS, &general4).unwrap();
    let group4 = Ipv4Addr::new(239, 1, 3, 6);
    stack.join_ipv4_multicast(iface, group4, Ipv4Addr::LOOPBACK).unwrap();
    assert_eq!(stack.v4_mcast.lock()[&iface].iter().find(|state|
        state.group == group4).unwrap().report_version(0), 1);

    let host = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    stack.add_v6_addr(iface, host);
    let general6 = crate::icmpv6::Mldv1Query { max_resp_delay: 1_000, group: Ipv6Addr::ANY,
        sources: alloc::vec::Vec::new(), qrv: 0, qqic: 0 };
    stack.respond_mld_query(&ingress, crate::ndp::IPV6_ALL_NODES, general6, true).unwrap();
    let group6 = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x1306]);
    stack.join_ipv6_multicast(iface, group6, host).unwrap();
    assert_eq!(stack.v6_mcast.lock()[&iface].iter().find(|state|
        state.group == group6).unwrap().report_version(0), 1);
}

#[test]
fn group_specific_queries_do_not_downgrade_interface() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let ingress = stack.ifaces.acquire_ingress(iface).unwrap();
    let group4 = Ipv4Addr::new(239, 1, 3, 4);
    stack.join_ipv4_multicast(iface, group4, Ipv4Addr::LOOPBACK).unwrap();
    let _ = lo.rx_pop(); finish_changes(&stack, &lo);
    let specific4 = crate::igmp::build_igmp_query(group4, 0);
    stack.handle_igmp(&ingress, Ipv4Addr::new(127, 0, 0, 2), group4, &specific4).unwrap();
    let _ = lo.rx_pop();
    assert_eq!(stack.v4_mcast.lock()[&iface].iter().find(|state|
        state.group == group4).unwrap().report_version(0), 3);
    let general4 = crate::igmp::build_igmp_query(Ipv4Addr::ANY, 0);
    stack.handle_igmp(&ingress, Ipv4Addr::new(127, 0, 0, 2),
        crate::igmp::IPV4_ALL_HOSTS, &general4).unwrap();
    let _ = lo.rx_pop();
    let group4b = Ipv4Addr::new(239, 1, 3, 5);
    stack.join_ipv4_multicast(iface, group4b, Ipv4Addr::LOOPBACK).unwrap();
    assert_eq!(stack.v4_mcast.lock()[&iface].iter().find(|state|
        state.group == group4b).unwrap().report_version(0), 1);
    let _ = lo.rx_pop(); finish_changes(&stack, &lo);

    let host = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let group6 = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x1304]);
    stack.add_v6_addr(iface, host);
    stack.join_ipv6_multicast(iface, group6, host).unwrap();
    let _ = lo.rx_pop(); finish_changes(&stack, &lo);
    let query6 = crate::icmpv6::Mldv1Query { max_resp_delay: 1_000, group: group6,
        sources: alloc::vec::Vec::new(), qrv: 0, qqic: 0 };
    stack.respond_mld_query(&ingress, group6, query6, true).unwrap();
    let _ = lo.rx_pop();
    assert_eq!(stack.v6_mcast.lock()[&iface].iter().find(|state|
        state.group == group6).unwrap().report_version(0), 2);
    let general6 = crate::icmpv6::Mldv1Query { max_resp_delay: 1_000, group: Ipv6Addr::ANY,
        sources: alloc::vec::Vec::new(), qrv: 0, qqic: 0 };
    stack.respond_mld_query(&ingress, crate::ndp::IPV6_ALL_NODES, general6, true).unwrap();
    let _ = lo.rx_pop();
    let group6b = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x1305]);
    stack.join_ipv6_multicast(iface, group6b, host).unwrap();
    assert_eq!(stack.v6_mcast.lock()[&iface].iter().find(|state|
        state.group == group6b).unwrap().report_version(0), 1);
}

#[test]
fn mld_report_source_is_link_local_or_unspecified() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let global = Ipv6Addr::from_segments([0x2001,0xdb8,0,0,0,0,0,1]);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x1236]);
    stack.add_v6_addr(iface, global);
    stack.join_ipv6_multicast(iface, group, global).unwrap();
    let report = lo.rx_pop().expect("MLD report");
    assert_eq!(crate::ipv6::Ipv6Hdr::parse(report.data()).unwrap().src, Ipv6Addr::ANY);
}

#[test]
fn mld_report_source_tracks_link_local_dad_completion() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let link_local = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,4]);
    let prefix = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,0]);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x1238]);
    let group2 = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x1239]);
    assert_eq!(stack.upsert_slaac_addr(iface, link_local, 64, u32::MAX, u32::MAX,
        prefix, 0, None), Some(true));

    stack.join_ipv6_multicast(iface, group, Ipv6Addr::ANY).unwrap();
    let report = lo.rx_pop().expect("initial MLD report");
    assert_eq!(crate::ipv6::Ipv6Hdr::parse(report.data()).unwrap().src, Ipv6Addr::ANY);
    stack.join_ipv6_multicast(iface, group2, Ipv6Addr::ANY).unwrap();
    let _ = lo.rx_pop().expect("second initial MLD report");
    stack.v6_addrs.lock().get_mut(&iface).unwrap().iter_mut()
        .find(|row| row.addr == link_local).unwrap().state = crate::stack_ipv6::Ipv6AddrState::Assigned;
    assert_eq!(stack.mld_src_on_iface(iface), Some(link_local));

    let rtnl = stack.rtnl_lock();
    let generation = stack.ifaces.control_generation_in_ns(&rtnl, iface, 0).unwrap();
    drop(rtnl);
    stack.mld_link_local_dad_complete(iface, generation.wrapping_add(1), link_local);
    assert!(lo.rx_pop().is_none());
    stack.mld_link_local_dad_complete(iface, generation, link_local);
    for _ in 0..2 { let report = lo.rx_pop().expect("fresh MLD report after DAD");
        assert_eq!(crate::ipv6::Ipv6Hdr::parse(report.data()).unwrap().src, link_local); }

    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,2]);
    let query = crate::icmpv6::build_mldv1_query(router, group, group, 1000);
    stack.deliver_rx_ipv6(iface, &ipv6_query_packet(router, group, &query, 1, true)).unwrap();
    let report = lo.rx_pop().expect("MLD query response after DAD");
    assert_eq!(crate::ipv6::Ipv6Hdr::parse(report.data()).unwrap().src, link_local);
}
