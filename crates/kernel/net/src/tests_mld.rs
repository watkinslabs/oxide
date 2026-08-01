use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct ToggleXmitDev { fail: AtomicBool, attempts: AtomicUsize }

impl ToggleXmitDev { fn new() -> Self { Self { fail: AtomicBool::new(false), attempts: AtomicUsize::new(0) } } }

impl crate::NetDev for ToggleXmitDev {
    fn name(&self) -> &str { "mld-fail" }
    fn mac(&self) -> crate::MacAddr { crate::MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1500 }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
    fn xmit(&self, _pkt: crate::Pkt) -> crate::NetResult<()> {
        self.attempts.fetch_add(1, Ordering::AcqRel);
        if self.fail.load(Ordering::Acquire) { Err(crate::NetError::Eio) } else { Ok(()) }
    }
}

fn ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
    let extension = [IpProto::Icmpv6 as u8, 0, 5, 2, 0, 0, 1, 0];
    let mut pkt = alloc::vec![0u8; crate::ipv6::IPV6_HDR_LEN + extension.len() + payload.len()];
    let mut hdr = crate::ipv6::Ipv6Hdr::build(src, dst, IpProto::Raw,
        (extension.len() + payload.len()) as u16);
    hdr.next_header = 0;
    hdr.hop_limit = 1;
    hdr.write_to(&mut pkt[..crate::ipv6::IPV6_HDR_LEN]);
    pkt[crate::ipv6::IPV6_HDR_LEN..crate::ipv6::IPV6_HDR_LEN + extension.len()]
        .copy_from_slice(&extension);
    pkt[crate::ipv6::IPV6_HDR_LEN + extension.len()..].copy_from_slice(payload);
    pkt
}

fn mld_report_body(packet: &crate::Pkt) -> &[u8] {
    let data = packet.data();
    let hdr = crate::ipv6::Ipv6Hdr::parse(data).unwrap();
    assert_eq!(hdr.next_header, 0);
    assert_eq!(hdr.hop_limit, 1);
    assert_eq!(&data[40..48], &[58, 0, 5, 2, 0, 0, 1, 0]);
    let body = &data[48..];
    let mut pseudo = alloc::vec![0u8; 40];
    pseudo[..16].copy_from_slice(&hdr.src.0);
    pseudo[16..32].copy_from_slice(&hdr.dst.0);
    pseudo[32..36].copy_from_slice(&(body.len() as u32).to_be_bytes());
    pseudo[39] = 58;
    pseudo.extend_from_slice(body);
    assert_eq!(crate::ipv4::ip_checksum(&pseudo), 0);
    body
}

fn finish_mld_change(stack: &NetStack, lo: &crate::LoopbackDev) {
    stack.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS);
    let _ = lo.rx_pop().expect("MLD retransmission");
}

#[test]
fn mld_failed_remove_does_not_publish_interface_state() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x3343]);
    let source = Ipv6Addr::from_segments([0,0,0,0,0,0,0,1]);
    assert_eq!(stack.set_ipv6_multicast_in(0, 7, iface, group, source, None),
        Err(crate::NetError::Eaddrnotavail));
    assert!(!stack.v6_mcast.lock().contains_key(&iface));
}

#[test]
fn mld_general_query_reports_joined_group() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::icmpv6::{
        build_mldv1_query, ICMPV6_TYPE_MLD_REPORT,
    };
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let src = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,2]);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x1234]);
    stack.add_v6_addr(id, src);

    stack.join_ipv6_multicast(id, group, src).unwrap();
    let _ = lo.rx_pop().expect("initial MLD report");
    finish_mld_change(&stack, &lo);

    let query = build_mldv1_query(router, crate::ndp::IPV6_ALL_NODES, Ipv6Addr::ANY, 1000);
    let packet = ipv6_packet(router, crate::ndp::IPV6_ALL_NODES, &query);
    stack.deliver_rx_ipv6(id, &packet).unwrap();

    let report = lo.rx_pop().expect("query response");
    let hdr = crate::ipv6::Ipv6Hdr::parse(report.data()).unwrap();
    assert_eq!(hdr.src, src);
    assert_eq!(hdr.dst, group);
    let body = mld_report_body(&report);
    assert_eq!(body[0], ICMPV6_TYPE_MLD_REPORT);
    assert_eq!(&body[8..24], &group.0);
    assert!(lo.rx_pop().is_none());

    stack.leave_ipv6_multicast(id, group, src).unwrap();
    let done = lo.rx_pop().expect("MLDv1 done");
    let hdr = crate::ipv6::Ipv6Hdr::parse(done.data()).unwrap();
    assert_eq!(hdr.dst, crate::ndp::IPV6_ALL_ROUTERS);
    assert_eq!(mld_report_body(&done)[0], crate::icmpv6::ICMPV6_TYPE_MLD_DONE);
}

#[test]
fn mld_query_requires_hop_limit_one_and_router_alert() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let host = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,2]);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x1240]);
    stack.add_v6_addr(id, host);
    stack.join_ipv6_multicast(id, group, host).unwrap();
    let _ = lo.rx_pop().unwrap();
    finish_mld_change(&stack, &lo);
    let query = crate::icmpv6::build_mldv1_query(router, group, group, 1000);

    let mut bad_hop = ipv6_packet(router, group, &query);
    bad_hop[7] = 2;
    stack.deliver_rx_ipv6(id, &bad_hop).unwrap();
    assert!(lo.rx_pop().is_none());
    let mut bad_alert = ipv6_packet(router, group, &query);
    bad_alert[44] = 1;
    stack.deliver_rx_ipv6(id, &bad_alert).unwrap();
    assert!(lo.rx_pop().is_none());
}

#[test]
fn mldv2_source_query_reports_sources() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::icmpv6::{
        build_mldv2_query, ICMPV6_TYPE_MLDV2_REPORT,
    };
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let src = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,2]);
    let group = Ipv6Addr::from_segments([0xff3e,0,0,0,0,0,0,0x1234]);
    let source = Ipv6Addr::from_segments([0x2001,0xdb8,0,0,0,0,0,9]);
    stack.add_v6_addr(id, src);

    stack.join_ipv6_multicast(id, group, src).unwrap();
    let _ = lo.rx_pop().expect("initial MLD report");

    let query = build_mldv2_query(router, group, group, 1000, &[source]);
    let packet = ipv6_packet(router, group, &query);
    stack.deliver_rx_ipv6(id, &packet).unwrap();

    let report = lo.rx_pop().expect("source query response");
    let hdr = crate::ipv6::Ipv6Hdr::parse(report.data()).unwrap();
    assert_eq!(hdr.dst, crate::icmpv6::IPV6_MLDV2_ROUTERS);
    let body = mld_report_body(&report);
    assert_eq!(body[0], ICMPV6_TYPE_MLDV2_REPORT);
    assert_eq!(body[8], crate::icmpv6::MLDV2_RECORD_MODE_IS_INCLUDE);
    assert_eq!(u16::from_be_bytes([body[10], body[11]]), 1);
    assert_eq!(&body[12..28], &group.0);
    assert_eq!(&body[28..44], &source.0);
    assert!(lo.rx_pop().is_none());
}

#[test]
fn mld_source_deltas_and_mode_changes_use_correct_records() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let src = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let group = Ipv6Addr::from_segments([0xff3e,0,0,0,0,0,0,0x2235]);
    let source_a = Ipv6Addr::from_segments([0x2001,0xdb8,0,0,0,0,0,10]);
    let source_b = Ipv6Addr::from_segments([0x2001,0xdb8,0,0,0,0,0,11]);
    let source_c = Ipv6Addr::from_segments([0x2001,0xdb8,0,0,0,0,0,12]);
    let state = crate::mcast_filter::SocketMcast::new();
    stack.add_v6_addr(id, src);

    state.set_v6(&stack, id, group, src, crate::mcast_filter::FilterMode::Include,
        &[source_a]).unwrap();
    let report = lo.rx_pop().expect("initial MLD include report");
    assert_eq!(mld_report_body(&report)[8], crate::icmpv6::MLDV2_RECORD_CHANGE_TO_INCLUDE);
    finish_mld_change(&stack, &lo);
    state.source_v6(&stack, id, group, src, source_b,
        crate::mcast_filter::SourceOp::Join).unwrap();
    let report = lo.rx_pop().expect("allow new MLD source");
    let body = mld_report_body(&report);
    assert_eq!(body[8], crate::icmpv6::MLDV2_RECORD_ALLOW_NEW_SOURCES);
    assert_eq!(&body[28..44], &source_b.0);
    finish_mld_change(&stack, &lo);
    state.set_v6(&stack, id, group, src, crate::mcast_filter::FilterMode::Include,
        &[source_b, source_c]).unwrap();
    let report = lo.rx_pop().expect("two-record MLD source delta");
    let body = mld_report_body(&report);
    assert_eq!(u16::from_be_bytes([body[6], body[7]]), 2);
    assert_eq!(body[8], crate::icmpv6::MLDV2_RECORD_ALLOW_NEW_SOURCES);
    assert_eq!(&body[28..44], &source_c.0);
    assert_eq!(body[44], crate::icmpv6::MLDV2_RECORD_BLOCK_OLD_SOURCES);
    assert_eq!(&body[64..80], &source_a.0);
    finish_mld_change(&stack, &lo);
    state.source_v6(&stack, id, group, src, source_c,
        crate::mcast_filter::SourceOp::Leave).unwrap();
    let report = lo.rx_pop().expect("block old MLD source");
    let body = mld_report_body(&report);
    assert_eq!(body[8], crate::icmpv6::MLDV2_RECORD_BLOCK_OLD_SOURCES);
    assert_eq!(&body[28..44], &source_c.0);
    finish_mld_change(&stack, &lo);

    state.set_v6(&stack, id, group, src, crate::mcast_filter::FilterMode::Exclude,
        &[source_b]).unwrap();
    let report = lo.rx_pop().expect("MLD mode-change report");
    assert_eq!(mld_report_body(&report)[8], crate::icmpv6::MLDV2_RECORD_CHANGE_TO_EXCLUDE);
}

#[test]
fn ipv6_multicast_device_state_is_reference_counted() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let src = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x2234]);
    stack.add_v6_addr(id, src);
    stack.join_ipv6_multicast(id, group, src).unwrap();
    let _ = lo.rx_pop().expect("first join report");
    finish_mld_change(&stack, &lo);
    stack.join_ipv6_multicast(id, group, src).unwrap();
    assert!(lo.rx_pop().is_none());
    stack.leave_ipv6_multicast(id, group, src).unwrap();
    assert!(lo.rx_pop().is_none());
    stack.leave_ipv6_multicast(id, group, src).unwrap();
    assert!(lo.rx_pop().is_some());
}

#[test]
fn mld_failed_close_report_consumes_bounded_attempts() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let dev = Arc::new(ToggleXmitDev::new());
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let source = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x3344]);
    let state = crate::mcast_filter::SocketMcast::new();
    state.change_v6(&stack, iface, group, source, true).unwrap();
    stack.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS);

    dev.fail.store(true, Ordering::Release);
    assert_eq!(state.change_v6(&stack, iface, group, source, false), Ok(()));
    // The leave dropped the membership; with unconditional multicast delivery
    // cleared the socket then refuses the group.
    state.set_multicast_all_v6(false);
    assert!(!state.accept_v6(iface, group, source));
    assert!(stack.v6_mcast.lock().get(&iface).is_some_and(|groups| {
        groups.iter().any(|current| current.group == group && current.members.is_empty()
            && current.change.as_ref().is_some_and(|change| {
                matches!(change.report, crate::mcast_state::V6Report::Tomb)
                    && change.remaining == crate::mcast_state::REPORT_ROBUSTNESS - 1
                    && change.next_ns == crate::mcast_state::REPORT_INTERVAL_NS
            }))
    }));

    let interval = crate::mcast_state::REPORT_INTERVAL_NS;
    let attempts = dev.attempts.load(Ordering::Acquire);
    stack.retry_multicast_reports(interval - 1);
    assert_eq!(dev.attempts.load(Ordering::Acquire), attempts);
    stack.retry_multicast_reports(interval);
    assert_eq!(dev.attempts.load(Ordering::Acquire), attempts + 1);
    stack.retry_multicast_reports(interval * 2);
    assert_eq!(dev.attempts.load(Ordering::Acquire), attempts + 1);
    assert!(!stack.v6_mcast.lock().get(&iface).is_some_and(|groups| {
        groups.iter().any(|current| current.group == group)
    }));
}

#[test]
fn mld_successful_initial_change_retransmits_when_due() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let dev = Arc::new(ToggleXmitDev::new());
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let source = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x3346]);
    stack.join_ipv6_multicast(iface, group, source).unwrap();
    let interval = crate::mcast_state::REPORT_INTERVAL_NS;
    assert!(stack.v6_mcast.lock().get(&iface).is_some_and(|groups| groups.iter().any(|entry| {
        entry.group == group && entry.change.as_ref().is_some_and(|change| {
            matches!(change.report, crate::mcast_state::V6Report::Active(_))
                && change.remaining == 1 && change.next_ns == interval
        })
    })));
    stack.retry_multicast_reports(interval - 1);
    assert_eq!(dev.attempts.load(Ordering::Acquire), 1);
    stack.retry_multicast_reports(interval);
    assert_eq!(dev.attempts.load(Ordering::Acquire), 2);
    assert!(stack.v6_mcast.lock().get(&iface).is_some_and(|groups| groups.iter().any(|entry| {
        entry.group == group && entry.change.is_none()
    })));
}

#[test]
fn mld_failed_initial_report_commits_join_and_retries() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let dev = Arc::new(ToggleXmitDev::new());
    dev.fail.store(true, Ordering::Release);
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let source = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x3347]);
    let state = crate::mcast_filter::SocketMcast::new();
    assert_eq!(state.change_v6(&stack, iface, group, source, true), Ok(()));
    assert!(state.accept_v6(iface, group, source));
    assert!(stack.v6_mcast.lock().get(&iface).is_some_and(|groups| groups.iter().any(|entry| {
        entry.group == group && entry.members.len() == 1 && entry.change.as_ref().is_some_and(|change| {
            matches!(change.report, crate::mcast_state::V6Report::Active(_))
                && change.remaining == crate::mcast_state::REPORT_ROBUSTNESS - 1
                && change.next_ns == crate::mcast_state::REPORT_INTERVAL_NS
        })
    })));
    let interval = crate::mcast_state::REPORT_INTERVAL_NS;
    stack.retry_multicast_reports(interval);
    assert_eq!(dev.attempts.load(Ordering::Acquire), crate::mcast_state::REPORT_ROBUSTNESS as usize);
    assert!(state.accept_v6(iface, group, source));
    assert!(stack.v6_mcast.lock().get(&iface).is_some_and(|groups| groups.iter().any(|entry| {
        entry.group == group && entry.members.len() == 1 && entry.change.is_none()
    })));
    stack.retry_multicast_reports(interval * 2);
    assert_eq!(dev.attempts.load(Ordering::Acquire), crate::mcast_state::REPORT_ROBUSTNESS as usize);
}

#[test]
fn mld_rejoin_supersedes_failed_close_tomb() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let dev = Arc::new(ToggleXmitDev::new());
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let source = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x3345]);
    let dead = crate::mcast_filter::SocketMcast::new();
    dead.change_v6(&stack, iface, group, source, true).unwrap();
    dev.fail.store(true, Ordering::Release);
    dead.release(&stack);

    dev.fail.store(false, Ordering::Release);
    let live = crate::mcast_filter::SocketMcast::new();
    live.change_v6(&stack, iface, group, source, true).unwrap();
    let attempts = dev.attempts.load(Ordering::Acquire);
    assert!(stack.v6_mcast.lock().get(&iface).is_some_and(|groups| groups.iter().any(|entry| {
        entry.group == group && entry.members.len() == 1 && entry.change.as_ref().is_some_and(|change| {
            matches!(change.report, crate::mcast_state::V6Report::Active(_)) && change.remaining == 1
        })
    })));
    stack.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS - 1);
    assert_eq!(dev.attempts.load(Ordering::Acquire), attempts);
}

#[test]
fn mld_pending_change_keeps_original_membership_baseline() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let dev = Arc::new(ToggleXmitDev::new());
    dev.fail.store(true, Ordering::Release);
    let iface = stack.ifaces.register(dev as Arc<dyn crate::NetDev>);
    let host = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let group = Ipv6Addr::from_segments([0xff3e,0,0,0,0,0,0,0x3348]);
    let a = Ipv6Addr::from_segments([0x2001,0xdb8,0,0,0,0,0,1]);
    let b = Ipv6Addr::from_segments([0x2001,0xdb8,0,0,0,0,0,2]);
    let state = crate::mcast_filter::SocketMcast::new();
    state.set_v6(&stack, iface, group, host, crate::mcast_filter::FilterMode::Include, &[a]).unwrap();
    state.set_v6(&stack, iface, group, host, crate::mcast_filter::FilterMode::Include, &[a,b]).unwrap();
    assert!(stack.v6_mcast.lock().get(&iface).is_some_and(|groups| groups.iter().any(|entry| {
        entry.change.as_ref().is_some_and(|change| change.records.len() == 1
            && change.records[0].record_type == crate::icmpv6::MLDV2_RECORD_CHANGE_TO_INCLUDE
            && change.records[0].sources == [a,b])
    })));
}
