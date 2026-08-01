use super::*;

// The delivery half, split out at the per-file size cutoff.
#[path = "tests_igmp/delivery.rs"]
mod delivery;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct ToggleXmitDev { fail: AtomicBool, attempts: AtomicUsize }

impl ToggleXmitDev { fn new() -> Self { Self { fail: AtomicBool::new(false), attempts: AtomicUsize::new(0) } } }

impl crate::NetDev for ToggleXmitDev {
    fn name(&self) -> &str { "igmp-fail" }
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

fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let header_len = 24usize;
    let mut pkt = alloc::vec![0u8; header_len + payload.len()];
    let hdr = crate::ipv4::Ipv4Hdr::build(src, dst, IpProto::Igmp, payload.len() as u16, 1);
    hdr.write_to(&mut pkt[..crate::ipv4::IPV4_HDR_LEN]);
    pkt[0] = 0x46;
    pkt[2..4].copy_from_slice(&((header_len + payload.len()) as u16).to_be_bytes());
    pkt[8] = 1;
    pkt[10..12].copy_from_slice(&0u16.to_be_bytes());
    pkt[20..24].copy_from_slice(&[0x94, 0x04, 0, 0]);
    let checksum = crate::ipv4::ip_checksum(&pkt[..header_len]);
    pkt[10..12].copy_from_slice(&checksum.to_be_bytes());
    pkt[header_len..].copy_from_slice(payload);
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

fn igmp_report_body(packet: &crate::Pkt) -> &[u8] {
    let data = packet.data();
    assert_eq!(data[0], 0x46);
    assert_eq!(data[8], 1);
    assert_eq!(data[9], IpProto::Igmp as u8);
    assert_eq!(&data[20..24], &[0x94, 0x04, 0, 0]);
    assert_eq!(crate::ipv4::ip_checksum(&data[..24]), 0);
    assert_eq!(crate::ipv4::ip_checksum(&data[24..]), 0);
    &data[24..]
}

fn finish_igmp_change(stack: &NetStack, lo: &crate::LoopbackDev) {
    stack.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS);
    let _ = lo.rx_pop().expect("IGMP retransmission");
}

#[test]
fn igmp_failed_remove_does_not_publish_interface_state() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let group = Ipv4Addr::new(239, 7, 8, 8);
    assert_eq!(stack.set_ipv4_multicast_in(0, 7, iface, group, Ipv4Addr::LOOPBACK, None),
        Err(crate::NetError::Eaddrnotavail));
    assert!(!stack.v4_mcast.lock().contains_key(&iface));
}

#[test]
fn igmp_join_leave_emit_report_and_leave() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let src = Ipv4Addr::LOOPBACK;
    let group = Ipv4Addr::new(224, 1, 2, 3);

    stack.join_ipv4_multicast(id, group, src).unwrap();
    let report = lo.rx_pop().expect("IGMP report");
    assert_eq!(&report.data()[12..16], &src.octets());
    assert_eq!(&report.data()[16..20], &crate::igmp::IPV4_IGMPV3_ROUTERS.octets());
    let body = igmp_report_body(&report);
    assert_eq!(body[0], crate::igmp::IGMP_TYPE_V3_REPORT);
    assert_eq!(u16::from_be_bytes([body[6], body[7]]), 1);
    assert_eq!(body[8], crate::igmp::IGMP_V3_RECORD_CHANGE_TO_EXCLUDE);
    assert_eq!(u16::from_be_bytes([body[10], body[11]]), 0);
    assert_eq!(&body[12..16], &group.octets());
    finish_igmp_change(&stack, &lo);

    stack.leave_ipv4_multicast(id, group, src).unwrap();
    let leave = lo.rx_pop().expect("IGMP leave");
    assert_eq!(&leave.data()[16..20], &crate::igmp::IPV4_IGMPV3_ROUTERS.octets());
    let body = igmp_report_body(&leave);
    assert_eq!(body[0], crate::igmp::IGMP_TYPE_V3_REPORT);
    assert_eq!(body[8], crate::igmp::IGMP_V3_RECORD_CHANGE_TO_INCLUDE);
    assert_eq!(&body[12..16], &group.octets());
}

#[test]
fn igmp_failed_close_report_consumes_bounded_attempts() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let dev = Arc::new(ToggleXmitDev::new());
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let group = Ipv4Addr::new(239, 7, 8, 9);
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let state = crate::mcast_filter::SocketMcast::new();
    state.change_v4(&stack, iface, group, source, true).unwrap();
    stack.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS);

    dev.fail.store(true, Ordering::Release);
    assert_eq!(state.change_v4(&stack, iface, group, source, false), Ok(()));
    // The leave dropped the membership; with unconditional multicast delivery
    // cleared the socket then refuses the group.
    state.set_multicast_all_v4(false);
    assert!(!state.accept_v4(iface, group, source));
    assert!(stack.v4_mcast.lock().get(&iface).is_some_and(|groups| {
        groups.iter().any(|entry| entry.group == group && entry.change.as_ref().is_some_and(|change| {
            matches!(change.report, crate::mcast_state::V4Report::Tomb)
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
    assert!(!stack.v4_mcast.lock().get(&iface).is_some_and(|groups| {
        groups.iter().any(|entry| entry.group == group)
    }));
}

#[test]
fn igmp_successful_initial_change_retransmits_when_due() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let dev = Arc::new(ToggleXmitDev::new());
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let group = Ipv4Addr::new(239, 7, 8, 11);
    stack.join_ipv4_multicast(iface, group, Ipv4Addr::new(10, 0, 0, 1)).unwrap();
    let interval = crate::mcast_state::REPORT_INTERVAL_NS;
    assert!(stack.v4_mcast.lock().get(&iface).is_some_and(|groups| groups.iter().any(|entry| {
        entry.group == group && entry.change.as_ref().is_some_and(|change| {
            matches!(change.report, crate::mcast_state::V4Report::Active(_))
                && change.remaining == 1 && change.next_ns == interval
        })
    })));
    stack.retry_multicast_reports(interval - 1);
    assert_eq!(dev.attempts.load(Ordering::Acquire), 1);
    stack.retry_multicast_reports(interval);
    assert_eq!(dev.attempts.load(Ordering::Acquire), 2);
    assert!(stack.v4_mcast.lock().get(&iface).is_some_and(|groups| groups.iter().any(|entry| {
        entry.group == group && entry.change.is_none()
    })));
}

#[test]
fn igmp_failed_initial_report_commits_join_and_retries() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let dev = Arc::new(ToggleXmitDev::new());
    dev.fail.store(true, Ordering::Release);
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let group = Ipv4Addr::new(239, 7, 8, 13);
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let state = crate::mcast_filter::SocketMcast::new();
    assert_eq!(state.change_v4(&stack, iface, group, source, true), Ok(()));
    assert!(state.accept_v4(iface, group, source));
    assert!(stack.v4_mcast.lock().get(&iface).is_some_and(|groups| groups.iter().any(|entry| {
        entry.group == group && entry.members.len() == 1 && entry.change.as_ref().is_some_and(|change| {
            matches!(change.report, crate::mcast_state::V4Report::Active(_))
                && change.remaining == crate::mcast_state::REPORT_ROBUSTNESS - 1
                && change.next_ns == crate::mcast_state::REPORT_INTERVAL_NS
        })
    })));
    let interval = crate::mcast_state::REPORT_INTERVAL_NS;
    stack.retry_multicast_reports(interval);
    assert_eq!(dev.attempts.load(Ordering::Acquire), crate::mcast_state::REPORT_ROBUSTNESS as usize);
    assert!(state.accept_v4(iface, group, source));
    assert!(stack.v4_mcast.lock().get(&iface).is_some_and(|groups| groups.iter().any(|entry| {
        entry.group == group && entry.members.len() == 1 && entry.change.is_none()
    })));
    stack.retry_multicast_reports(interval * 2);
    assert_eq!(dev.attempts.load(Ordering::Acquire), crate::mcast_state::REPORT_ROBUSTNESS as usize);
}

#[test]
fn igmp_rejoin_supersedes_failed_close_tomb() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let dev = Arc::new(ToggleXmitDev::new());
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let group = Ipv4Addr::new(239, 7, 8, 10);
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let dead = crate::mcast_filter::SocketMcast::new();
    dead.change_v4(&stack, iface, group, source, true).unwrap();
    dev.fail.store(true, Ordering::Release);
    dead.release(&stack);

    dev.fail.store(false, Ordering::Release);
    let live = crate::mcast_filter::SocketMcast::new();
    live.change_v4(&stack, iface, group, source, true).unwrap();
    let attempts = dev.attempts.load(Ordering::Acquire);
    assert!(stack.v4_mcast.lock().get(&iface).is_some_and(|groups| groups.iter().any(|entry| {
        entry.group == group && entry.members.len() == 1 && entry.change.as_ref().is_some_and(|change| {
            matches!(change.report, crate::mcast_state::V4Report::Active(_)) && change.remaining == 1
        })
    })));
    stack.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS - 1);
    assert_eq!(dev.attempts.load(Ordering::Acquire), attempts);
}

#[test]
fn igmp_pending_changes_merge_from_original_state_and_cancel_inverse() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let dev = Arc::new(ToggleXmitDev::new());
    dev.fail.store(true, Ordering::Release);
    let iface = stack.ifaces.register(dev as Arc<dyn crate::NetDev>);
    let group = Ipv4Addr::new(232, 7, 8, 20);
    let source_a = Ipv4Addr::new(10, 0, 0, 1);
    let source_b = Ipv4Addr::new(10, 0, 0, 2);
    let state = crate::mcast_filter::SocketMcast::new();
    state.set_v4(&stack, iface, group, source_a, crate::mcast_filter::FilterMode::Include,
        &[source_a]).unwrap();
    state.set_v4(&stack, iface, group, source_a, crate::mcast_filter::FilterMode::Include,
        &[source_a, source_b]).unwrap();
    assert!(stack.v4_mcast.lock().get(&iface).is_some_and(|groups| groups.iter().any(|entry| {
        entry.change.as_ref().is_some_and(|change| change.records.len() == 1
            && change.records[0].record_type == crate::igmp::IGMP_V3_RECORD_CHANGE_TO_INCLUDE
            && change.records[0].sources == [source_a, source_b])
    })));
    state.release(&stack);
    assert!(!stack.v4_mcast.lock().get(&iface).is_some_and(|groups| {
        groups.iter().any(|entry| entry.group == group)
    }));
}

#[test]
fn igmp_general_query_reports_joined_group() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let src = Ipv4Addr::LOOPBACK;
    let router = Ipv4Addr::new(127, 0, 0, 2);
    let group = Ipv4Addr::new(224, 9, 8, 7);

    stack.join_ipv4_multicast(id, group, src).unwrap();
    let _ = lo.rx_pop().expect("initial IGMP report");
    finish_igmp_change(&stack, &lo);

    let query = crate::igmp::build_igmp_query(Ipv4Addr::ANY, 10);
    let packet = ipv4_packet(router, crate::igmp::IPV4_ALL_HOSTS, &query);
    stack.deliver_rx(id, &packet).unwrap();

    let report = lo.rx_pop().expect("query response");
    assert_eq!(&report.data()[12..16], &src.octets());
    assert_eq!(&report.data()[16..20], &group.octets());
    assert_eq!(report.data()[24], crate::igmp::IGMP_TYPE_V2_REPORT);
    assert_eq!(&report.data()[28..32], &group.octets());
    assert!(lo.rx_pop().is_none());

    stack.leave_ipv4_multicast(id, group, src).unwrap();
    let leave = lo.rx_pop().expect("IGMPv2 leave");
    assert_eq!(&leave.data()[16..20], &crate::igmp::IPV4_ALL_ROUTERS.octets());
    assert_eq!(leave.data()[24], crate::igmp::IGMP_TYPE_LEAVE);
}

#[test]
fn igmpv1_group_query_uses_v1_response_without_downgrading_interface() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let group = Ipv4Addr::new(224, 9, 8, 19);
    stack.join_ipv4_multicast(id, group, Ipv4Addr::LOOPBACK).unwrap();
    let _ = lo.rx_pop().unwrap();
    finish_igmp_change(&stack, &lo);

    let query = crate::igmp::build_igmp_query(group, 0);
    stack.deliver_rx(id, &ipv4_packet(Ipv4Addr::new(127,0,0,2), group, &query)).unwrap();
    let report = lo.rx_pop().expect("IGMPv1 report");
    assert_eq!(report.data()[24], 0x12);
    assert_eq!(&report.data()[16..20], &group.octets());
    stack.leave_ipv4_multicast(id, group, Ipv4Addr::LOOPBACK).unwrap();
    let leave = lo.rx_pop().expect("IGMPv3 state change");
    assert_eq!(leave.data()[24], crate::igmp::IGMP_TYPE_V3_REPORT);
    assert_eq!(leave.data()[32], crate::igmp::IGMP_V3_RECORD_CHANGE_TO_INCLUDE);
}

#[test]
fn igmpv3_query_updates_robustness_and_qqic() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let group = Ipv4Addr::new(239, 9, 8, 14);
    stack.join_ipv4_multicast(id, group, Ipv4Addr::LOOPBACK).unwrap();
    let _ = lo.rx_pop().expect("initial report");
    finish_igmp_change(&stack, &lo);
    let mut query = crate::igmp::build_igmpv3_query(Ipv4Addr::ANY, 10, &[]);
    query[8] = 5;
    query[9] = 0x81;
    query[2] = 0;
    query[3] = 0;
    let checksum = crate::ipv4::ip_checksum(&query);
    query[2..4].copy_from_slice(&checksum.to_be_bytes());
    let packet = ipv4_packet(Ipv4Addr::new(127, 0, 0, 2), crate::igmp::IPV4_ALL_HOSTS, &query);
    stack.deliver_rx(id, &packet).unwrap();
    let _ = lo.rx_pop().expect("query response");
    assert!(stack.v4_mcast.lock().get(&id).is_some_and(|groups| groups.iter().any(|entry| {
        entry.group == group && entry.robustness() == 5
            && entry.query_interval_ns() == 136_000_000_000
    })));
    stack.leave_ipv4_multicast(id, group, Ipv4Addr::LOOPBACK).unwrap();
    let _ = lo.rx_pop().expect("leave report");
    assert!(stack.v4_mcast.lock().get(&id).is_some_and(|groups| groups.iter().any(|entry| {
        entry.group == group && entry.change.as_ref().is_some_and(|change| change.remaining == 4)
    })));
}

#[test]
fn igmpv3_source_query_reports_sources() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let src = Ipv4Addr::LOOPBACK;
    let router = Ipv4Addr::new(127, 0, 0, 2);
    let group = Ipv4Addr::new(232, 9, 8, 7);
    let source = Ipv4Addr::new(10, 0, 0, 9);

    stack.join_ipv4_multicast(id, group, src).unwrap();
    let _ = lo.rx_pop().expect("initial IGMP report");

    let query = crate::igmp::build_igmpv3_query(group, 10, &[source]);
    let packet = ipv4_packet(router, group, &query);
    stack.deliver_rx(id, &packet).unwrap();

    let report = lo.rx_pop().expect("source query response");
    let body = igmp_report_body(&report);
    assert_eq!(body[0], crate::igmp::IGMP_TYPE_V3_REPORT);
    assert_eq!(body[8], crate::igmp::IGMP_V3_RECORD_MODE_IS_INCLUDE);
    assert_eq!(u16::from_be_bytes([body[10], body[11]]), 1);
    assert_eq!(&body[12..16], &group.octets());
    assert_eq!(&body[16..20], &source.octets());
    assert!(lo.rx_pop().is_none());
}

#[test]
fn igmp_source_membership_reports_and_queries_aggregate_policy() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let group = Ipv4Addr::new(232, 9, 8, 8);
    let source_a = Ipv4Addr::new(10, 0, 0, 10);
    let source_b = Ipv4Addr::new(10, 0, 0, 11);
    let query_source = Ipv4Addr::new(10, 0, 0, 99);
    let first = crate::mcast_filter::SocketMcast::new();
    let second = crate::mcast_filter::SocketMcast::new();

    first.source_v4(&stack, id, group, Ipv4Addr::LOOPBACK,
        source_a, crate::mcast_filter::SourceOp::Join).unwrap();
    let report = lo.rx_pop().expect("first source report");
    let body = igmp_report_body(&report);
    assert_eq!(body[8], crate::igmp::IGMP_V3_RECORD_CHANGE_TO_INCLUDE);
    assert_eq!(u16::from_be_bytes([body[10], body[11]]), 1);
    assert_eq!(&body[16..20], &source_a.octets());
    finish_igmp_change(&stack, &lo);

    second.source_v4(&stack, id, group, Ipv4Addr::LOOPBACK,
        source_b, crate::mcast_filter::SourceOp::Join).unwrap();
    let report = lo.rx_pop().expect("aggregate source report");
    let body = igmp_report_body(&report);
    assert_eq!(body[8], crate::igmp::IGMP_V3_RECORD_ALLOW_NEW_SOURCES);
    assert_eq!(u16::from_be_bytes([body[10], body[11]]), 1);
    assert_eq!(&body[16..20], &source_b.octets());

    let query = crate::igmp::build_igmpv3_query(group, 10, &[source_a, query_source]);
    let packet = ipv4_packet(Ipv4Addr::new(127, 0, 0, 2), group, &query);
    stack.deliver_rx(id, &packet).unwrap();
    let report = lo.rx_pop().expect("aggregate query response");
    let body = igmp_report_body(&report);
    assert_eq!(body[8], crate::igmp::IGMP_V3_RECORD_MODE_IS_INCLUDE);
    assert_eq!(u16::from_be_bytes([body[10], body[11]]), 1);
    assert_eq!(&body[16..20], &source_a.octets());
}

#[test]
fn igmp_same_mode_removal_blocks_and_mode_change_uses_change_to() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let group = Ipv4Addr::new(232, 9, 8, 12);
    let source_a = Ipv4Addr::new(10, 0, 0, 20);
    let source_b = Ipv4Addr::new(10, 0, 0, 21);
    let source_c = Ipv4Addr::new(10, 0, 0, 22);
    let state = crate::mcast_filter::SocketMcast::new();

    state.set_v4(&stack, id, group, Ipv4Addr::LOOPBACK,
        crate::mcast_filter::FilterMode::Include, &[source_a, source_b]).unwrap();
    let _ = lo.rx_pop().expect("initial include report");
    finish_igmp_change(&stack, &lo);
    state.set_v4(&stack, id, group, Ipv4Addr::LOOPBACK,
        crate::mcast_filter::FilterMode::Include, &[source_b, source_c]).unwrap();
    let report = lo.rx_pop().expect("two-record source delta");
    let body = igmp_report_body(&report);
    assert_eq!(u16::from_be_bytes([body[6], body[7]]), 2);
    assert_eq!(body[8], crate::igmp::IGMP_V3_RECORD_ALLOW_NEW_SOURCES);
    assert_eq!(&body[16..20], &source_c.octets());
    assert_eq!(body[20], crate::igmp::IGMP_V3_RECORD_BLOCK_OLD_SOURCES);
    assert_eq!(&body[28..32], &source_a.octets());
    finish_igmp_change(&stack, &lo);
    state.source_v4(&stack, id, group, Ipv4Addr::LOOPBACK,
        source_c, crate::mcast_filter::SourceOp::Leave).unwrap();
    let report = lo.rx_pop().expect("block old source report");
    let body = igmp_report_body(&report);
    assert_eq!(body[8], crate::igmp::IGMP_V3_RECORD_BLOCK_OLD_SOURCES);
    assert_eq!(&body[16..20], &source_c.octets());
    finish_igmp_change(&stack, &lo);

    state.set_v4(&stack, id, group, Ipv4Addr::LOOPBACK,
        crate::mcast_filter::FilterMode::Exclude, &[source_b]).unwrap();
    let report = lo.rx_pop().expect("mode-change report");
    let body = igmp_report_body(&report);
    assert_eq!(body[8], crate::igmp::IGMP_V3_RECORD_CHANGE_TO_EXCLUDE);
    assert_eq!(&body[16..20], &source_b.octets());
}
