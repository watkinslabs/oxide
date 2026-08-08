use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct FailingXmitDev {
    fail: AtomicBool,
    attempts: AtomicUsize,
}

impl FailingXmitDev {
    fn new() -> Self {
        Self { fail: AtomicBool::new(false), attempts: AtomicUsize::new(0) }
    }
}

impl crate::NetDev for FailingXmitDev {
    fn name(&self) -> &str { "mcast-qrv" }
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

fn ipv4_query_packet(src: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let header_len = 24usize;
    let mut pkt = alloc::vec![0u8; header_len + payload.len()];
    let hdr = crate::ipv4::Ipv4Hdr::build(
        src, crate::igmp::IPV4_ALL_HOSTS, IpProto::Igmp, payload.len() as u16, 1,
    );
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

fn ipv6_query_packet(src: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
    let dst = crate::ndp::IPV6_ALL_NODES;
    let extension = [IpProto::Icmpv6 as u8, 0, 5, 2, 0, 0, 1, 0];
    let mut pkt = alloc::vec![0u8; crate::ipv6::IPV6_HDR_LEN + extension.len() + payload.len()];
    let mut hdr = crate::ipv6::Ipv6Hdr::build(
        src, dst, IpProto::Raw, (extension.len() + payload.len()) as u16,
    );
    hdr.next_header = 0;
    hdr.hop_limit = 1;
    hdr.write_to(&mut pkt[..crate::ipv6::IPV6_HDR_LEN]);
    pkt[crate::ipv6::IPV6_HDR_LEN..crate::ipv6::IPV6_HDR_LEN + extension.len()]
        .copy_from_slice(&extension);
    pkt[crate::ipv6::IPV6_HDR_LEN + extension.len()..].copy_from_slice(payload);
    pkt
}

fn set_mld_qrv(query: &mut [u8], src: Ipv6Addr, qrv: u8) {
    let dst = crate::ndp::IPV6_ALL_NODES;
    query[24] = qrv & 0x07;
    query[2..4].copy_from_slice(&0u16.to_be_bytes());
    let mut pseudo = alloc::vec![0u8; 40];
    pseudo[..16].copy_from_slice(&src.0);
    pseudo[16..32].copy_from_slice(&dst.0);
    pseudo[32..36].copy_from_slice(&(query.len() as u32).to_be_bytes());
    pseudo[39] = IpProto::Icmpv6 as u8;
    pseudo.extend_from_slice(query);
    let checksum = crate::ipv4::ip_checksum(&pseudo);
    query[2..4].copy_from_slice(&checksum.to_be_bytes());
}

#[test]
fn learned_igmp_qrv_bounds_persistent_failed_change_transmissions() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    const QRV: usize = 5;
    let stack = NetStack::new();
    let dev = Arc::new(FailingXmitDev::new());
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let router = Ipv4Addr::new(10, 0, 0, 2);
    let group = Ipv4Addr::new(239, 7, 8, 50);

    stack.join_ipv4_multicast(iface, group, source).unwrap();
    stack.retry_multicast_reports(u64::MAX);
    let mut query = crate::igmp::build_igmpv3_query(Ipv4Addr::ANY, 10, &[]);
    query[8] = QRV as u8;
    query[2..4].copy_from_slice(&0u16.to_be_bytes());
    let checksum = crate::ipv4::ip_checksum(&query);
    query[2..4].copy_from_slice(&checksum.to_be_bytes());
    stack.deliver_rx(iface, &ipv4_query_packet(router, &query)).unwrap();
    assert!(stack.v4_mcast.lock()[&iface].iter().any(|state| {
        state.group == group && state.robustness() == QRV as u8
    }));

    let before = dev.attempts.load(Ordering::Acquire);
    dev.fail.store(true, Ordering::Release);
    stack.leave_ipv4_multicast(iface, group, source).unwrap();
    for _ in 1..QRV { stack.retry_multicast_reports(u64::MAX); }
    assert_eq!(dev.attempts.load(Ordering::Acquire) - before, QRV);
    assert!(!stack.v4_mcast.lock().get(&iface).is_some_and(|groups| {
        groups.iter().any(|state| state.group == group)
    }));
    stack.retry_multicast_reports(u64::MAX);
    stack.retry_multicast_reports(u64::MAX);
    assert_eq!(dev.attempts.load(Ordering::Acquire) - before, QRV);
}

#[test]
fn learned_mld_qrv_bounds_persistent_failed_change_transmissions() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    const QRV: usize = 6;
    let stack = NetStack::new();
    let dev = Arc::new(FailingXmitDev::new());
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let source = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,2]);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x3350]);

    stack.add_v6_addr(iface, source);
    stack.join_ipv6_multicast(iface, group, source).unwrap();
    stack.retry_multicast_reports(u64::MAX);
    let mut query = crate::icmpv6::build_mldv2_query(
        router, crate::ndp::IPV6_ALL_NODES, Ipv6Addr::ANY, 1000, &[],
    );
    set_mld_qrv(&mut query, router, QRV as u8);
    stack.deliver_rx_ipv6(iface, &ipv6_query_packet(router, &query)).unwrap();
    assert!(stack.v6_mcast.lock()[&iface].iter().any(|state| {
        state.group == group && state.robustness() == QRV as u8
    }));

    let before = dev.attempts.load(Ordering::Acquire);
    dev.fail.store(true, Ordering::Release);
    stack.leave_ipv6_multicast(iface, group, source).unwrap();
    for _ in 1..QRV { stack.retry_multicast_reports(u64::MAX); }
    assert_eq!(dev.attempts.load(Ordering::Acquire) - before, QRV);
    assert!(!stack.v6_mcast.lock().get(&iface).is_some_and(|groups| {
        groups.iter().any(|state| state.group == group)
    }));
    stack.retry_multicast_reports(u64::MAX);
    stack.retry_multicast_reports(u64::MAX);
    assert_eq!(dev.attempts.load(Ordering::Acquire) - before, QRV);
}
