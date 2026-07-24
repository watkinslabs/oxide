use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, Ordering};

use sync::{Socket as StackLockClass, Spinlock};

use crate::{Ipv4Addr, Ipv6Addr, NetError, NetIfaceId, NetStack, SocketError, UdpRxQueue};
use crate::stack_ipv6::Udp6RxQueue;

const PORT: u16 = 42_000;
const UID: u32 = 1_000;
const OTHER_UID: u32 = 1_001;
const IFACE_A: NetIfaceId = NetIfaceId::from_raw(11);
const IFACE_B: NetIfaceId = NetIfaceId::from_raw(12);
const V4_A: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const V4_B: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const V4_SRC: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const V6_A: Ipv6Addr = Ipv6Addr::from_segments([0x2001, 0xdb8, 1, 0, 0, 0, 0, 1]);
const V6_B: Ipv6Addr = Ipv6Addr::from_segments([0x2001, 0xdb8, 1, 0, 0, 0, 0, 2]);
const V6_SRC: Ipv6Addr = Ipv6Addr::from_segments([0x2001, 0xdb8, 2, 0, 0, 0, 0, 1]);

fn flag(enabled: bool) -> Arc<AtomicI32> { Arc::new(AtomicI32::new(i32::from(enabled))) }
fn mcast() -> Arc<crate::mcast_filter::SocketMcast> {
    Arc::new(crate::mcast_filter::SocketMcast::new())
}

fn bind4(stack: &NetStack, ip: Ipv4Addr, iface: Option<NetIfaceId>, reuseaddr: bool,
         reuseport: bool, uid: u32, peer: Option<(Ipv4Addr, u16)>)
    -> Result<Arc<UdpRxQueue>, NetError>
{
    stack.bind_udp_socket(
        ip, PORT, iface, Arc::new(SocketError::new()), flag(reuseaddr), flag(reuseport),
        Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)), uid,
        Arc::new(Spinlock::<_, StackLockClass>::new(peer)),
        Arc::new(crate::bpf_filter::SocketFilter::new()), mcast(),
    )
}

fn bind6(stack: &NetStack, ip: Ipv6Addr, iface: Option<NetIfaceId>, reuseaddr: bool,
         reuseport: bool, uid: u32, peer: Option<(Ipv6Addr, u16)>)
    -> Result<Arc<Udp6RxQueue>, NetError>
{
    bind6_mode(stack, ip, iface, reuseaddr, reuseport, uid, false, peer)
}

fn bind6_mode(stack: &NetStack, ip: Ipv6Addr, iface: Option<NetIfaceId>, reuseaddr: bool,
              reuseport: bool, uid: u32, v6only: bool, peer: Option<(Ipv6Addr, u16)>)
    -> Result<Arc<Udp6RxQueue>, NetError>
{
    stack.bind_udp6_socket(
        ip, PORT, iface, Arc::new(SocketError::new()), flag(reuseaddr), flag(reuseport), uid,
        flag(v6only),
        Arc::new(Spinlock::<_, StackLockClass>::new(peer)),
        Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
        Arc::new(AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)),
        Arc::new(crate::bpf_filter::SocketFilter::new()), mcast(),
    )
}

fn assert_only4(actual: &[Arc<UdpRxQueue>], expected: &Arc<UdpRxQueue>) {
    assert_eq!(actual.len(), 1);
    assert!(Arc::ptr_eq(&actual[0], expected));
}

fn assert_only6(actual: &[Arc<Udp6RxQueue>], expected: &Arc<Udp6RxQueue>) {
    assert_eq!(actual.len(), 1);
    assert!(Arc::ptr_eq(&actual[0], expected));
}

#[test]
fn udp6_endpoint_shares_distinct_inet_socket_pmtudisc_modes() {
    let stack = NetStack::new();
    let sock = crate::sock::InetSocket::new_udp6();
    sock.opts.ip_mtu_discover.store(crate::uapi::IP_PMTUDISC_DONT, Ordering::Release);
    sock.opts.ipv6_mtu_discover.store(crate::uapi::IPV6_PMTUDISC_DO, Ordering::Release);
    let endpoint = stack.bind_udp6_socket(
        V6_A, PORT, None, sock.error.clone(), sock.opts.reuseaddr.clone(),
        sock.opts.reuseport.clone(), sock.owner_uid, sock.opts.ipv6_v6only.clone(),
        sock.peer6.clone(), sock.opts.ip_mtu_discover.clone(),
        sock.opts.ipv6_mtu_discover.clone(), sock.bpf_filter.clone(), sock.mcast.clone(),
    ).unwrap();
    assert!(Arc::ptr_eq(&endpoint.ip_mtu_discover, &sock.opts.ip_mtu_discover));
    assert!(Arc::ptr_eq(&endpoint.ipv6_mtu_discover, &sock.opts.ipv6_mtu_discover));
    endpoint.ip_mtu_discover.store(crate::uapi::IP_PMTUDISC_PROBE, Ordering::Release);
    assert_eq!(sock.opts.ip_mtu_discover.load(Ordering::Acquire), crate::uapi::IP_PMTUDISC_PROBE);
    assert_eq!(endpoint.ipv6_mtu_discover.load(Ordering::Acquire), crate::uapi::IPV6_PMTUDISC_DO);
}

#[test]
fn ipv4_bind_overlap_and_reuse_rules() {
    let stack = NetStack::new();
    bind4(&stack, V4_A, None, false, false, UID, None).unwrap();
    assert_eq!(bind4(&stack, V4_A, None, false, false, UID, None).err(), Some(NetError::Eaddrinuse));

    let stack = NetStack::new();
    bind4(&stack, Ipv4Addr::ANY, None, false, false, UID, None).unwrap();
    assert_eq!(bind4(&stack, V4_A, None, false, false, UID, None).err(), Some(NetError::Eaddrinuse));

    let stack = NetStack::new();
    bind4(&stack, V4_A, None, false, false, UID, None).unwrap();
    assert!(bind4(&stack, V4_B, None, false, false, UID, None).is_ok());

    let stack = NetStack::new();
    bind4(&stack, V4_A, Some(IFACE_A), false, false, UID, None).unwrap();
    assert!(bind4(&stack, V4_A, Some(IFACE_B), false, false, UID, None).is_ok());

    let stack = NetStack::new();
    bind4(&stack, V4_A, None, true, false, UID, None).unwrap();
    assert_eq!(bind4(&stack, V4_A, None, false, false, UID, None).err(), Some(NetError::Eaddrinuse));
    assert!(bind4(&stack, V4_A, None, true, false, UID, None).is_ok());

    let stack = NetStack::new();
    bind4(&stack, V4_A, None, false, true, UID, None).unwrap();
    assert_eq!(bind4(&stack, V4_A, None, false, true, OTHER_UID, None).err(), Some(NetError::Eaddrinuse));
    assert!(bind4(&stack, V4_A, None, false, true, UID, None).is_ok());
}

#[test]
fn ipv6_bind_overlap_and_reuse_rules() {
    let stack = NetStack::new();
    bind6(&stack, V6_A, None, false, false, UID, None).unwrap();
    assert_eq!(bind6(&stack, V6_A, None, false, false, UID, None).err(), Some(NetError::Eaddrinuse));

    let stack = NetStack::new();
    bind6(&stack, Ipv6Addr::ANY, None, false, false, UID, None).unwrap();
    assert_eq!(bind6(&stack, V6_A, None, false, false, UID, None).err(), Some(NetError::Eaddrinuse));

    let stack = NetStack::new();
    bind6(&stack, V6_A, None, false, false, UID, None).unwrap();
    assert!(bind6(&stack, V6_B, None, false, false, UID, None).is_ok());

    let stack = NetStack::new();
    bind6(&stack, V6_A, Some(IFACE_A), false, false, UID, None).unwrap();
    assert!(bind6(&stack, V6_A, Some(IFACE_B), false, false, UID, None).is_ok());

    let stack = NetStack::new();
    bind6(&stack, V6_A, None, true, false, UID, None).unwrap();
    assert_eq!(bind6(&stack, V6_A, None, false, false, UID, None).err(), Some(NetError::Eaddrinuse));
    assert!(bind6(&stack, V6_A, None, true, false, UID, None).is_ok());

    let stack = NetStack::new();
    bind6(&stack, V6_A, None, false, true, UID, None).unwrap();
    assert_eq!(bind6(&stack, V6_A, None, false, true, OTHER_UID, None).err(), Some(NetError::Eaddrinuse));
    assert!(bind6(&stack, V6_A, None, false, true, UID, None).is_ok());
}

#[test]
fn dual_stack_wildcard_bind_overlap_honors_v6only_and_reuse() {
    let stack = NetStack::new();
    bind4(&stack, Ipv4Addr::ANY, None, false, false, UID, None).unwrap();
    assert_eq!(
        bind6(&stack, Ipv6Addr::ANY, None, false, false, UID, None).err(),
        Some(NetError::Eaddrinuse),
    );
    assert!(bind6_mode(&stack, Ipv6Addr::ANY, None, false, false, UID, true, None).is_ok());

    let stack = NetStack::new();
    bind6(&stack, Ipv6Addr::ANY, None, false, false, UID, None).unwrap();
    assert_eq!(
        bind4(&stack, Ipv4Addr::ANY, None, false, false, UID, None).err(),
        Some(NetError::Eaddrinuse),
    );

    let stack = NetStack::new();
    bind4(&stack, Ipv4Addr::ANY, None, false, true, UID, None).unwrap();
    assert!(bind6(&stack, Ipv6Addr::ANY, None, false, true, UID, None).is_ok());

    let stack = NetStack::new();
    bind4(&stack, Ipv4Addr::ANY, None, true, false, UID, None).unwrap();
    assert!(bind6(&stack, Ipv6Addr::ANY, None, true, false, OTHER_UID, None).is_ok());
}

#[test]
fn mapped_ipv6_bind_conflicts_with_equivalent_ipv4_endpoint() {
    let stack = NetStack::new();
    bind4(&stack, V4_A, None, false, false, UID, None).unwrap();
    assert_eq!(
        bind6(&stack, Ipv6Addr::from_v4_mapped(V4_A), None, false, false, UID, None).err(),
        Some(NetError::Eaddrinuse),
    );

    let stack = NetStack::new();
    bind6(&stack, Ipv6Addr::from_v4_mapped(V4_A), None, false, false, UID, None).unwrap();
    assert_eq!(
        bind4(&stack, V4_A, None, false, false, UID, None).err(),
        Some(NetError::Eaddrinuse),
    );
}

#[test]
fn ipv4_endpoint_wins_once_over_reused_dual_stack_wildcard() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, loopback) = stack.register_loopback();
    let v4 = stack.bind_udp_socket(
        Ipv4Addr::LOOPBACK, PORT, None, Arc::new(SocketError::new()),
        flag(false), flag(true), Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
        UID, Arc::new(Spinlock::new(None)),
        Arc::new(crate::bpf_filter::SocketFilter::new()), mcast(),
    ).unwrap();
    let dual = stack.bind_udp6_socket(
        Ipv6Addr::ANY, PORT, None, Arc::new(SocketError::new()),
        flag(false), flag(true), UID, flag(false), Arc::new(Spinlock::new(None)),
        Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
        Arc::new(AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)),
        Arc::new(crate::bpf_filter::SocketFilter::new()), mcast(),
    ).unwrap();

    stack.send_udp_to(
        Ipv4Addr::LOOPBACK, 9_001, Ipv4Addr::LOOPBACK, PORT, b"one",
    ).unwrap();
    stack.drain_loopback(iface, &loopback);

    assert_eq!(v4.queued_len(), 1);
    assert_eq!(dual.queued_len(), 0);
}

#[test]
fn ipv4_demux_prefers_connected_then_exact_address_then_device() {
    let stack = NetStack::new();
    let wildcard = bind4(&stack, Ipv4Addr::ANY, None, true, false, UID, None).unwrap();
    let exact = bind4(&stack, V4_A, None, true, false, UID, None).unwrap();
    let device = bind4(&stack, V4_A, Some(IFACE_A), true, false, UID, None).unwrap();
    let connected = bind4(&stack, Ipv4Addr::ANY, None, true, false, UID, Some((V4_SRC, 9_000))).unwrap();

    assert_only4(&stack.udp_demux(V4_SRC, 9_000, V4_A, PORT, IFACE_A), &connected);
    assert_only4(&stack.udp_demux(V4_SRC, 9_001, V4_A, PORT, IFACE_A), &device);
    assert_only4(&stack.udp_demux(V4_SRC, 9_001, V4_A, PORT, IFACE_B), &exact);
    assert_only4(&stack.udp_demux(V4_SRC, 9_001, V4_B, PORT, IFACE_B), &wildcard);
}

#[test]
fn ipv6_demux_prefers_connected_then_exact_address_then_device() {
    let stack = NetStack::new();
    let wildcard = bind6(&stack, Ipv6Addr::ANY, None, true, false, UID, None).unwrap();
    let exact = bind6(&stack, V6_A, None, true, false, UID, None).unwrap();
    let device = bind6(&stack, V6_A, Some(IFACE_A), true, false, UID, None).unwrap();
    let connected = bind6(&stack, Ipv6Addr::ANY, None, true, false, UID, Some((V6_SRC, 9_000))).unwrap();

    assert_only6(&stack.udp6_demux(V6_SRC, 9_000, V6_A, PORT, IFACE_A), &connected);
    assert_only6(&stack.udp6_demux(V6_SRC, 9_001, V6_A, PORT, IFACE_A), &device);
    assert_only6(&stack.udp6_demux(V6_SRC, 9_001, V6_A, PORT, IFACE_B), &exact);
    assert_only6(&stack.udp6_demux(V6_SRC, 9_001, V6_B, PORT, IFACE_B), &wildcard);
}

#[test]
fn reuseaddr_ipv4_selection_is_not_flow_hashed() {
    let stack = NetStack::new();
    bind4(&stack, V4_A, None, true, false, UID, None).unwrap();
    bind4(&stack, V4_A, None, true, false, UID, None).unwrap();
    let newest = bind4(&stack, V4_A, None, true, false, UID, None).unwrap();

    for sport in 10_000..10_064 {
        assert_only4(&stack.udp_demux(V4_SRC, sport, V4_A, PORT, IFACE_A), &newest);
    }
}

#[test]
fn reuseaddr_ipv6_selection_is_not_flow_hashed() {
    let stack = NetStack::new();
    bind6(&stack, V6_A, None, true, false, UID, None).unwrap();
    bind6(&stack, V6_A, None, true, false, UID, None).unwrap();
    let newest = bind6(&stack, V6_A, None, true, false, UID, None).unwrap();

    for sport in 10_000..10_064 {
        assert_only6(&stack.udp6_demux(V6_SRC, sport, V6_A, PORT, IFACE_A), &newest);
    }
}

#[test]
fn ipv4_reuseport_hash_never_crosses_reuseaddr_owner_groups() {
    let stack = NetStack::new();
    let older = [
        bind4(&stack, V4_A, None, true, true, UID, None).unwrap(),
        bind4(&stack, V4_A, None, true, true, UID, None).unwrap(),
    ];
    let newer = [
        bind4(&stack, V4_A, None, true, true, OTHER_UID, None).unwrap(),
        bind4(&stack, V4_A, None, true, true, OTHER_UID, None).unwrap(),
    ];
    for sport in 10_000..10_128 {
        let selected = stack.udp_demux(V4_SRC, sport, V4_A, PORT, IFACE_A);
        assert_eq!(selected.len(), 1);
        assert!(newer.iter().any(|endpoint| Arc::ptr_eq(endpoint, &selected[0])));
        assert!(!older.iter().any(|endpoint| Arc::ptr_eq(endpoint, &selected[0])));
    }
}

#[test]
fn ipv6_reuseport_hash_never_crosses_reuseaddr_owner_groups() {
    let stack = NetStack::new();
    let older = [
        bind6(&stack, V6_A, None, true, true, UID, None).unwrap(),
        bind6(&stack, V6_A, None, true, true, UID, None).unwrap(),
    ];
    let newer = [
        bind6(&stack, V6_A, None, true, true, OTHER_UID, None).unwrap(),
        bind6(&stack, V6_A, None, true, true, OTHER_UID, None).unwrap(),
    ];
    for sport in 10_000..10_128 {
        let selected = stack.udp6_demux(V6_SRC, sport, V6_A, PORT, IFACE_A);
        assert_eq!(selected.len(), 1);
        assert!(newer.iter().any(|endpoint| Arc::ptr_eq(endpoint, &selected[0])));
        assert!(!older.iter().any(|endpoint| Arc::ptr_eq(endpoint, &selected[0])));
    }
}

#[test]
fn udp4_unbind_linearizes_payload_and_error_delivery() {
    let stack = NetStack::new();
    let endpoint = bind4(&stack, V4_A, None, false, false, UID, None).unwrap();
    let stale = stack.udp_demux(V4_SRC, 9_000, V4_A, PORT, IFACE_A).pop().unwrap();
    assert!(stale.enqueue((V4_SRC, 9_000, V4_A, IFACE_A, 64, alloc::vec![1])));
    stack.unbind_udp_endpoint(&endpoint);
    assert_eq!(stale.queued_len(), 1);
    assert!(!stale.enqueue((V4_SRC, 9_000, V4_A, IFACE_A, 64, alloc::vec![2])));

    stale.error.set_recverr4(true);
    let entry = crate::SocketErrorEntry {
        errno: syscall::errno::Errno::Econnrefused as i32,
        origin: crate::socket_error::SO_EE_ORIGIN_ICMP, kind: 3, code: 3,
        info: 0, data: 0, offender: crate::IpAddr::V4(V4_SRC),
        destination: crate::IpAddr::V4(V4_A), destination_port: PORT,
        ifindex: IFACE_A.raw(), payload: alloc::vec![],
    };
    assert!(!stale.publish_error(entry, true));
    assert!(!stale.error.has());
    assert!(!stale.error.has_extended());
}

#[test]
fn udp6_unbind_linearizes_native_and_mapped_delivery() {
    let stack = NetStack::new();
    let endpoint = bind6(&stack, V6_A, None, false, false, UID, None).unwrap();
    let stale = stack.udp6_demux(V6_SRC, 9_000, V6_A, PORT, IFACE_A).pop().unwrap();
    stack.unbind_udp6_endpoint(&endpoint);
    assert!(!stale.enqueue((V6_SRC, 9_000, V6_A, IFACE_A, 64, 0, alloc::vec![1])));
    assert!(!stale.set_error(syscall::errno::Errno::Econnrefused as i32));
    assert!(!stale.error.has());

    let endpoint = bind6(&stack, Ipv6Addr::ANY, None, false, false, UID, None).unwrap();
    let mapped = stack.udp6_demux_v4(V4_SRC, 9_001, V4_A, PORT, IFACE_A).pop().unwrap();
    stack.unbind_udp6_endpoint(&endpoint);
    assert!(!mapped.enqueue((
        Ipv6Addr::from_v4_mapped(V4_SRC), 9_001, Ipv6Addr::from_v4_mapped(V4_A),
        IFACE_A, 64, 0, alloc::vec![2],
    )));
    assert_eq!(mapped.queued_len(), 0);
}

#[test]
fn concurrent_udp4_delivery_linearizes_once_against_unbind() {
    use std::sync::Barrier;
    use std::thread;
    for _ in 0..256 {
        let stack = Arc::new(NetStack::new());
        let endpoint = bind4(&stack, V4_A, None, false, false, UID, None).unwrap();
        let stale = stack.udp_demux(V4_SRC, 9_000, V4_A, PORT, IFACE_A).pop().unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let deliver_barrier = barrier.clone();
        let deliver = stale.clone();
        let sender = thread::spawn(move || {
            deliver_barrier.wait();
            deliver.enqueue((V4_SRC, 9_000, V4_A, IFACE_A, 64, alloc::vec![1]))
        });
        let close_barrier = barrier.clone();
        let close_stack = stack.clone();
        let close_endpoint = endpoint.clone();
        let closer = thread::spawn(move || {
            close_barrier.wait();
            close_stack.unbind_udp_endpoint(&close_endpoint);
        });
        let accepted = sender.join().unwrap();
        closer.join().unwrap();
        assert_eq!(stale.queued_len(), usize::from(accepted));
        assert!(!stale.enqueue((V4_SRC, 9_000, V4_A, IFACE_A, 64, alloc::vec![2])));
    }
}

#[test]
fn reuseport_ipv4_selection_is_stable_per_flow() {
    let stack = NetStack::new();
    let endpoints = [
        bind4(&stack, V4_A, None, false, true, UID, None).unwrap(),
        bind4(&stack, V4_A, None, false, true, UID, None).unwrap(),
        bind4(&stack, V4_A, None, false, true, UID, None).unwrap(),
    ];
    let selected = stack.udp_demux(V4_SRC, 12_345, V4_A, PORT, IFACE_A);
    for _ in 0..32 {
        let again = stack.udp_demux(V4_SRC, 12_345, V4_A, PORT, IFACE_A);
        assert!(Arc::ptr_eq(&selected[0], &again[0]));
    }
    assert!(endpoints.iter().all(|endpoint| {
        (10_000..10_064).any(|sport| Arc::ptr_eq(endpoint, &stack.udp_demux(V4_SRC, sport, V4_A, PORT, IFACE_A)[0]))
    }));
}

#[test]
fn reuseport_ipv6_selection_is_stable_per_flow() {
    let stack = NetStack::new();
    let endpoints = [
        bind6(&stack, V6_A, None, false, true, UID, None).unwrap(),
        bind6(&stack, V6_A, None, false, true, UID, None).unwrap(),
        bind6(&stack, V6_A, None, false, true, UID, None).unwrap(),
    ];
    let selected = stack.udp6_demux(V6_SRC, 12_345, V6_A, PORT, IFACE_A);
    for _ in 0..32 {
        let again = stack.udp6_demux(V6_SRC, 12_345, V6_A, PORT, IFACE_A);
        assert!(Arc::ptr_eq(&selected[0], &again[0]));
    }
    assert!(endpoints.iter().all(|endpoint| {
        (10_000..10_064).any(|sport| Arc::ptr_eq(endpoint, &stack.udp6_demux(V6_SRC, sport, V6_A, PORT, IFACE_A)[0]))
    }));
}

#[test]
fn reuseport_membership_is_frozen_at_bind_for_ipv4_and_ipv6() {
    let stack = NetStack::new();
    let v4_flag = flag(true);
    let first4 = stack.bind_udp_socket(
        V4_A, PORT, None, Arc::new(SocketError::new()), flag(false), v4_flag.clone(),
        Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)), UID,
        Arc::new(Spinlock::new(None)), Arc::new(crate::bpf_filter::SocketFilter::new()), mcast(),
    ).unwrap();
    v4_flag.store(0, Ordering::Release);
    let second4 = bind4(&stack, V4_A, None, false, true, UID, None).unwrap();
    assert!(first4.reuseport_member());
    assert!(second4.reuseport_member());

    let stack = NetStack::new();
    let v6_flag = flag(false);
    let first6 = stack.bind_udp6_socket(
        V6_A, PORT, None, Arc::new(SocketError::new()), flag(false), v6_flag.clone(), UID,
        flag(false), Arc::new(Spinlock::new(None)),
        Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
        Arc::new(AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)),
        Arc::new(crate::bpf_filter::SocketFilter::new()), mcast(),
    ).unwrap();
    v6_flag.store(1, Ordering::Release);
    assert!(!first6.reuseport_member());
    assert_eq!(bind6(&stack, V6_A, None, false, true, UID, None).err(), Some(NetError::Eaddrinuse));
}

#[test]
fn ipv6_native_reuseport_hash_keeps_v6only_groups_separate() {
    let stack = NetStack::new();
    let dual = [
        bind6(&stack, V6_A, None, false, true, UID, None).unwrap(),
        bind6(&stack, V6_A, None, false, true, UID, None).unwrap(),
    ];
    let native = [
        bind6_mode(&stack, V6_A, None, false, true, UID, true, None).unwrap(),
        bind6_mode(&stack, V6_A, None, false, true, UID, true, None).unwrap(),
    ];
    for sport in 10_000..10_128 {
        let selected = stack.udp6_demux(V6_SRC, sport, V6_A, PORT, IFACE_A);
        assert!(native.iter().any(|endpoint| Arc::ptr_eq(endpoint, &selected[0])));
        assert!(!dual.iter().any(|endpoint| Arc::ptr_eq(endpoint, &selected[0])));
    }
}

#[test]
fn exact_ipv4_close_preserves_reuse_peer() {
    let stack = NetStack::new();
    let closed = bind4(&stack, V4_A, None, false, true, UID, None).unwrap();
    let peer = bind4(&stack, V4_A, None, false, true, UID, None).unwrap();

    stack.unbind_udp_endpoint(&closed);

    assert_only4(&stack.udp_demux(V4_SRC, 13_000, V4_A, PORT, IFACE_A), &peer);
    assert_eq!(stack.udp_map().lock().get(&PORT).map(|group| group.len()), Some(1));
}

#[test]
fn exact_ipv6_close_preserves_reuse_peer() {
    let stack = NetStack::new();
    let closed = bind6(&stack, V6_A, None, false, true, UID, None).unwrap();
    let peer = bind6(&stack, V6_A, None, false, true, UID, None).unwrap();

    stack.unbind_udp6_endpoint(&closed);

    assert_only6(&stack.udp6_demux(V6_SRC, 13_000, V6_A, PORT, IFACE_A), &peer);
    assert_eq!(stack.udp6_map().lock().get(&PORT).map(|group| group.len()), Some(1));
}

#[cfg(target_os = "oxide-kernel")]
#[test]
fn inet_socket_bind_port_zero_publishes_exact_v4_and_v6_endpoints() {
    use crate::sock::{bind, BoundAddr, InetSocket};

    let v4 = Arc::new(InetSocket::new_udp());
    bind(&v4, BoundAddr::Inet { ip: V4_A, port: 0 }).unwrap();
    let v4_port = v4.local_port.lock().expect("port-zero bind must allocate a port");
    assert_ne!(v4_port, 0);
    assert_eq!(v4.udp4.lock().as_ref().map(|endpoint| endpoint.bound_port), Some(v4_port));

    let v6 = Arc::new(InetSocket::new_udp6());
    bind(&v6, BoundAddr::Inet6 { ip: V6_A, port: 0, scope_id: 0 }).unwrap();
    let v6_port = v6.local_port.lock().expect("port-zero bind must allocate a port");
    assert_ne!(v6_port, 0);
    assert_eq!(v6.udp6.lock().as_ref().map(|endpoint| endpoint.bound_port), Some(v6_port));
}
