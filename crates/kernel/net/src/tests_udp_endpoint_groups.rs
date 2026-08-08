use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, Ordering};

use sync::{Socket as StackLockClass, Spinlock};

use crate::{Ipv4Addr, Ipv6Addr, NetError, NetIfaceId, NetStack, SocketError, UdpRxQueue};
use crate::stack_ipv6::Udp6RxQueue;

// The delivery half, split out at the per-file size cutoff.
mod delivery;

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
        V6_A, PORT, None, sock.error.clone(), sock.opts.base.reuseaddr.clone(),
        sock.opts.base.reuseport.clone(), sock.owner_uid, sock.opts.ipv6_v6only.clone(),
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
