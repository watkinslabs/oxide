use alloc::sync::Arc;
use core::sync::atomic::AtomicI32;

use sync::{Socket as StackLockClass, Spinlock};

use crate::addr::{IpAddr, IpProto, Ipv4Addr, Ipv6Addr};
use crate::netdev::{NetDev, NetResult};
use crate::stack::{NetStack, UdpRxQueue};
use crate::stack_ipv6::Udp6RxQueue;
use crate::{LoopbackDev, NetIfaceId, SocketError};

const PORT: u16 = 42_824;
const V6_PORT: u16 = 42_825;

fn owners() -> (network_namespace::NetworkNamespaceRef,
    network_namespace::NetworkNamespaceRef)
{
    (crate::net_ns::test_support::allocate_namespace(),
        crate::net_ns::test_support::allocate_namespace())
}

fn flag(value: i32) -> Arc<AtomicI32> { Arc::new(AtomicI32::new(value)) }

fn bind_udp(stack: &NetStack, ns: u64, ip: Ipv4Addr, port: u16) -> NetResult<Arc<UdpRxQueue>> {
    stack.bind_udp_socket_in(
        ns, ip, port, None, Arc::new(SocketError::new()), flag(0), flag(0),
        flag(crate::uapi::IP_PMTUDISC_WANT), 1_000,
        Arc::new(Spinlock::<Option<(Ipv4Addr, u16)>, StackLockClass>::new(None)),
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(crate::mcast_filter::SocketMcast::new()),
    )
}

fn bind_udp6(stack: &NetStack, ns: u64, port: u16) -> NetResult<Arc<Udp6RxQueue>> {
    stack.bind_udp6_socket_in(
        ns, Ipv6Addr::ANY, port, None, Arc::new(SocketError::new()), flag(0), flag(0),
        1_000, flag(0), Arc::new(Spinlock::new(None)),
        flag(crate::uapi::IP_PMTUDISC_WANT),
        flag(crate::uapi::IPV6_PMTUDISC_WANT),
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(crate::mcast_filter::SocketMcast::new()),
    )
}

fn udp4_packet(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> alloc::vec::Vec<u8> {
    let udp_len = crate::udp::UDP_HDR_LEN + 1;
    let mut packet = alloc::vec![0u8; crate::ipv4::IPV4_HDR_LEN + udp_len];
    crate::udp::UdpHdr::build_into(
        sport, dport, src, dst, &[4], &mut packet[crate::ipv4::IPV4_HDR_LEN..],
    );
    crate::ipv4::Ipv4Hdr::build(src, dst, IpProto::Udp, udp_len as u16, 1)
        .write_to(&mut packet[..crate::ipv4::IPV4_HDR_LEN]);
    packet
}

fn udp6_packet(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16) -> alloc::vec::Vec<u8> {
    let udp_len = crate::udp::UDP_HDR_LEN + 1;
    let mut packet = alloc::vec![0u8; crate::ipv6::IPV6_HDR_LEN + udp_len];
    crate::ipv6::Ipv6Hdr::build(src, dst, IpProto::Udp, udp_len as u16)
        .write_to(&mut packet[..crate::ipv6::IPV6_HDR_LEN]);
    crate::udp::build_into_v6(
        sport, dport, src, dst, &[6], &mut packet[crate::ipv6::IPV6_HDR_LEN..],
    );
    packet
}

fn iface_in(stack: &NetStack, ns: u64) -> NetIfaceId {
    let owner = network_namespace::lookup_u64(ns).expect("test namespace must remain live");
    let _tables = stack.inet_tables_for(&owner);
    stack.ifaces.register_in_ns(Arc::new(LoopbackDev::new()) as Arc<dyn NetDev>, ns)
}

#[test]
fn duplicate_udp_and_tcp_local_names_are_isolated() {
    let stack = NetStack::new();
    let (owner_a, owner_b) = owners();
    let (ns_a, ns_b) = (owner_a.id().as_u64(), owner_b.id().as_u64());
    let udp_a = bind_udp(&stack, ns_a, Ipv4Addr::ANY, PORT).unwrap();
    let udp_b = bind_udp(&stack, ns_b, Ipv4Addr::ANY, PORT).unwrap();
    assert!(!Arc::ptr_eq(&udp_a, &udp_b));

    let tcp_a = stack.tcp_reserve_in(ns_a, IpAddr::V4(Ipv4Addr::ANY), PORT,
        None, false, false, 1_000, false).unwrap();
    let tcp_b = stack.tcp_reserve_in(ns_b, IpAddr::V4(Ipv4Addr::ANY), PORT,
        None, false, false, 1_000, false).unwrap();
    stack.tcp_listen_reserved(&tcp_a).unwrap();
    stack.tcp_listen_reserved(&tcp_b).unwrap();

    assert_eq!(stack.inet_diag_snapshot_in(ns_a, 17).len(), 1);
    assert_eq!(stack.inet_diag_snapshot_in(ns_b, 17).len(), 1);
    assert_eq!(stack.inet_diag_snapshot_in(ns_a, 6).len(), 1);
    assert_eq!(stack.inet_diag_snapshot_in(ns_b, 6).len(), 1);
    assert!(stack.inet_diag_snapshot_in(0, 17).is_empty());
    assert!(stack.inet_diag_snapshot_in(0, 6).is_empty());
}

#[test]
fn ingress_interface_selects_only_its_namespace_udp_endpoint() {
    let stack = NetStack::new();
    let (owner_a, owner_b) = owners();
    let (ns_a, ns_b) = (owner_a.id().as_u64(), owner_b.id().as_u64());
    let iface_a = iface_in(&stack, ns_a);
    let iface_b = iface_in(&stack, ns_b);
    let a = bind_udp(&stack, ns_a, Ipv4Addr::ANY, PORT).unwrap();
    let b = bind_udp(&stack, ns_b, Ipv4Addr::ANY, PORT).unwrap();
    let src = Ipv4Addr::new(192, 0, 2, 1);

    let selected_a = stack.udp_demux_in(ns_a, src, 50_000, Ipv4Addr::LOOPBACK, PORT, iface_a, &[]);
    let selected_b = stack.udp_demux_in(ns_b, src, 50_000, Ipv4Addr::LOOPBACK, PORT, iface_b, &[]);
    assert_eq!(selected_a.len(), 1);
    assert_eq!(selected_b.len(), 1);
    assert!(Arc::ptr_eq(&selected_a[0], &a));
    assert!(Arc::ptr_eq(&selected_b[0], &b));
}

#[test]
fn ingress_lease_selects_only_its_namespace() {
    let stack = NetStack::new();
    let (owner_a, owner_b) = owners();
    let (ns_a, ns_b) = (owner_a.id().as_u64(), owner_b.id().as_u64());
    let (_iface_a, _) = stack.register_loopback_in(ns_a);
    let (iface_b, _) = stack.register_loopback_in(ns_b);
    let v4_a = bind_udp(&stack, ns_a, Ipv4Addr::ANY, PORT).unwrap();
    let v4_b = bind_udp(&stack, ns_b, Ipv4Addr::ANY, PORT).unwrap();
    let v6_a = bind_udp6(&stack, ns_a, V6_PORT).unwrap();
    let v6_b = bind_udp6(&stack, ns_b, V6_PORT).unwrap();

    let lease = stack.ifaces.acquire_ingress(iface_b).unwrap();
    stack.deliver_rx_in(&lease, &udp4_packet(
        Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::LOOPBACK, 50_000, PORT,
    )).unwrap();
    stack.deliver_rx_ipv6_in(&lease, &udp6_packet(
        Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]),
        Ipv6Addr::LOOPBACK, 50_001, V6_PORT,
    )).unwrap();

    assert!(v4_a.recv(false).is_none());
    assert_eq!(v4_b.recv(false).unwrap().payload, alloc::vec![4]);
    assert!(v6_a.recv(false).is_none());
    assert_eq!(v6_b.recv(false).unwrap().payload, alloc::vec![6]);
}

#[test]
fn pmtu_and_ephemeral_sequences_are_namespace_owned() {
    let stack = NetStack::new();
    let (owner_a, owner_b) = owners();
    crate::net_ns::materialize_state(&owner_a);
    crate::net_ns::materialize_state(&owner_b);
    let (ns_a, ns_b) = (owner_a.id().as_u64(), owner_b.id().as_u64());
    let iface_a = iface_in(&stack, ns_a);
    let iface_b = iface_in(&stack, ns_b);
    let dst = Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
    stack.update_pmtu_v6_in(ns_a, iface_a, dst, 1_280);
    assert_eq!(stack.path_mtu_in(ns_a, IpAddr::V6(dst), Some(iface_a), false), Ok(1_280));
    assert_eq!(stack.path_mtu_in(ns_b, IpAddr::V6(dst), Some(iface_b), false), Ok(65_535));

    crate::ephemeral::set_range_in(ns_a, 45_000, 45_001).unwrap();
    crate::ephemeral::set_range_in(ns_b, 45_000, 45_001).unwrap();
    let a = stack.tcp_reserve_in(ns_a, IpAddr::V4(Ipv4Addr::ANY), 0,
        None, false, false, 1_000, false).unwrap();
    let b = stack.tcp_reserve_in(ns_b, IpAddr::V4(Ipv4Addr::ANY), 0,
        None, false, false, 1_000, false).unwrap();
    assert_eq!(a.local.port, b.local.port);
}

#[test]
fn namespace_teardown_removes_all_transport_visibility() {
    let _guard = crate::net_ns::test_support::LIFETIME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stack = NetStack::new();
    let (owner, _) = owners();
    let id = owner.id();
    let ns = id.as_u64();
    let endpoint = bind_udp(&stack, ns, Ipv4Addr::ANY, PORT).unwrap();
    stack.unbind_udp_endpoint(&endpoint);
    drop(endpoint);
    assert!(stack.remove_inet_namespace(ns));
    assert!(stack.inet_diag_snapshot_in(ns, 17).is_empty());
    drop(owner);
    let claimed = network_namespace::take_dead_namespace_ids();
    assert!(claimed.contains(&id));
    assert!(stack.try_inet_tables(ns).is_none(), "claimed ID cannot recreate transport state");
    crate::net_ns::test_support::finish_claimed(&stack, &claimed);
    assert!(stack.try_inet_tables(ns).is_none(), "finished ID cannot recreate transport state");
}

#[test]
fn transport_table_reverse_link_does_not_pin_namespace_lifetime() {
    let _guard = crate::net_ns::test_support::LIFETIME_LOCK.lock()
        .unwrap_or_else(|error| error.into_inner());
    let stack = NetStack::new();
    let owner = crate::net_ns::test_support::allocate_namespace();
    let id = owner.id();
    let tables = stack.inet_tables_for(&owner);
    drop(tables);
    drop(owner);

    let claimed = network_namespace::take_dead_namespace_ids();
    assert!(claimed.contains(&id), "per-net transport map retains only a weak owner");
    assert!(stack.try_inet_tables(id.as_u64()).is_none(),
        "numeric packet-path lookup cannot reconstruct a dead namespace");
    crate::net_ns::test_support::finish_claimed(&stack, &claimed);
}

#[test]
fn namespace_teardown_removes_tcp_and_ipv6_udp_state() {
    let _guard = crate::net_ns::test_support::LIFETIME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stack = NetStack::new();
    let owner = crate::net_ns::test_support::allocate_namespace();
    let id = owner.id();
    let ns = id.as_u64();
    let udp6 = bind_udp6(&stack, ns, V6_PORT).unwrap();
    let tcp = stack.tcp_reserve_in(ns, IpAddr::V4(Ipv4Addr::ANY), PORT,
        None, false, false, 1_000, false).unwrap();
    let listener = stack.tcp_listen_reserved(&tcp).unwrap();

    assert_eq!(stack.inet_diag_snapshot_in(ns, 17).len(), 1);
    assert_eq!(stack.inet_diag_snapshot_in(ns, 6).len(), 1);
    assert!(crate::net_ns::destroy_namespace_into(&stack, ns));
    assert!(listener.closed.load(core::sync::atomic::Ordering::Acquire));

    drop(udp6);
    drop(listener);
    drop(tcp);
    drop(owner);
    let claimed = network_namespace::take_dead_namespace_ids();
    assert!(claimed.contains(&id));
    crate::net_ns::test_support::finish_claimed(&stack, &claimed);
    assert!(stack.try_inet_tables(ns).is_none(), "teardown removes all family tables");
}

#[test]
fn namespace_teardown_wakes_ipv4_and_ipv6_udp_poll_observers() {
    let _guard = crate::net_ns::test_support::LIFETIME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stack = NetStack::new();
    let owner = crate::net_ns::test_support::allocate_namespace();
    let id = owner.id();
    let ns = id.as_u64();
    let udp4 = bind_udp(&stack, ns, Ipv4Addr::ANY, PORT + 2).unwrap();
    let udp6 = bind_udp6(&stack, ns, V6_PORT + 2).unwrap();
    let poll4 = Arc::new(vfs::PollSubscribers::new());
    let poll6 = Arc::new(vfs::PollSubscribers::new());
    udp4.register_poll_subs(&poll4);
    udp6.register_poll_subs(&poll6);
    let before4 = poll4.generation();
    let before6 = poll6.generation();

    assert!(crate::net_ns::destroy_namespace_into(&stack, ns));
    assert!(poll4.generation() > before4);
    assert!(poll6.generation() > before6);
    drop(udp4);
    drop(udp6);
    drop(owner);
    let claimed = network_namespace::take_dead_namespace_ids();
    assert!(claimed.contains(&id));
    crate::net_ns::test_support::finish_claimed(&stack, &claimed);
}

#[test]
fn udp_enqueue_wakes_ipv4_and_ipv6_poll_observers() {
    let udp4 = UdpRxQueue::new(Ipv4Addr::ANY, PORT + 4);
    let udp6 = Udp6RxQueue::new(Ipv6Addr::ANY, V6_PORT + 4);
    let poll4 = Arc::new(vfs::PollSubscribers::new());
    let poll6 = Arc::new(vfs::PollSubscribers::new());
    udp4.register_poll_subs(&poll4);
    udp6.register_poll_subs(&poll6);
    let before4 = poll4.generation();
    let before6 = poll6.generation();

    assert!(udp4.enqueue(crate::stack::UdpDatagram::plain(Ipv4Addr::LOOPBACK, 9, Ipv4Addr::ANY,
        NetIfaceId::from_raw(9), 64, alloc::vec![1])));
    assert!(udp6.enqueue(crate::stack_ipv6::Udp6Datagram::plain(Ipv6Addr::LOOPBACK, 9, Ipv6Addr::ANY,
        NetIfaceId::from_raw(9), 64, 0, alloc::vec![1])));
    assert!(poll4.generation() > before4);
    assert!(poll6.generation() > before6);
}

#[test]
fn namespace_teardown_wakes_tcp_listener_poll_observers() {
    let _guard = crate::net_ns::test_support::LIFETIME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stack = NetStack::new();
    let owner = crate::net_ns::test_support::allocate_namespace();
    let id = owner.id();
    let ns = id.as_u64();
    let bind = stack.tcp_reserve_in(ns, IpAddr::V4(Ipv4Addr::ANY), PORT + 3,
        None, false, false, 1_000, false).unwrap();
    let listener = stack.tcp_listen_reserved(&bind).unwrap();
    let poll = Arc::new(vfs::PollSubscribers::new());
    listener.register_poll_subs(&poll);
    let before = poll.generation();

    assert!(crate::net_ns::destroy_namespace_into(&stack, ns));
    assert!(listener.is_closed());
    assert!(poll.generation() > before);
    drop(listener);
    drop(bind);
    drop(owner);
    let claimed = network_namespace::take_dead_namespace_ids();
    assert!(claimed.contains(&id));
    crate::net_ns::test_support::finish_claimed(&stack, &claimed);
}

/// The SNMP counters must move where the events happen, not merely render.
///
/// A test that bumps a counter and reads it back proves only that the
/// rendering works; it cannot fail if the receive path stops counting. This
/// drives a real datagram through `deliver_rx_in` and asserts the columns a
/// tool reads actually moved — which is what the hardcoded table of zeroes
/// could never do.
#[test]
fn the_receive_path_counts_what_it_delivers() {
    use crate::mib::{get, forget, Mib};
    let stack = NetStack::new();
    let (owner, _) = owners();
    let ns = owner.id().as_u64();
    let (iface, _) = stack.register_loopback_in(ns);
    let _bound = bind_udp(&stack, ns, Ipv4Addr::ANY, PORT).unwrap();
    forget(ns);

    let lease = stack.ifaces.acquire_ingress(iface).unwrap();
    stack.deliver_rx_in(&lease, &udp4_packet(
        Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::LOOPBACK, 50_000, PORT,
    )).unwrap();

    assert_eq!(get(ns, Mib::IpInReceives), 1, "the datagram was received");
    assert_eq!(get(ns, Mib::IpInDelivers), 1, "and delivered locally");
    assert_eq!(get(ns, Mib::UdpInDatagrams), 1, "and counted as UDP");
    assert_eq!(get(ns, Mib::TcpInSegs), 0, "a UDP datagram is not a TCP segment");
    forget(ns);
}

/// One ICMP type must move one column.
///
/// The echo-reply arm once named its constant unqualified. An unqualified
/// name that is not in scope is a *binding pattern*, not a comparison: it
/// matched every type, counted every ICMP message as an echo reply, and made
/// the arm after it unreachable. The compiler said so and the suite did not,
/// because nothing asserted which column a given type moves.
#[test]
fn each_icmp_type_counts_in_its_own_column() {
    use crate::mib::{forget, get, Mib};
    fn icmp4_packet(src: Ipv4Addr, dst: Ipv4Addr, typ: u8) -> alloc::vec::Vec<u8> {
        const ICMP_LEN: usize = 8 + 1;
        let mut packet = alloc::vec![0u8; crate::ipv4::IPV4_HDR_LEN + ICMP_LEN];
        let mut echo = crate::icmp::IcmpEcho { typ, code: 0, checksum: 0, id: 1, seq: 1 };
        echo.build_into(&[7], &mut packet[crate::ipv4::IPV4_HDR_LEN..]);
        crate::ipv4::Ipv4Hdr::build(src, dst, IpProto::Icmp, ICMP_LEN as u16, 1)
            .write_to(&mut packet[..crate::ipv4::IPV4_HDR_LEN]);
        packet
    }
    let stack = NetStack::new();
    let (owner, _) = owners();
    let ns = owner.id().as_u64();
    let (iface, _) = stack.register_loopback_in(ns);
    let lease = stack.ifaces.acquire_ingress(iface).unwrap();
    let src = Ipv4Addr::new(192, 0, 2, 1);
    forget(ns);

    let _ = stack.deliver_rx_in(&lease,
        &icmp4_packet(src, Ipv4Addr::LOOPBACK, crate::icmp::ICMP_TYPE_ECHO_REPLY));
    assert_eq!(get(ns, Mib::IcmpInEchoReps), 1);
    assert_eq!(get(ns, Mib::IcmpInEchos), 0, "a reply is not a request");

    let _ = stack.deliver_rx_in(&lease,
        &icmp4_packet(src, Ipv4Addr::LOOPBACK, crate::icmp::ICMP_TYPE_ECHO_REQUEST));
    assert_eq!(get(ns, Mib::IcmpInEchos), 1);
    assert_eq!(get(ns, Mib::IcmpInEchoReps), 1, "the request did not move the reply column");

    // A type that is neither moves neither, which the catch-all binding broke.
    let _ = stack.deliver_rx_in(&lease, &icmp4_packet(src, Ipv4Addr::LOOPBACK, 13));
    assert_eq!(get(ns, Mib::IcmpInEchos), 1);
    assert_eq!(get(ns, Mib::IcmpInEchoReps), 1);
    assert_eq!(get(ns, Mib::IcmpInMsgs), 3, "every ICMP message is counted once");
    forget(ns);
}
