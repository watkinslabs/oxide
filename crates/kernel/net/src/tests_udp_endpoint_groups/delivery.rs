// UDP endpoint DELIVERY once the bind table has chosen: unbind
// linearization, reuseport flow stability and exact-close behaviour.
// Split out of `tests_udp_endpoint_groups` at the per-file size cutoff;
// the bind overlap and demux-preference coverage stays in the parent.

use super::*;

#[test]
fn udp4_unbind_linearizes_payload_and_error_delivery() {
    let stack = NetStack::new();
    let endpoint = bind4(&stack, V4_A, None, false, false, UID, None).unwrap();
    let stale = stack.udp_demux(V4_SRC, 9_000, V4_A, PORT, IFACE_A).pop().unwrap();
    assert!(stale.enqueue(crate::stack::UdpDatagram::plain(V4_SRC, 9_000, V4_A, IFACE_A, 64, alloc::vec![1])));
    stack.unbind_udp_endpoint(&endpoint);
    assert_eq!(stale.queued_len(), 1);
    assert!(!stale.enqueue(crate::stack::UdpDatagram::plain(V4_SRC, 9_000, V4_A, IFACE_A, 64, alloc::vec![2])));

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
    assert!(!stale.enqueue(crate::stack_ipv6::Udp6Datagram::plain(V6_SRC, 9_000, V6_A, IFACE_A, 64, 0, alloc::vec![1])));
    assert!(!stale.set_error(syscall::errno::Errno::Econnrefused as i32));
    assert!(!stale.error.has());

    let endpoint = bind6(&stack, Ipv6Addr::ANY, None, false, false, UID, None).unwrap();
    let mapped = stack.udp6_demux_v4(V4_SRC, 9_001, V4_A, PORT, IFACE_A).pop().unwrap();
    stack.unbind_udp6_endpoint(&endpoint);
    assert!(!mapped.enqueue(crate::stack_ipv6::Udp6Datagram::plain(
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
            deliver.enqueue(crate::stack::UdpDatagram::plain(V4_SRC, 9_000, V4_A, IFACE_A, 64, alloc::vec![1]))
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
        assert!(!stale.enqueue(crate::stack::UdpDatagram::plain(V4_SRC, 9_000, V4_A, IFACE_A, 64, alloc::vec![2])));
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
