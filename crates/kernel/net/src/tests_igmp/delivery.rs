// What an IPv4 multicast membership actually does to DELIVERY: the source
// filter, endpoint locality and the device reference count. Split out of
// `tests_igmp` at the per-file size cutoff; the report and query protocol
// coverage stays in the parent.

use super::*;

#[test]
fn ipv4_multicast_source_filter_drops_denied_udp_source() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    let group = Ipv4Addr::new(239, 8, 7, 6);
    let allowed = Ipv4Addr::new(10, 0, 0, 1);
    let denied = Ipv4Addr::new(10, 0, 0, 2);
    let port = 47117;

    let state = alloc::sync::Arc::new(crate::mcast_filter::SocketMcast::new());
    state.set_v4(&stack, id, group, Ipv4Addr::LOOPBACK,
        crate::mcast_filter::FilterMode::Include, &[allowed]).unwrap();
    let endpoint = stack.bind_udp_socket(
        Ipv4Addr::ANY, port, None, alloc::sync::Arc::new(crate::SocketError::new()),
        alloc::sync::Arc::new(core::sync::atomic::AtomicI32::new(0)),
        alloc::sync::Arc::new(core::sync::atomic::AtomicI32::new(0)),
        alloc::sync::Arc::new(core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)), 0,
        alloc::sync::Arc::new(sync::Spinlock::new(None)),
        alloc::sync::Arc::new(crate::bpf_filter::SocketFilter::new()), state,
    ).unwrap();

    let blocked = udp_packet(denied, group, 32000, port, b"blocked");
    stack.deliver_rx(id, &blocked).unwrap();
    assert!(endpoint.recv(false).is_none());

    let accepted = udp_packet(allowed, group, 32001, port, b"accepted");
    stack.deliver_rx(id, &accepted).unwrap();
    let d = endpoint.recv(false).unwrap();
    let (src, sport, dst, iface, body) = (d.src, d.sport, d.dst, d.iface, d.payload);
    assert_eq!(src, allowed);
    assert_eq!(sport, 32001);
    assert_eq!(dst, group);
    assert_eq!(iface, id);
    assert_eq!(&body, b"accepted");
}

#[test]
fn ipv4_multicast_delivery_is_endpoint_local() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use alloc::sync::Arc;
    use core::sync::atomic::AtomicI32;
    use sync::Spinlock;
    let stack = NetStack::new();
    let (id, _) = stack.register_loopback();
    let group = Ipv4Addr::new(239, 4, 3, 2);
    let port = 47118;
    let bind = |state| stack.bind_udp_socket(
        Ipv4Addr::ANY, port, None, Arc::new(crate::SocketError::new()),
        Arc::new(AtomicI32::new(1)), Arc::new(AtomicI32::new(0)),
        Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)), 1000,
        Arc::new(Spinlock::new(None)), Arc::new(crate::bpf_filter::SocketFilter::new()), state,
    ).unwrap();
    let joined_state = Arc::new(crate::mcast_filter::SocketMcast::new());
    joined_state.change_v4(&stack, id, group, Ipv4Addr::LOOPBACK, true).unwrap();
    let joined = bind(joined_state);
    // Unconditional multicast delivery is on at creation, so a socket bound to
    // the port receives the group WITHOUT joining it — clearing the option is
    // what makes membership decide.
    let other_state = Arc::new(crate::mcast_filter::SocketMcast::new());
    other_state.set_multicast_all_v4(false);
    let other = bind(other_state);
    let unrestricted = bind(Arc::new(crate::mcast_filter::SocketMcast::new()));

    stack.deliver_rx(id, &udp_packet(Ipv4Addr::new(10, 0, 0, 7), group, 32000, port, b"one")).unwrap();
    assert_eq!(joined.queued_len(), 1);
    assert_eq!(other.queued_len(), 0);
    assert_eq!(unrestricted.queued_len(), 1);
}

#[test]
fn ipv4_multicast_device_state_is_reference_counted() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let group = Ipv4Addr::new(239, 4, 3, 3);
    stack.join_ipv4_multicast(id, group, Ipv4Addr::LOOPBACK).unwrap();
    let _ = lo.rx_pop().expect("first join report");
    finish_igmp_change(&stack, &lo);
    stack.join_ipv4_multicast(id, group, Ipv4Addr::LOOPBACK).unwrap();
    assert!(lo.rx_pop().is_none());
    stack.leave_ipv4_multicast(id, group, Ipv4Addr::LOOPBACK).unwrap();
    assert!(lo.rx_pop().is_none());
    stack.leave_ipv4_multicast(id, group, Ipv4Addr::LOOPBACK).unwrap();
    assert!(lo.rx_pop().is_some());
}
