// Bind/connect reservation tests for `stack::tcp_bind`. Split out when the
// parent crossed the 500-line cap (`docs/08§7`); the parent keeps the
// reservation logic, this file keeps its coverage.

use super::*;

const UID: u32 = 1_000;
const PORT: u16 = 42_123;
const IFACE_A: NetIfaceId = NetIfaceId::from_raw(11);
const IFACE_B: NetIfaceId = NetIfaceId::from_raw(12);

fn reserve(stack: &NetStack, ip: IpAddr, port: u16, iface: Option<NetIfaceId>, v6only: bool)
    -> NetResult<Arc<TcpBindReservation>>
{
    stack.tcp_reserve(ip, port, iface, false, false, UID, v6only)
}

#[test]
fn exact_reservation_conflicts_until_exact_release() {
    let stack = NetStack::new();
    let first = reserve(&stack, IpAddr::V4(Ipv4Addr::ANY), PORT, None, false).unwrap();
    assert_eq!(reserve(&stack, IpAddr::V4(Ipv4Addr::LOOPBACK), PORT, None, false).err(),
               Some(NetError::Eaddrinuse));
    stack.tcp_release_bind(&first);
    assert!(reserve(&stack, IpAddr::V4(Ipv4Addr::LOOPBACK), PORT, None, false).is_ok());
}

#[test]
fn reuseaddr_cannot_bind_over_listener() {
    let stack = NetStack::new();
    let first = stack.tcp_reserve(IpAddr::V4(Ipv4Addr::ANY), PORT, None,
        true, false, UID, false).unwrap();
    stack.tcp_listen_reserved(&first).unwrap();
    assert!(matches!(stack.tcp_reserve(IpAddr::V4(Ipv4Addr::ANY), PORT, None,
               true, false, UID, false), Err(NetError::Eaddrinuse)));
}

#[test]
fn time_wait_reuseaddr_requires_both_sockets_to_opt_in() {
    let stack = NetStack::new();
    let local = IpAddr::V4(Ipv4Addr::LOOPBACK);
    let remote = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    let old = stack.tcp_reserve(local, PORT + 2, None, false, false, UID, false).unwrap();
    let key = TcpKey { local_ip: local, local_port: PORT + 2,
        remote_ip: remote, remote_port: PORT + 3 };
    let mut conn = TcpConn::new_client(
        Endpoint { ip: local, port: PORT + 2 },
        Endpoint { ip: remote, port: PORT + 3 }, 1);
    conn.state = crate::tcp_state::TcpState::TimeWait;
    let old_entry = Arc::new(TcpEntry::new_bound_with_filter_pmtu_modes(
        conn, Arc::new(crate::SocketError::new()), Some(old.clone()),
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(::core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
        Arc::new(::core::sync::atomic::AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT))));
    stack.inet_tables(0).tcp_conns.lock().insert(key, old_entry);

    assert_eq!(stack.tcp_reserve(local, PORT + 2, None, true, false, UID, false).err(),
        Some(NetError::Eaddrinuse));

    drop(old);
    let stack = NetStack::new();
    let old = stack.tcp_reserve(local, PORT + 4, None, true, false, UID, false).unwrap();
    let key = TcpKey { local_ip: local, local_port: PORT + 4,
        remote_ip: remote, remote_port: PORT + 5 };
    let mut conn = TcpConn::new_client(
        Endpoint { ip: local, port: PORT + 4 },
        Endpoint { ip: remote, port: PORT + 5 }, 1);
    conn.state = crate::tcp_state::TcpState::TimeWait;
    let old_entry = Arc::new(TcpEntry::new_bound_with_filter_pmtu_modes(
        conn, Arc::new(crate::SocketError::new()), Some(old),
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(::core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
        Arc::new(::core::sync::atomic::AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT))));
    stack.inet_tables(0).tcp_conns.lock().insert(key, old_entry);
    assert!(stack.tcp_reserve(local, PORT + 4, None, true, false, UID, false).is_ok());
}

#[test]
fn reuseport_listener_group_requires_same_owner_uid() {
    let stack = NetStack::new();
    let first = stack.tcp_reserve(IpAddr::V4(Ipv4Addr::ANY), PORT + 1, None,
        false, true, UID, false).unwrap();
    let second = stack.tcp_reserve(IpAddr::V4(Ipv4Addr::ANY), PORT + 1, None,
        false, true, UID, false).unwrap();
    stack.tcp_listen_reserved(&first).unwrap();
    stack.tcp_listen_reserved(&second).unwrap();
    assert_eq!(stack.tcp_reserve(IpAddr::V4(Ipv4Addr::ANY), PORT + 1, None,
        false, true, UID + 1, false).err(), Some(NetError::Eaddrinuse));
}

/// Replaces `ephemeral_sequence_wraps_from_last_to_first`, which asserted
/// the old counter's behaviour: allocation N was always
/// `DEFAULT_START + N`. That is a sequential scan from a fixed base — an
/// off-path attacker knew every source port a client would use, which is
/// half of what a blind spoof needs. Selection must be spread now.
#[test]
fn ephemeral_ports_are_not_a_sequential_walk_from_the_range_base() {
    let stack = NetStack::new();
    let ports: Vec<u16> = (0..24)
        .map(|_| reserve(&stack, IpAddr::V4(Ipv4Addr::ANY), 0, None, false)
            .unwrap().local.port)
        .collect();
    assert_eq!(ports[0] == crate::ephemeral::DEFAULT_START
               && ports[1] == crate::ephemeral::DEFAULT_START + 1, false,
        "still walking sequentially from the range base");
    // Every reservation is live, so a sequential allocator would produce
    // exactly {base, base+1, ...}. Require the span to be far wider.
    let lo = *ports.iter().min().unwrap();
    let hi = *ports.iter().max().unwrap();
    assert!(hi - lo > ports.len() as u16 * 4,
        "ephemeral ports {lo}..={hi} are packed like a counter");
    for port in &ports {
        assert!((crate::ephemeral::DEFAULT_START..=crate::ephemeral::DEFAULT_END)
            .contains(port), "port {port} escaped ip_local_port_range");
    }
}

#[test]
fn ephemeral_range_is_selected_by_socket_namespace() {
    let stack = NetStack::new();
    let owner = crate::net_ns::test_support::allocate_namespace();
    crate::net_ns::materialize_state(&owner);
    let net_ns = owner.id().as_u64();
    crate::ephemeral::set_range_in(net_ns, 45_100, 45_101).unwrap();
    let first = stack.tcp_reserve_in(net_ns, IpAddr::V4(Ipv4Addr::ANY), 0,
        None, false, false, UID, false).unwrap();
    let second = stack.tcp_reserve_in(net_ns, IpAddr::V4(Ipv4Addr::ANY), 0,
        None, false, false, UID, false).unwrap();
    assert!(matches!(first.local.port, 45_100 | 45_101));
    assert!(matches!(second.local.port, 45_100 | 45_101));
    assert_ne!(first.local.port, second.local.port);
}

#[test]
fn ephemeral_exhaustion_scans_each_canonical_port_once() {
    let stack = NetStack::new();
    let range = crate::ephemeral::range().unwrap();
    let mut held = Vec::with_capacity(range.count() as usize);
    for port in range.start..=range.end {
        held.push(reserve(
            &stack, IpAddr::V4(Ipv4Addr::ANY), port as u16, None, false,
        ).unwrap());
    }
    assert_eq!(reserve(&stack, IpAddr::V4(Ipv4Addr::ANY), 0, None, false).err(),
               Some(NetError::Eaddrnotavail));
    assert_eq!(held.len(), range.count() as usize);
}

#[test]
fn v6only_controls_cross_family_wildcard_conflict() {
    let stack = NetStack::new();
    let _v6 = reserve(&stack, IpAddr::V6(Ipv6Addr::ANY), PORT, None, true).unwrap();
    assert!(reserve(&stack, IpAddr::V4(Ipv4Addr::ANY), PORT, None, false).is_ok());

    let stack = NetStack::new();
    let _v6 = reserve(&stack, IpAddr::V6(Ipv6Addr::ANY), PORT, None, false).unwrap();
    assert_eq!(reserve(&stack, IpAddr::V4(Ipv4Addr::ANY), PORT, None, false).err(),
               Some(NetError::Eaddrinuse));
}

#[test]
fn bind_to_device_rebind_is_transactional() {
    let stack = NetStack::new();
    let a = reserve(&stack, IpAddr::V4(Ipv4Addr::ANY), PORT, Some(IFACE_A), false).unwrap();
    let _b = reserve(&stack, IpAddr::V4(Ipv4Addr::ANY), PORT, Some(IFACE_B), false).unwrap();
    assert_eq!(stack.tcp_rebind_iface(&a, Some(IFACE_B)), Err(NetError::Eaddrinuse));
    assert_eq!(a.bound_iface(), Some(IFACE_A));
}

#[test]
fn listener_transition_consumes_one_reservation_role() {
    let stack = NetStack::new();
    let bind = reserve(&stack, IpAddr::V4(Ipv4Addr::LOOPBACK), PORT, None, false).unwrap();
    let listener = stack.tcp_listen_reserved(&bind).unwrap();
    assert_eq!(bind.role.load(Ordering::Acquire), TCP_BIND_LISTEN);
    assert_eq!(stack.tcp_listen_reserved(&bind).err(), Some(NetError::Einval));
    stack.tcp_unlisten_entry(&listener);
    assert_eq!(bind.role.load(Ordering::Acquire), TCP_BIND_BOUND);
}
