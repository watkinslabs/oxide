use super::*;

fn assert_no_endpoint(sock: &InetSocket) {
    assert_eq!(*sock.local_port.lock(), None);
    assert!(sock.udp4.lock().is_none());
    assert!(sock.udp6.lock().is_none());
}

#[cfg(target_os = "oxide-kernel")]
#[test]
fn implicit_udp_bind_rejects_foreign_namespace_device() {
    const FOREIGN_NS: u64 = 71_002;
    let stack = crate::global_stack();
    let (foreign, _) = stack.register_loopback_in(FOREIGN_NS);
    let sock = InetSocket::new_udp();
    sock.set_bound_iface(Some(foreign)).unwrap();
    assert_eq!(sock.ensure_bound(), Err(NetError::Enodev));
    assert!(stack.unregister_iface_in(FOREIGN_NS, foreign));
}

#[test]
fn closed_socket_rejects_multicast_interface_setters() {
    let sock = InetSocket::new_udp();
    sock.close_mcast_ops();
    assert_eq!(sock.set_v4_mcast_iface(Ipv4Addr::ANY, 0), Err(NetError::Einval));
    assert_eq!(sock.set_v6_mcast_iface(0), Err(NetError::Einval));
}

#[test]
fn ipv4_membership_and_filter_do_not_autobind() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = crate::global_stack();
    let (iface, _) = stack.register_loopback();
    let sock = InetSocket::new_udp();
    let group = Ipv4Addr::new(239, 84, 5, 1);
    let source = Ipv4Addr::new(192, 0, 2, 1);
    sock.change_v4_mcast_membership(iface.raw() as i32, Ipv4Addr::ANY, group, true).unwrap();
    assert_no_endpoint(&sock);
    sock.set_v4_mcast_filter_raw_req(iface.raw(), Ipv4Addr::ANY, group,
        crate::mcast_filter::MCAST_INCLUDE, &[source]).unwrap();
    assert_no_endpoint(&sock);
    assert!(stack.unregister_iface(iface));
}

#[test]
fn b829_tcp_multicast_errors_are_network_policy() {
    let tcp4 = InetSocket::new_tcp();
    let tcp6 = InetSocket::new_tcp6();
    let group4 = Ipv4Addr::new(239, 84, 5, 2);
    let group6 = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x846]);
    assert_eq!(tcp4.set_mcast_scalar(McastScalar::V4Iface {
        addr: Ipv4Addr::ANY, ifindex: 0,
    }), Err(NetError::Einval));
    assert_eq!(tcp4.set_mcast_scalar(McastScalar::V4Ttl(1)), Err(NetError::Einval));
    assert_eq!(tcp4.change_v4_mcast_membership(0, Ipv4Addr::ANY, group4, true),
        Err(NetError::Eproto));
    assert_eq!(tcp6.set_mcast_scalar(McastScalar::V6Iface(0)), Err(NetError::Enoprotoopt));
    assert_eq!(tcp6.set_mcast_scalar(McastScalar::V6Hops(1)), Err(NetError::Enoprotoopt));
    assert_eq!(tcp6.change_v6_mcast_membership(0, group6, true), Err(NetError::Eproto));
}

#[test]
fn multicast_family_and_value_errors_are_network_policy() {
    let unix = InetSocket::new_unix();
    let udp = InetSocket::new_udp();
    let group4 = Ipv4Addr::new(239, 84, 5, 3);
    assert_eq!(unix.set_mcast_scalar(McastScalar::V4Iface {
        addr: Ipv4Addr::ANY, ifindex: 0,
    }), Err(NetError::Eopnotsupp));
    assert_eq!(unix.change_v4_mcast_membership(0, Ipv4Addr::ANY, group4, true),
        Err(NetError::Eopnotsupp));
    assert_eq!(unix.set_mcast_scalar(McastScalar::V4Loop(1)), Err(NetError::Eopnotsupp));
    assert_eq!(unix.set_mcast_scalar(McastScalar::V6Loop(1)), Err(NetError::Eopnotsupp));
    assert_eq!(udp.set_mcast_scalar(McastScalar::V4Ttl(256)), Err(NetError::Einval));
    assert_eq!(udp.change_v4_mcast_req(0, Ipv4Addr::ANY, Ipv4Addr::LOOPBACK, true),
        Err(NetError::Einval));
    assert_eq!(udp.source_v4_mcast_req(0, Ipv4Addr::ANY, group4, Ipv4Addr::ANY,
        SourceOp::Join), Err(NetError::Einval));
}

#[test]
fn multicast_preflight_precedes_uapi_and_preserves_b829_errors() {
    let tcp4 = InetSocket::new_tcp();
    let tcp6 = InetSocket::new_tcp6();
    assert_eq!(tcp4.preflight_mcast_set(McastSetOp::V4Membership), Err(NetError::Eproto));
    assert_eq!(tcp6.preflight_mcast_set(McastSetOp::V6Membership), Err(NetError::Eproto));
    assert_eq!(tcp6.preflight_mcast_set(McastSetOp::V6IfaceOrHops), Err(NetError::Enoprotoopt));
    assert_eq!(tcp4.preflight_mcast_set(McastSetOp::V6Membership), Err(NetError::Enoprotoopt));
    let unix = InetSocket::new_unix();
    assert_eq!(unix.preflight_mcast_set(McastSetOp::V4Membership), Err(NetError::Eopnotsupp));
    assert_eq!(unix.preflight_mcast_set(McastSetOp::V6Membership), Err(NetError::Eopnotsupp));
}

#[test]
fn multicast_getters_own_family_group_and_close_policy() {
    let udp4 = InetSocket::new_udp();
    let udp6 = InetSocket::new_udp6();
    assert_eq!(udp4.get_mcast_scalar(McastScalarGet::V4Ttl), Ok(1));
    assert_eq!(udp4.get_mcast_scalar(McastScalarGet::V6Loop), Err(NetError::Eopnotsupp));
    assert_eq!(udp4.get_v6_mcast_filter(0,
        Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,1])), Err(NetError::Eopnotsupp));
    assert_eq!(udp6.get_v6_mcast_filter(0, Ipv6Addr::from_segments([0,0,0,0,0,0,0,1])),
        Err(NetError::Einval));
    udp4.close_mcast_ops();
    assert_eq!(udp4.get_mcast_scalar(McastScalarGet::V4Loop), Err(NetError::Einval));
    assert_eq!(udp4.get_v4_mcast_filter_req(0, Ipv4Addr::ANY,
        Ipv4Addr::new(239, 84, 5, 4)), Err(NetError::Einval));
}

#[test]
fn ipv6_multicast_hops_and_loop_match_linux_values() {
    let sock = InetSocket::new_udp6();
    for value in [0, 1, 255] {
        assert_eq!(sock.set_mcast_scalar(McastScalar::V6Hops(value)), Ok(()));
        assert_eq!(sock.get_mcast_scalar(McastScalarGet::V6Hops), Ok(value));
    }
    assert_eq!(sock.set_mcast_scalar(McastScalar::V6Hops(-1)), Ok(()));
    assert_eq!(sock.get_mcast_scalar(McastScalarGet::V6Hops), Ok(1));
    assert_eq!(sock.set_mcast_scalar(McastScalar::V6Hops(256)), Err(NetError::Einval));
    for value in [0, 1] {
        assert_eq!(sock.set_mcast_scalar(McastScalar::V6Loop(value)), Ok(()));
        assert_eq!(sock.get_mcast_scalar(McastScalarGet::V6Loop), Ok(value));
    }
    assert_eq!(sock.set_mcast_scalar(McastScalar::V6Loop(-1)), Err(NetError::Einval));
    assert_eq!(sock.set_mcast_scalar(McastScalar::V6Loop(2)), Err(NetError::Einval));
}

#[test]
fn ipv6_membership_and_filter_do_not_autobind() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = crate::global_stack();
    let (iface, _) = stack.register_loopback();
    let sock = InetSocket::new_udp6();
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x845]);
    let source = Ipv6Addr::from_segments([0x2001,0xdb8,0,0,0,0,0,1]);
    sock.change_v6_mcast_membership(iface.raw(), group, true).unwrap();
    assert_no_endpoint(&sock);
    sock.set_v6_mcast_filter_raw(iface.raw(), group,
        crate::mcast_filter::MCAST_INCLUDE, &[source]).unwrap();
    assert_no_endpoint(&sock);
    assert!(stack.unregister_iface(iface));
}
