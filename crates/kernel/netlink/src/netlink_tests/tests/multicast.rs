use super::*;

#[test]
fn rtnl_multicast_delivers_only_to_subscribers() {
    use alloc::sync::Arc;
    let namespace = network_namespace::initial();
    let a = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace));
    let b = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace));
    let _ = a.add_membership(1);
    let _ = b.add_membership(5);
    register_rtnl_listener(&a);
    register_rtnl_listener(&b);
    let msg = alloc::vec![0xABu8; 8];

    let n = rtnl_multicast(1, &msg);
    assert_eq!(n, 1);
    assert!(a.dequeue().is_some());
    assert!(b.dequeue().is_none());

    let n = rtnl_multicast(5, &msg);
    assert_eq!(n, 1);
    assert!(a.dequeue().is_none());
    assert!(b.dequeue().is_some());

    assert_eq!(rtnl_multicast(0, &msg), 0);
}

#[test]
fn rtnl_multicast_isolates_link_addr_and_route_by_socket_namespace() {
    use alloc::sync::Arc;
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let namespace_a = test_namespace();
    let namespace_b = test_namespace();
    let ns_a = namespace_a.id().as_u64();
    let iface = net::global_stack().ifaces
        .register_in_ns(Arc::new(net::LoopbackDev::new()), ns_a);
    let a = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace_a));
    let b = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace_b));
    for group in [
        mcast::grp::RTNLGRP_LINK,
        mcast::grp::RTNLGRP_IPV4_IFADDR,
        mcast::grp::RTNLGRP_IPV4_ROUTE,
    ] {
        let _ = a.add_membership(group);
        let _ = b.add_membership(group);
    }
    register_rtnl_listener(&a);
    register_rtnl_listener(&b);

    let stack = net::global_stack();
    let generation = stack.ifaces.acquire_ingress(iface).unwrap().generation();
    let rtnl = stack.rtnl_lock();
    let owner = net::control_event::IfaceOwner { iface, generation };
    let namespace_owner = || net::control_event::NamespaceOwner::Live(namespace_a.clone());
    let link_ticket = net::control_event::stage(&rtnl,
        net::control_event::ControlEvent::Link(net::control_event::LinkEvent {
            kind: net::control_event::EventKind::New, namespace: namespace_owner(), owner, ifindex: 1,
            name: alloc::string::String::from("lo"), mac: net::MacAddr::ZERO, mtu: 65_535,
            broadcast: net::PacketLinkAddress { len: net::MacAddr::ZERO.0.len() as u8,
                bytes: [0; net::PACKET_LINK_ADDRESS_MAX] },
            is_loopback: true, flags: net::netdev::iff::IFF_UP,
            stats: net::NetStats::default(),
        }));
    let addr_ticket = net::control_event::stage(&rtnl,
        net::control_event::ControlEvent::Addr(net::control_event::AddrEvent {
            kind: net::control_event::EventKind::New, namespace: namespace_owner(), owner,
            label: alloc::string::String::from("lo"),
            row: net::iface_addr::Ipv4IfaceAddr {
                ns: ns_a, iface, addr: net::Ipv4Addr::new(198, 18, 61, 1), peer: None,
                prefixlen: 24,
                mask: 0xffff_ff00, broadcast: None, scope: rtnetlink::RT_SCOPE_UNIVERSE,
                flags: net::iface_addr::IFA_F_PERMANENT, proto: 0, rt_priority: 0,
                cacheinfo: net::iface_addr::Ipv4AddrCacheInfo::PERMANENT,
            },
        }));
    let row = rtnetlink::RouteRow {
            ns: ns_a, table: rtnetlink::RT_TABLE_MAIN as u32,
            protocol: rtnetlink::RTPROT_STATIC, scope: rtnetlink::RT_SCOPE_LINK,
            kind: rtnetlink::RTN_UNICAST, dst: Some(([198, 18, 61, 0], 24)),
            gateway: None, oif_ifindex: iface.raw(), prefsrc: None,
            metric: 0, metrics: net::RouteMetrics::NONE,
            flags: 0, weight: 1, nh_flags: 0,
        };
    let route_ticket = net::control_event::stage(&rtnl,
        net::control_event::ControlEvent::Route(net::control_event::RouteEvent {
            kind: net::control_event::EventKind::New, namespace: namespace_owner(),
            owners: alloc::vec![owner], leases: alloc::vec::Vec::new(),
            records: alloc::vec![rtnetlink::route_state::to_record(row)],
        }));
    drop(rtnl);
    net::control_event::publish(link_ticket);
    net::control_event::publish(addr_ticket);
    net::control_event::publish(route_ticket);

    for ty in [
        rtnetlink::RTM_NEWLINK,
        rtnetlink::RTM_NEWADDR,
        rtnetlink::RTM_NEWROUTE,
    ] {
        let (msg, src) = a.dequeue().expect("mutation namespace listener receives notification");
        assert_eq!(src, 0);
        assert_eq!(Nlmsghdr::parse(&msg).unwrap().nlmsg_type, ty);
    }
    assert!(b.dequeue().is_none(), "other network namespace must not receive rtnetlink multicast");
    let _ = net::global_stack().ifaces.unregister(iface);
}

#[test]
fn rtnl_listen_all_nsid_receives_foreign_namespace_with_local_id() {
    use alloc::sync::Arc;
    let source = test_namespace();
    let receiver_ns = test_namespace();
    receiver_ns.assign_peer_id(&source, 29).unwrap();
    let sock = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &receiver_ns));
    sock.flags.assign(sockflags::F_LISTEN_ALL_NSID, true);
    let _ = sock.add_membership(mcast::grp::RTNLGRP_LINK);
    register_rtnl_listener(&sock);

    assert_eq!(rtnl_multicast_in(source.id().as_u64(), mcast::grp::RTNLGRP_LINK, &[7]), 1);
    let received = match sock.receive(false) {
        ReceiveState::Datagram(received) => received,
        _ => panic!("foreign namespace multicast was not queued"),
    };
    assert_eq!(received.multicast_group, mcast::grp::RTNLGRP_LINK);
    assert_eq!(received.nsid, Some(29));
}

#[test]
fn rtnl_listen_all_nsid_requires_the_socket_opener_capability_for_source() {
    use alloc::sync::Arc;
    let source = test_namespace();
    let receiver_ns = test_namespace();
    receiver_ns.assign_peer_id(&source, 30).unwrap();
    let opener = namespace_identity::initial(namespace_identity::NamespaceKind::User).pin();
    let sock = Arc::new(NetlinkSocket::new_with_cred(proto::NETLINK_ROUTE, &receiver_ns, opener, 0));
    sock.flags.assign(sockflags::F_LISTEN_ALL_NSID, true);
    let _ = sock.add_membership(mcast::grp::RTNLGRP_LINK);
    register_rtnl_listener(&sock);

    assert_eq!(rtnl_multicast_in(source.id().as_u64(), mcast::grp::RTNLGRP_LINK, &[7]), 0);
    assert!(sock.dequeue().is_none());
}

#[test]
fn rtnl_broadcast_error_reports_only_an_opted_in_receiver_overrun() {
    use alloc::sync::Arc;
    let namespace = network_namespace::initial();
    let plain = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace));
    let opted_in = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace));
    for socket in [&plain, &opted_in] {
        socket.set_receive_buffer(0);
        let _ = socket.add_membership(mcast::grp::RTNLGRP_LINK);
        register_rtnl_listener(socket);
    }
    let first = listeners::rtnl_multicast_result_in(namespace.id().as_u64(),
        mcast::grp::RTNLGRP_LINK, &[9]);
    assert_eq!(first.delivered, 0);
    assert!(!first.delivery_error);

    opted_in.flags.assign(sockflags::F_BROADCAST_SEND_ERROR, true);
    let second = listeners::rtnl_multicast_result_in(namespace.id().as_u64(),
        mcast::grp::RTNLGRP_LINK, &[9]);
    assert_eq!(second.delivered, 0);
    assert!(second.delivery_error);
}

