use super::*;

fn checksum_words(bytes: &[u8], mut sum: u32) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for word in &mut chunks {
        sum += u16::from_be_bytes([word[0], word[1]]) as u32;
    }
    if let Some(byte) = chunks.remainder().first() { sum += (*byte as u32) << 8; }
    sum
}

fn deliver_ra(stack: &net::NetStack, iface: net::NetIfaceId, src: net::Ipv6Addr,
              prefix: net::Ipv6Addr, router_lifetime: u16, valid: u32, preferred: u32) {
    let dst = net::ndp::IPV6_ALL_NODES;
    let mut payload = net::ndp::RouterAdvertisement::build_one_prefix(
        src, dst, net::MacAddr([2, 0, 0, 0, 0, 1]), router_lifetime, prefix, 64,
        net::ndp::NDP_PIO_FLAG_ONLINK | net::ndp::NDP_PIO_FLAG_AUTO);
    const PIO: usize = 24;
    payload[PIO + 4..PIO + 8].copy_from_slice(&valid.to_be_bytes());
    payload[PIO + 8..PIO + 12].copy_from_slice(&preferred.to_be_bytes());
    payload[2..4].fill(0);
    let mut sum = checksum_words(&src.0, 0);
    sum = checksum_words(&dst.0, sum);
    sum += ((payload.len() as u32) >> 16) + ((payload.len() as u32) & 0xffff);
    sum += net::IpProto::Icmpv6 as u8 as u32;
    sum = checksum_words(&payload, sum);
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    payload[2..4].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    let mut frame = alloc::vec![0; net::ipv6::IPV6_HDR_LEN + payload.len()];
    let mut hdr = net::ipv6::Ipv6Hdr::build(src, dst, net::IpProto::Icmpv6,
        payload.len() as u16);
    hdr.hop_limit = u8::MAX;
    hdr.write_to(&mut frame[..net::ipv6::IPV6_HDR_LEN]);
    frame[net::ipv6::IPV6_HDR_LEN..].copy_from_slice(&payload);
    stack.deliver_rx_ipv6(iface, &frame).unwrap();
}

#[test]
fn ra_withdrawal_and_teardown_emit_ipv6_addr_route_events_in_order() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let _serial = NOTIFICATION_TEST.lock().unwrap();
    let namespace = crate::netlink_tests::test_namespace();
    let ns = namespace.id().as_u64();
    let stack = net::global_stack();
    let reg = stack.prepare_iface(Arc::new(MovingDev), &namespace).unwrap();
    let iface = reg.id();
    assert!(stack.publish_iface(reg));
    let ifindex = visible_ifindex(iface, ns);
    let listener = Arc::new(crate::NetlinkSocket::new(crate::proto::NETLINK_ROUTE, &namespace));
    let _ = listener.add_membership(crate::mcast::grp::RTNLGRP_IPV6_IFADDR);
    let _ = listener.add_membership(crate::mcast::grp::RTNLGRP_IPV6_ROUTE);
    crate::register_rtnl_listener(&listener);
    let router = net::Ipv6Addr::from_segments([0xfe80, 0, 0, 0, 0, 0, 0, 1]);
    let prefix = net::Ipv6Addr::from_segments([0x2001, 0xdb8, 0x844, 0, 0, 0, 0, 0]);

    deliver_ra(stack, iface, router, prefix, 60, 300, 200);
    stack.ipv6_control_tick(0);
    let (addr, _) = listener.dequeue().expect("SLAAC address event");
    assert_eq!(Nlmsghdr::parse(&addr).unwrap().nlmsg_type, RTM_NEWADDR);
    assert_eq!(addr[Nlmsghdr::SIZE], AF_INET6);
    assert_eq!(addr[Nlmsghdr::SIZE + 2] & net::iface_addr::IFA_F_PERMANENT as u8, 0,
        "SLAAC must not be permanent");
    let addr_attrs = &addr[Nlmsghdr::SIZE + Ifaddrmsg::SIZE..];
    // IFA_LABEL names an IPv4 alias; the IPv6 fill emits IFA_ADDRESS instead.
    assert!(find_attr(addr_attrs, ifa::IFA_LABEL).is_none());
    assert!(find_attr(addr_attrs, ifa::IFA_ADDRESS).is_some());
    let (prefix_route, _) = listener.dequeue().expect("RA prefix route event");
    let (default_route, _) = listener.dequeue().expect("RA default route event");
    for route in [&prefix_route, &default_route] {
        assert_eq!(Nlmsghdr::parse(route).unwrap().nlmsg_type, RTM_NEWROUTE);
        assert_eq!(route[Nlmsghdr::SIZE], AF_INET6);
        assert_eq!(route[Nlmsghdr::SIZE + 5], RTPROT_RA);
        assert_eq!(u32::from_ne_bytes(find_attr(
            &route[Nlmsghdr::SIZE + Rtmsg::SIZE..], rta::RTA_OIF).unwrap()
            .try_into().unwrap()), ifindex);
    }
    assert_eq!(find_attr(&prefix_route[Nlmsghdr::SIZE + Rtmsg::SIZE..], rta::RTA_DST),
        Some(prefix.0.as_slice()));
    assert_eq!(find_attr(&default_route[Nlmsghdr::SIZE + Rtmsg::SIZE..], rta::RTA_GATEWAY),
        Some(router.0.as_slice()));

    deliver_ra(stack, iface, router, prefix, 0, 0, 0);
    stack.ipv6_control_tick(0);
    let (updated, _) = listener.dequeue().expect("withdrawn SLAAC lifetime update");
    assert_eq!(Nlmsghdr::parse(&updated).unwrap().nlmsg_type, RTM_NEWADDR);
    for _ in 0..2 {
        let (deleted, _) = listener.dequeue().expect("withdrawn RA route");
        assert_eq!(Nlmsghdr::parse(&deleted).unwrap().nlmsg_type, RTM_DELROUTE);
        assert_eq!(deleted[Nlmsghdr::SIZE], AF_INET6);
    }
    assert!(stack.unregister_iface_in(ns, iface));
    let (deleted_addr, _) = listener.dequeue().expect("teardown address deletion");
    assert_eq!(Nlmsghdr::parse(&deleted_addr).unwrap().nlmsg_type, RTM_DELADDR);
    assert_eq!(deleted_addr[Nlmsghdr::SIZE], AF_INET6);
    assert!(listener.dequeue().is_none());
}

#[test]
fn loopback_registration_emits_ipv4_and_ipv6_address_route_events() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let _serial = NOTIFICATION_TEST.lock().unwrap();
    let namespace = crate::netlink_tests::test_namespace();
    let listener = Arc::new(crate::NetlinkSocket::new(crate::proto::NETLINK_ROUTE, &namespace));
    for group in [crate::mcast::grp::RTNLGRP_LINK, crate::mcast::grp::RTNLGRP_IPV4_IFADDR,
        crate::mcast::grp::RTNLGRP_IPV4_ROUTE, crate::mcast::grp::RTNLGRP_IPV6_IFADDR,
        crate::mcast::grp::RTNLGRP_IPV6_ROUTE]
    {
        let _ = listener.add_membership(group);
    }
    crate::register_rtnl_listener(&listener);

    let (iface, _) = net::global_stack().register_loopback_for(&namespace);
    let expected = [RTM_NEWLINK, RTM_NEWADDR, RTM_NEWROUTE, RTM_NEWADDR, RTM_NEWROUTE];
    let mut events = Vec::new();
    for ty in expected {
        let (event, _) = listener.dequeue().expect("loopback control event");
        assert_eq!(Nlmsghdr::parse(&event).unwrap().nlmsg_type, ty);
        events.push(event);
    }
    assert_eq!(events[1][Nlmsghdr::SIZE], AF_INET);
    assert_eq!(events[2][Nlmsghdr::SIZE], AF_INET);
    assert_eq!(events[3][Nlmsghdr::SIZE], AF_INET6);
    assert_eq!(events[4][Nlmsghdr::SIZE], AF_INET6);
    assert!(listener.dequeue().is_none());
    assert!(net::global_stack().unregister_iface_in(namespace.id().as_u64(), iface));
}
