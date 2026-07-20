use super::*;
use alloc::string::String;
use crate::rtnetlink::rtnetlink_route::{parse_route_attrs, put_multipath_attr, RouteNexthop};

static NOTIFICATION_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn link_req(iface: net::NetIfaceId, flags: u32, change: u32) -> (Nlmsghdr, Vec<u8>) {
    let ifi = Ifinfomsg { ifi_family: 0, __pad: 0, ifi_type: 0,
        ifi_index: iface.raw() as i32, ifi_flags: flags, ifi_change: change };
    let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE + Ifinfomsg::SIZE];
    let req = Nlmsghdr { nlmsg_len: msg.len() as u32, nlmsg_type: RTM_SETLINK,
        nlmsg_flags: crate::flags::NLM_F_REQUEST, nlmsg_seq: 8, nlmsg_pid: 9 };
    req.write_to(&mut msg[..Nlmsghdr::SIZE]);
    ifi.write_to(&mut msg[Nlmsghdr::SIZE..]);
    (req, msg)
}

fn listener(namespace: &network_namespace::NetworkNamespaceRef, group: u32)
    -> Arc<crate::NetlinkSocket>
{
    let listener = Arc::new(crate::NetlinkSocket::new(crate::proto::NETLINK_ROUTE, namespace));
    listener.add_membership(group);
    crate::register_rtnl_listener(&listener);
    listener
}

fn route_req(dst: [u8; 4], oif: Option<u32>, nexthops: &[RouteNexthop])
    -> (Nlmsghdr, Vec<u8>)
{
    let mut body = alloc::vec![0u8; Rtmsg::SIZE];
    Rtmsg { rtm_family: AF_INET, rtm_dst_len: 24, rtm_table: RT_TABLE_MAIN,
        rtm_protocol: RTPROT_STATIC, rtm_scope: RT_SCOPE_UNIVERSE,
        rtm_type: RTN_UNICAST, ..Rtmsg::default() }.write_to(&mut body);
    put_nlattr(&mut body, rta::RTA_DST, &dst);
    if let Some(oif) = oif { put_nlattr_u32(&mut body, rta::RTA_OIF, oif); }
    if !nexthops.is_empty() { put_multipath_attr(&mut body, nexthops); }
    let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE];
    msg.extend_from_slice(&body);
    let req = Nlmsghdr { nlmsg_len: msg.len() as u32, nlmsg_type: RTM_NEWROUTE,
        nlmsg_flags: crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_CREATE
            | crate::flags::NLM_F_EXCL,
        nlmsg_seq: 844, nlmsg_pid: 1 };
    req.write_to(&mut msg[..Nlmsghdr::SIZE]);
    (req, msg)
}

#[test]
fn link_notifications_follow_rtnl_mutation_order() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let _serial = NOTIFICATION_TEST.lock().unwrap();
    let namespace = crate::netlink_tests::test_namespace();
    let ns = namespace.id().as_u64();
    let stack = net::global_stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(MovingDev), ns);
    let listener = listener(&namespace, crate::mcast::grp::RTNLGRP_LINK);
    crate::mcast::block_notification(iface.raw());
    let (first_req, first_msg) = link_req(iface, iff::IFF_UP, iff::IFF_UP);
    let first = std::thread::spawn(move || handle_setlink_in(ns, &first_req, &first_msg));
    crate::mcast::wait_notification_blocked();

    let (second_req, second_msg) = link_req(iface, 0, iff::IFF_UP);
    let second = std::thread::spawn(move || handle_setlink_in(ns, &second_req, &second_msg));
    while stack.ifaces.iface_flags(iface).unwrap() & iff::IFF_UP != 0 {
        std::thread::yield_now();
    }
    assert!(listener.dequeue().is_none());
    crate::mcast::release_notification();
    assert_eq!(ack_errno(&first.join().unwrap()), 0);
    assert_eq!(ack_errno(&second.join().unwrap()), 0);

    let (up, _) = listener.dequeue().expect("first link event");
    let (down, _) = listener.dequeue().expect("second link event");
    let flags = |msg: &[u8]| u32::from_ne_bytes(
        msg[Nlmsghdr::SIZE + 8..Nlmsghdr::SIZE + 12].try_into().unwrap());
    assert_ne!(flags(&up) & iff::IFF_UP, 0);
    assert_eq!(flags(&down) & iff::IFF_UP, 0);
    let _ = stack.ifaces.unregister(iface);
}

#[test]
fn queued_generation_blocks_move_and_ifindex_reuse_until_delivery() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let _serial = NOTIFICATION_TEST.lock().unwrap();
    let namespace = crate::netlink_tests::test_namespace();
    let ns = namespace.id().as_u64();
    let stack = net::global_stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(MovingDev), ns);
    let source = listener(&namespace, crate::mcast::grp::RTNLGRP_IPV4_IFADDR);
    crate::mcast::block_notification(iface.raw());
    let (req, msg) = addr_req(RTM_NEWADDR, iface.raw(), 24, [198, 51, 100, 27]);
    let worker = std::thread::spawn(move || handle_newaddr_in(ns, &req, &msg));
    crate::mcast::wait_notification_blocked();

    let teardown = std::thread::spawn(move || stack.teardown_iface_in(ns, iface));
    while stack.ifaces.acquire_ingress(iface).is_some() { std::thread::yield_now(); }
    assert!(stack.ifaces.lookup_in_ns(iface, ns).is_none());
    assert!(stack.ifaces.lookup_in_ns(iface, 0).is_none());
    assert!(source.dequeue().is_none());
    crate::mcast::release_notification();
    assert_eq!(ack_errno(&worker.join().unwrap()), 0);
    let (event, _) = source.dequeue().expect("old generation event delivered before move");
    assert_eq!(Nlmsghdr::parse(&event).unwrap().nlmsg_type, RTM_NEWADDR);
    assert!(teardown.join().unwrap());
    assert!(stack.ifaces.lookup_in_ns(iface, 0).is_some());
    let _ = stack.ifaces.unregister(iface);
}

#[test]
fn namespace_move_emits_old_dellink_then_initial_newlink() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let _serial = NOTIFICATION_TEST.lock().unwrap();
    let namespace = crate::netlink_tests::test_namespace();
    let ns = namespace.id().as_u64();
    let stack = net::global_stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(MovingDev), ns);
    let old_listener = listener(&namespace, crate::mcast::grp::RTNLGRP_LINK);
    let initial = network_namespace::initial();
    let new_listener = listener(&initial, crate::mcast::grp::RTNLGRP_LINK);

    assert!(stack.teardown_iface_in(ns, iface));
    let (deleted, _) = old_listener.dequeue().expect("old namespace link deletion");
    let (created, _) = new_listener.dequeue().expect("initial namespace link creation");
    assert_eq!(Nlmsghdr::parse(&deleted).unwrap().nlmsg_type, RTM_DELLINK);
    assert_eq!(Nlmsghdr::parse(&created).unwrap().nlmsg_type, RTM_NEWLINK);
    assert_eq!(i32::from_ne_bytes(
        deleted[Nlmsghdr::SIZE + 4..Nlmsghdr::SIZE + 8].try_into().unwrap()),
        iface.raw() as i32);
    assert_eq!(i32::from_ne_bytes(
        created[Nlmsghdr::SIZE + 4..Nlmsghdr::SIZE + 8].try_into().unwrap()),
        iface.raw() as i32);
    let _ = stack.ifaces.unregister(iface);
}

fn addr_req_meta(ifindex: u32, addr: [u8; 4], peer: [u8; 4], flags: u32, scope: u8,
                 cacheinfo: IfaCacheInfo) -> (Nlmsghdr, Vec<u8>) {
    let mut body = Vec::new();
    Ifaddrmsg { ifa_family: AF_INET, ifa_prefixlen: 27, ifa_flags: flags as u8,
        ifa_scope: scope, ifa_index: ifindex }.write_to({
            body.resize(Ifaddrmsg::SIZE, 0); &mut body[..]
        });
    put_nlattr(&mut body, ifa::IFA_LOCAL, &addr);
    put_nlattr(&mut body, ifa::IFA_ADDRESS, &peer);
    put_nlattr(&mut body, ifa::IFA_FLAGS, &flags.to_ne_bytes());
    let mut cache = [0u8; IfaCacheInfo::SIZE];
    cacheinfo.write_to(&mut cache);
    put_nlattr(&mut body, ifa::IFA_CACHEINFO, &cache);
    let req = Nlmsghdr { nlmsg_len: (Nlmsghdr::SIZE + body.len()) as u32,
        nlmsg_type: RTM_NEWADDR, nlmsg_flags: crate::flags::NLM_F_REQUEST,
        nlmsg_seq: 12, nlmsg_pid: 13 };
    let mut msg = alloc::vec![0; Nlmsghdr::SIZE];
    req.write_to(&mut msg);
    msg.extend_from_slice(&body);
    (req, msg)
}

#[test]
fn deladdr_notification_preserves_removed_row_metadata() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let _serial = NOTIFICATION_TEST.lock().unwrap();
    const FLAGS: u32 = 0x41;
    const SCOPE: u8 = 199;
    let cacheinfo = IfaCacheInfo { preferred: 71, valid: 83, cstamp: 97, tstamp: 101 };
    let namespace = crate::netlink_tests::test_namespace();
    let ns = namespace.id().as_u64();
    let stack = net::global_stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(MovingDev), ns);
    let listener = listener(&namespace, crate::mcast::grp::RTNLGRP_IPV4_IFADDR);
    let addr = [203, 0, 113, 73];
    let peer = [203, 0, 113, 74];
    let (new_req, new_msg) = addr_req_meta(iface.raw(), addr, peer, FLAGS, SCOPE, cacheinfo);
    assert_eq!(ack_errno(&handle_newaddr_in(ns, &new_req, &new_msg)), 0);
    let (created, _) = listener.dequeue().expect("new address event");
    let attrs = &created[Nlmsghdr::SIZE + Ifaddrmsg::SIZE..];
    assert_eq!(find_attr(attrs, ifa::IFA_LOCAL).unwrap(), &addr);
    assert_eq!(find_attr(attrs, ifa::IFA_ADDRESS).unwrap(), &peer);
    assert!(find_attr(attrs, ifa::IFA_BROADCAST).is_none());

    let (mut del_req, mut del_msg) = addr_req(RTM_DELADDR, iface.raw(), 27, addr);
    put_nlattr(&mut del_msg, ifa::IFA_ADDRESS, &peer);
    del_req.nlmsg_len = del_msg.len() as u32;
    del_req.write_to(&mut del_msg[..Nlmsghdr::SIZE]);
    assert_eq!(ack_errno(&handle_deladdr_in(ns, &del_req, &del_msg)), 0);
    let (event, _) = listener.dequeue().expect("delete address event");
    assert_eq!(Nlmsghdr::parse(&event).unwrap().nlmsg_type, RTM_DELADDR);
    assert_eq!(event[Nlmsghdr::SIZE + 1], 27);
    assert_eq!(event[Nlmsghdr::SIZE + 2], FLAGS as u8);
    assert_eq!(event[Nlmsghdr::SIZE + 3], SCOPE);
    let attrs = &event[Nlmsghdr::SIZE + Ifaddrmsg::SIZE..];
    assert_eq!(find_attr(attrs, ifa::IFA_LOCAL).unwrap(), &addr);
    assert_eq!(find_attr(attrs, ifa::IFA_ADDRESS).unwrap(), &peer);
    assert!(find_attr(attrs, ifa::IFA_BROADCAST).is_none());
    assert_eq!(find_attr(attrs, ifa::IFA_LABEL).unwrap(), b"eth-stable\0");
    assert_eq!(u32::from_ne_bytes(find_attr(attrs, ifa::IFA_FLAGS).unwrap().try_into().unwrap()), FLAGS);
    let cache = find_attr(attrs, ifa::IFA_CACHEINFO).unwrap();
    assert_eq!(u32::from_ne_bytes(cache[0..4].try_into().unwrap()), cacheinfo.preferred);
    assert_eq!(u32::from_ne_bytes(cache[4..8].try_into().unwrap()), cacheinfo.valid);
    assert_eq!(u32::from_ne_bytes(cache[8..12].try_into().unwrap()), cacheinfo.cstamp);
    assert_eq!(u32::from_ne_bytes(cache[12..16].try_into().unwrap()), cacheinfo.tstamp);
    let _ = stack.ifaces.unregister(iface);
}

#[test]
fn link_route_rule_notifications_share_one_rtnl_order() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let _serial = NOTIFICATION_TEST.lock().unwrap();
    let namespace = crate::netlink_tests::test_namespace();
    let ns = namespace.id().as_u64();
    let stack = net::global_stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(MovingDev), ns);
    let listener = Arc::new(crate::NetlinkSocket::new(crate::proto::NETLINK_ROUTE, &namespace));
    for group in [crate::mcast::grp::RTNLGRP_LINK, crate::mcast::grp::RTNLGRP_IPV4_ROUTE,
        crate::mcast::grp::RTNLGRP_IPV4_RULE] {
        listener.add_membership(group);
    }
    crate::register_rtnl_listener(&listener);
    crate::mcast::block_notification(iface.raw());

    let generation = stack.ifaces.acquire_ingress(iface).unwrap().generation();
    let owner = net::control_event::IfaceOwner { iface, generation };
    let namespace_owner = || net::control_event::NamespaceOwner::Live(namespace.clone());
    let rtnl = stack.rtnl_lock();
    let _link = net::control_event::stage(&rtnl,
        net::control_event::ControlEvent::Link(net::control_event::LinkEvent {
            kind: net::control_event::EventKind::New, namespace: namespace_owner(), owner,
            name: String::from("eth-stable"), mac: net::MacAddr([2, 0, 0, 0, 0, 1]),
            broadcast: net::PacketLinkAddress { len: net::MacAddr::ZERO.0.len() as u8,
                bytes: [u8::MAX; net::PACKET_LINK_ADDRESS_MAX] },
            mtu: 1500, is_loopback: false, flags: iff::IFF_UP,
            stats: net::NetStats::default(),
        }));
    let route_row = RouteRow {
            ns, table: RT_TABLE_MAIN as u32, protocol: RTPROT_STATIC,
            scope: RT_SCOPE_LINK, kind: RTN_UNICAST,
            dst: Some(([192, 0, 2, 0], 24)), gateway: None,
            oif_ifindex: iface.raw(), prefsrc: None, metric: 0, mtu: None,
            flags: 0, weight: 1, nh_flags: 0,
        };
    let _route = net::control_event::stage(&rtnl,
        net::control_event::ControlEvent::Route(net::control_event::RouteEvent {
            kind: net::control_event::EventKind::New, namespace: namespace_owner(),
            owners: alloc::vec![owner], leases: alloc::vec::Vec::new(),
            records: alloc::vec![super::route_state::to_record(route_row)],
        }));
    let rule = net::control_event::stage(&rtnl,
        net::control_event::ControlEvent::Rule(net::control_event::RuleEvent {
        kind: net::control_event::EventKind::New, namespace: namespace_owner(),
        row: net::policy_rule::PolicyRule {
            ns, family: net::policy_rule::AF_INET, dst_len: 0, src_len: 0, tos: 0,
            table: RT_TABLE_MAIN as u32, action: net::policy_rule::FR_ACT_TO_TBL,
            flags: 0, priority: 844,
        },
    }));
    drop(rtnl);

    let publisher = std::thread::spawn(move || net::control_event::publish(rule));
    crate::mcast::wait_notification_blocked();
    assert!(listener.dequeue().is_none(), "later event must not overtake blocked link event");
    crate::mcast::release_notification();
    publisher.join().unwrap();
    for expected in [RTM_NEWLINK, RTM_NEWROUTE, RTM_NEWRULE] {
        let (msg, _) = listener.dequeue().expect("ordered notification");
        assert_eq!(Nlmsghdr::parse(&msg).unwrap().nlmsg_type, expected);
    }
    assert!(listener.dequeue().is_none());
    let _ = stack.ifaces.unregister(iface);
}

#[test]
fn ecmp_route_notification_is_one_canonical_multipath_message() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let _serial = NOTIFICATION_TEST.lock().unwrap();
    let namespace = crate::netlink_tests::test_namespace();
    let ns = namespace.id().as_u64();
    let stack = net::global_stack();
    let first = stack.ifaces.register_in_ns(Arc::new(MovingDev), ns);
    let second = stack.ifaces.register_in_ns(Arc::new(MovingDev), ns);
    let listener = listener(&namespace, crate::mcast::grp::RTNLGRP_IPV4_ROUTE);
    let nexthops = [
        RouteNexthop { gateway: Some([192, 0, 2, 11]), oif: first.raw(), flags: 4, hops: 2 },
        RouteNexthop { gateway: Some([192, 0, 2, 12]), oif: second.raw(), flags: 1, hops: 6 },
    ];
    let (req, msg) = route_req([198, 18, 87, 0], None, &nexthops);

    assert_eq!(ack_errno(&handle_newroute_in(ns, &req, &msg)), 0);
    let (event, _) = listener.dequeue().expect("one ECMP route notification");
    assert_eq!(Nlmsghdr::parse(&event).unwrap().nlmsg_type, RTM_NEWROUTE);
    let attrs = &event[Nlmsghdr::SIZE + Rtmsg::SIZE..];
    let parsed = parse_route_attrs(attrs).unwrap();
    assert_eq!(parsed.oif, None);
    assert_eq!(parsed.gateway, None);
    assert_eq!(parsed.multipath, nexthops);
    assert!(listener.dequeue().is_none(), "ECMP nexthops must not be split into events");

    stack.routes.remove_namespace(ns);
    let _ = stack.ifaces.unregister(first);
    let _ = stack.ifaces.unregister(second);
}

#[test]
fn route_notification_owns_generation_until_publication() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let _serial = NOTIFICATION_TEST.lock().unwrap();
    let namespace = crate::netlink_tests::test_namespace();
    let ns = namespace.id().as_u64();
    let stack = net::global_stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(MovingDev), ns);
    let listener = listener(&namespace, crate::mcast::grp::RTNLGRP_IPV4_ROUTE);
    crate::mcast::block_notification(iface.raw());
    let (req, msg) = route_req([198, 18, 88, 0], Some(iface.raw()), &[]);
    let worker = std::thread::spawn(move || handle_newroute_in(ns, &req, &msg));
    crate::mcast::wait_notification_blocked();

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let teardown = std::thread::spawn(move || {
        done_tx.send(stack.teardown_iface_in(ns, iface)).unwrap();
    });
    while stack.ifaces.lookup_in_ns(iface, ns).is_some() { std::thread::yield_now(); }
    assert!(done_rx.try_recv().is_err(), "teardown must wait for route publication ownership");
    assert!(listener.dequeue().is_none());

    crate::mcast::release_notification();
    assert_eq!(ack_errno(&worker.join().unwrap()), 0);
    let (event, _) = listener.dequeue().expect("generation-owned route event");
    assert_eq!(Nlmsghdr::parse(&event).unwrap().nlmsg_type, RTM_NEWROUTE);
    assert!(done_rx.recv().unwrap());
    teardown.join().unwrap();
    let (deleted, _) = listener.dequeue().expect("teardown route deletion");
    assert_eq!(Nlmsghdr::parse(&deleted).unwrap().nlmsg_type, RTM_DELROUTE);
    let parsed = parse_route_attrs(&deleted[Nlmsghdr::SIZE + Rtmsg::SIZE..]).unwrap();
    assert_eq!(parsed.dst, Some([198, 18, 88, 0]));
    assert_eq!(parsed.oif, Some(iface.raw()));
    assert!(listener.dequeue().is_none());
    let _ = stack.ifaces.unregister(iface);
}

#[test]
fn interface_teardown_does_not_merge_distinct_route_aliases_as_ecmp() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let _serial = NOTIFICATION_TEST.lock().unwrap();
    let namespace = crate::netlink_tests::test_namespace();
    let ns = namespace.id().as_u64();
    let stack = net::global_stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(MovingDev), ns);
    let listener = listener(&namespace, crate::mcast::grp::RTNLGRP_IPV4_ROUTE);
    for protocol in [RTPROT_STATIC, RTPROT_BOOT] {
        stack.routes.add_record_in(ns, super::route_state::to_record(RouteRow {
            ns, table: RT_TABLE_MAIN as u32, protocol, scope: RT_SCOPE_LINK,
            kind: RTN_UNICAST, dst: Some(([198, 18, 90, 0], 24)), gateway: None,
            oif_ifindex: iface.raw(), prefsrc: None, metric: 7, mtu: None,
            flags: 0, weight: 1, nh_flags: 0,
        }));
    }

    assert!(stack.unregister_iface_in(ns, iface));
    for protocol in [RTPROT_STATIC, RTPROT_BOOT] {
        let (event, _) = listener.dequeue().expect("one deletion per route alias");
        assert_eq!(Nlmsghdr::parse(&event).unwrap().nlmsg_type, RTM_DELROUTE);
        assert_eq!(event[Nlmsghdr::SIZE + 5], protocol);
        let parsed = parse_route_attrs(&event[Nlmsghdr::SIZE + Rtmsg::SIZE..]).unwrap();
        assert_eq!(parsed.oif, Some(iface.raw()));
        assert!(parsed.multipath.is_empty());
    }
    assert!(listener.dequeue().is_none());
}

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
    let iface = stack.ifaces.register_in_ns(Arc::new(MovingDev), ns);
    let listener = Arc::new(crate::NetlinkSocket::new(crate::proto::NETLINK_ROUTE, &namespace));
    listener.add_membership(crate::mcast::grp::RTNLGRP_IPV6_IFADDR);
    listener.add_membership(crate::mcast::grp::RTNLGRP_IPV6_ROUTE);
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
    assert_eq!(find_attr(addr_attrs, ifa::IFA_LABEL).unwrap(), b"eth-stable\0");
    let (prefix_route, _) = listener.dequeue().expect("RA prefix route event");
    let (default_route, _) = listener.dequeue().expect("RA default route event");
    for route in [&prefix_route, &default_route] {
        assert_eq!(Nlmsghdr::parse(route).unwrap().nlmsg_type, RTM_NEWROUTE);
        assert_eq!(route[Nlmsghdr::SIZE], AF_INET6);
        assert_eq!(route[Nlmsghdr::SIZE + 5], RTPROT_RA);
        assert_eq!(u32::from_ne_bytes(find_attr(
            &route[Nlmsghdr::SIZE + Rtmsg::SIZE..], rta::RTA_OIF).unwrap()
            .try_into().unwrap()), iface.raw());
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
        listener.add_membership(group);
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
