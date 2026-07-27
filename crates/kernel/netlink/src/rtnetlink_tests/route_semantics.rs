use alloc::{sync::Arc, vec::Vec};

use super::*;
use crate::rtnetlink::rtnetlink_route::{parse_route_attrs, put_multipath_attr, RouteNexthop};

const EEXIST: i32 = -17;
const ENOENT: i32 = -2;
const EINVAL: i32 = -22;
const ENODEV: i32 = -19;

fn request(ty: u16, nl_flags: u16, dst: Option<([u8; 4], u8)>, oif: Option<u32>,
    gateway: Option<[u8; 4]>, multipath: &[RouteNexthop]) -> (Nlmsghdr, Vec<u8>) {
    let mut body = alloc::vec![0u8; Rtmsg::SIZE];
    Rtmsg {
        rtm_family: AF_INET,
        rtm_dst_len: dst.map(|(_, prefix)| prefix).unwrap_or(0),
        rtm_table: RT_TABLE_MAIN,
        rtm_protocol: if ty == RTM_NEWROUTE { RTPROT_STATIC } else { 0 },
        rtm_scope: if ty == RTM_NEWROUTE { RT_SCOPE_UNIVERSE } else { 0 },
        rtm_type: if ty == RTM_NEWROUTE { RTN_UNICAST } else { 0 },
        ..Rtmsg::default()
    }.write_to(&mut body[..Rtmsg::SIZE]);
    if let Some((addr, _)) = dst { put_nlattr(&mut body, rta::RTA_DST, &addr); }
    if let Some(oif) = oif { put_nlattr_u32(&mut body, rta::RTA_OIF, oif); }
    if let Some(gateway) = gateway { put_nlattr(&mut body, rta::RTA_GATEWAY, &gateway); }
    if !multipath.is_empty() { put_multipath_attr(&mut body, multipath); }

    let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE];
    msg.extend_from_slice(&body);
    let req = Nlmsghdr {
        nlmsg_len: msg.len() as u32, nlmsg_type: ty, nlmsg_flags: nl_flags,
        nlmsg_seq: 825, nlmsg_pid: 1,
    };
    req.write_to(&mut msg[..Nlmsghdr::SIZE]);
    (req, msg)
}

fn malformed_request(attrs: &[u8], dst_len: u8, oif: Option<u32>) -> (Nlmsghdr, Vec<u8>) {
    let mut body = alloc::vec![0u8; Rtmsg::SIZE];
    Rtmsg {
        rtm_family: AF_INET, rtm_dst_len: dst_len, rtm_table: RT_TABLE_MAIN,
        rtm_protocol: RTPROT_STATIC, rtm_scope: RT_SCOPE_UNIVERSE,
        rtm_type: RTN_UNICAST, ..Rtmsg::default()
    }.write_to(&mut body[..Rtmsg::SIZE]);
    if let Some(oif) = oif { put_nlattr_u32(&mut body, rta::RTA_OIF, oif); }
    body.extend_from_slice(attrs);
    let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE];
    msg.extend_from_slice(&body);
    let req = Nlmsghdr {
        nlmsg_len: msg.len() as u32, nlmsg_type: RTM_NEWROUTE,
        nlmsg_flags: crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_CREATE,
        nlmsg_seq: 826, nlmsg_pid: 1,
    };
    req.write_to(&mut msg[..Nlmsghdr::SIZE]);
    (req, msg)
}

fn rows_for(ns: u64, dst: Option<([u8; 4], u8)>) -> Vec<RouteRow> {
    route_snapshot_ns(ns).into_iter().filter(|row| row.dst == dst).collect()
}

fn cleanup(ns: u64, ifaces: &[net::NetIfaceId]) {
    net::global_stack().routes.remove_namespace(ns);
    for iface in ifaces { let _ = net::global_stack().ifaces.unregister(*iface); }
}

#[test]
fn newroute_create_excl_and_replace_follow_linux_flags() {
    let _serial = crate::test_serial::fib();
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let namespace = crate::netlink_tests::test_namespace();
    let ns = namespace.id().as_u64();
    let iface = net::global_stack().ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), ns);
    let ifindex = visible_ifindex(iface, ns);
    let dst = Some(([198, 18, 82, 0], 24));
    let create_flags = crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_CREATE
        | crate::flags::NLM_F_EXCL;
    let (create, create_msg) = request(
        RTM_NEWROUTE, create_flags, dst, Some(ifindex), Some([192, 0, 2, 1]), &[]);
    assert_eq!(ack_errno(&handle_newroute_in(ns, &create, &create_msg)), 0);
    assert_eq!(ack_errno(&handle_newroute_in(ns, &create, &create_msg)), EEXIST);
    assert_eq!(rows_for(ns, dst).len(), 1, "exclusive collision must not duplicate route");

    let (replace, replace_msg) = request(
        RTM_NEWROUTE, crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_REPLACE,
        dst, Some(ifindex), Some([192, 0, 2, 9]), &[]);
    assert_eq!(ack_errno(&handle_newroute_in(ns, &replace, &replace_msg)), 0);
    let rows = rows_for(ns, dst);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].gateway, Some([192, 0, 2, 9]));
    cleanup(ns, &[iface]);
}

#[test]
fn newroute_replace_selects_existing_alias_before_mutable_metadata() {
    let _serial = crate::test_serial::fib();
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let namespace = crate::netlink_tests::test_namespace();
    let ns = namespace.id().as_u64();
    let stack = net::global_stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), ns);
    let ifindex = visible_ifindex(iface, ns);
    let dst = Some(([198, 18, 92, 0], 24));
    route_insert(RouteRow { ns, table: RT_TABLE_MAIN as u32, protocol: 99,
        scope: RT_SCOPE_LINK, kind: RTN_UNICAST, dst, gateway: Some([192, 0, 2, 31]),
        oif_ifindex: iface.raw(), prefsrc: Some([198, 18, 92, 7]), metric: 0,
        mtu: Some(1400), flags: 0, weight: 1, nh_flags: 0 });
    let (replace, msg) = request(RTM_NEWROUTE,
        crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_CREATE | crate::flags::NLM_F_REPLACE,
        dst, Some(ifindex), Some([192, 0, 2, 32]), &[]);
    assert_eq!(ack_errno(&handle_newroute_in(ns, &replace, &msg)), 0);
    let rows = rows_for(ns, dst);
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].protocol, rows[0].scope, rows[0].gateway, rows[0].prefsrc, rows[0].mtu),
        (RTPROT_STATIC, RT_SCOPE_UNIVERSE, Some([192, 0, 2, 32]), None, None));
    cleanup(ns, &[iface]);
}

#[test]
fn newroute_replace_requires_existing_route_unless_create_is_set() {
    let _serial = crate::test_serial::fib();
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let namespace = crate::netlink_tests::test_namespace();
    let ns = namespace.id().as_u64();
    let iface = net::global_stack().ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), ns);
    let ifindex = visible_ifindex(iface, ns);
    let dst = Some(([198, 18, 83, 0], 24));
    let (replace, replace_msg) = request(
        RTM_NEWROUTE, crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_REPLACE,
        dst, Some(ifindex), None, &[]);
    assert_eq!(ack_errno(&handle_newroute_in(ns, &replace, &replace_msg)), ENOENT);
    assert!(rows_for(ns, dst).is_empty());

    let (upsert, upsert_msg) = request(
        RTM_NEWROUTE, crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_CREATE
            | crate::flags::NLM_F_REPLACE,
        dst, Some(ifindex), None, &[]);
    assert_eq!(ack_errno(&handle_newroute_in(ns, &upsert, &upsert_msg)), 0);
    assert_eq!(rows_for(ns, dst).len(), 1);
    cleanup(ns, &[iface]);
}

#[test]
fn delroute_without_oif_removes_lowest_metric_matching_alias() {
    let _serial = crate::test_serial::fib();
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let namespace = crate::netlink_tests::test_namespace();
    let ns = namespace.id().as_u64();
    let iface = net::global_stack().ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), ns);
    let ifindex = visible_ifindex(iface, ns);
    let dst = Some(([198, 18, 84, 0], 24));
    route_insert(RouteRow {
        ns, table: RT_TABLE_MAIN as u32, protocol: RTPROT_STATIC,
        scope: RT_SCOPE_UNIVERSE, kind: RTN_UNICAST, dst,
        gateway: None, oif_ifindex: iface.raw(), prefsrc: None,
        metric: 41, mtu: None, flags: 0, weight: 1, nh_flags: 0,
    });
    let (del, del_msg) = request(RTM_DELROUTE, crate::flags::NLM_F_REQUEST, dst, None, None, &[]);
    assert_eq!(ack_errno(&handle_delroute_in(ns, &del, &del_msg)), 0);
    assert!(rows_for(ns, dst).is_empty());
    cleanup(ns, &[iface]);
}

#[test]
fn delroute_without_retained_interface_owner_does_not_mutate() {
    let _serial = crate::test_serial::fib();
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let namespace = crate::netlink_tests::test_namespace();
    let ns = namespace.id().as_u64();
    let dst = Some(([198, 18, 91, 0], 24));
    let stale = RouteRow {
        ns, table: RT_TABLE_MAIN as u32, protocol: RTPROT_STATIC,
        scope: RT_SCOPE_LINK, kind: RTN_UNICAST, dst, gateway: None,
        oif_ifindex: u32::MAX, prefsrc: None, metric: 0, mtu: None,
        flags: 0, weight: 1, nh_flags: 0,
    };
    net::global_stack().routes.add_record_in(ns, super::route_state::to_record(stale));
    let (del, del_msg) = request(RTM_DELROUTE, crate::flags::NLM_F_REQUEST,
        dst, None, None, &[]);
    assert_eq!(ack_errno(&handle_delroute_in(ns, &del, &del_msg)), ENODEV);
    assert_eq!(rows_for(ns, dst), alloc::vec![stale]);
    net::global_stack().routes.remove_namespace(ns);
}

#[test]
fn newroute_rejects_malformed_attributes_without_mutation() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let namespace = crate::netlink_tests::test_namespace();
    let ns = namespace.id().as_u64();
    let iface = net::global_stack().ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), ns);
    let ifindex = visible_ifindex(iface, ns);
    let malformed_len = [3, 0, rta::RTA_DST as u8, (rta::RTA_DST >> 8) as u8];
    let (bad_len, bad_len_msg) = malformed_request(&malformed_len, 24, Some(ifindex));
    assert_eq!(ack_errno(&handle_newroute_in(ns, &bad_len, &bad_len_msg)), EINVAL);

    let mut short_dst = Vec::new();
    put_nlattr(&mut short_dst, rta::RTA_DST, &[198, 18, 85]);
    let (bad_dst, bad_dst_msg) = malformed_request(&short_dst, 24, Some(ifindex));
    assert_eq!(ack_errno(&handle_newroute_in(ns, &bad_dst, &bad_dst_msg)), EINVAL);

    let (missing_dst, missing_dst_msg) = malformed_request(&[], 24, Some(ifindex));
    assert_eq!(ack_errno(&handle_newroute_in(ns, &missing_dst, &missing_dst_msg)), EINVAL);
    assert!(rows_for(ns, Some(([198, 18, 85, 0], 24))).is_empty());
    cleanup(ns, &[iface]);
}

#[test]
fn weighted_multipath_preserves_hops_flags_and_gateways() {
    let _serial = crate::test_serial::fib();
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let namespace = crate::netlink_tests::test_namespace();
    let ns = namespace.id().as_u64();
    let first = net::global_stack().ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), ns);
    let second = net::global_stack().ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), ns);
    let first_ifindex = visible_ifindex(first, ns);
    let second_ifindex = visible_ifindex(second, ns);
    let dst = Some(([198, 18, 86, 0], 24));
    let nexthops = [
        RouteNexthop { gateway: Some([192, 0, 2, 11]), oif: first_ifindex, flags: 4, hops: 2 },
        RouteNexthop { gateway: Some([192, 0, 2, 12]), oif: second_ifindex, flags: 1, hops: 6 },
    ];
    let (add, add_msg) = request(
        RTM_NEWROUTE, crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_CREATE
            | crate::flags::NLM_F_EXCL,
        dst, None, None, &nexthops);
    assert_eq!(ack_errno(&handle_newroute_in(ns, &add, &add_msg)), 0);
    let rows = rows_for(ns, dst);
    assert_eq!(rows.len(), 2);
    let first_row = rows.iter().find(|row| row.oif_ifindex == first.raw()).unwrap();
    assert_eq!((first_row.gateway, first_row.weight, first_row.nh_flags),
        (Some([192, 0, 2, 11]), 3, 4));
    let second_row = rows.iter().find(|row| row.oif_ifindex == second.raw()).unwrap();
    assert_eq!((second_row.gateway, second_row.weight, second_row.nh_flags),
        (Some([192, 0, 2, 12]), 7, 1));

    let (del, del_msg) = request(
        RTM_DELROUTE, crate::flags::NLM_F_REQUEST, dst, None, None, &nexthops);
    assert_eq!(ack_errno(&handle_delroute_in(ns, &del, &del_msg)), 0);
    assert!(rows_for(ns, dst).is_empty());
    cleanup(ns, &[first, second]);
}

#[test]
fn append_notification_contains_complete_resulting_group() {
    let _serial = crate::test_serial::fib();
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let namespace = crate::netlink_tests::test_namespace();
    let ns = namespace.id().as_u64();
    let stack = net::global_stack();
    let first = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), ns);
    let second = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), ns);
    let first_ifindex = visible_ifindex(first, ns);
    let second_ifindex = visible_ifindex(second, ns);
    let listener = Arc::new(crate::NetlinkSocket::new(crate::proto::NETLINK_ROUTE, &namespace));
    listener.add_membership(crate::mcast::grp::RTNLGRP_IPV4_ROUTE);
    crate::register_rtnl_listener(&listener);
    let dst = Some(([198, 18, 89, 0], 24));
    let (add, add_msg) = request(RTM_NEWROUTE,
        crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_CREATE | crate::flags::NLM_F_EXCL,
        dst, Some(first_ifindex), Some([192, 0, 2, 21]), &[]);
    assert_eq!(ack_errno(&handle_newroute_in(ns, &add, &add_msg)), 0);
    let _initial = listener.dequeue().expect("initial route notification");

    let (append, append_msg) = request(RTM_NEWROUTE,
        crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_APPEND,
        dst, Some(second_ifindex), Some([192, 0, 2, 22]), &[]);
    assert_eq!(ack_errno(&handle_newroute_in(ns, &append, &append_msg)), 0);
    let (event, _) = listener.dequeue().expect("append route notification");
    let parsed = parse_route_attrs(&event[Nlmsghdr::SIZE + Rtmsg::SIZE..]).unwrap();
    assert_eq!(parsed.multipath, alloc::vec![
        RouteNexthop { gateway: Some([192, 0, 2, 21]), oif: first_ifindex, flags: 0, hops: 0 },
        RouteNexthop { gateway: Some([192, 0, 2, 22]), oif: second_ifindex, flags: 0, hops: 0 },
    ]);
    assert!(listener.dequeue().is_none());
    cleanup(ns, &[first, second]);
}

#[test]
fn accepted_ipv6_rule_changes_table_aware_route6_lookup() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let namespace = crate::netlink_tests::test_namespace();
    let ns = namespace.id().as_u64();
    let stack = net::global_stack();
    let dst = net::Ipv6Addr::from_segments([0x2001, 0xdb8, 0x844, 0, 0, 0, 0, 1]);
    let main = net::NetIfaceId::from_raw(84);
    let selected = net::NetIfaceId::from_raw(844);
    stack.routes6.add_in(ns, net::Route6Entry { table: net::policy_rule::RT_TABLE_MAIN,
        dst: net::Ipv6Addr::ANY, prefix_len: 0, iface: main, gateway: None, src_hint: None,
        origin: net::Route6Origin::Static });
    stack.routes6.add_in(ns, net::Route6Entry { table: 844,
        dst: net::Ipv6Addr::ANY, prefix_len: 0, iface: selected, gateway: None, src_hint: None,
        origin: net::Route6Origin::Static });
    let mut body = alloc::vec![0u8; crate::rtnetlink_rule::FibRuleHdr::SIZE];
    crate::rtnetlink_rule::FibRuleHdr { family: AF_INET6, table: 0,
        action: net::policy_rule::FR_ACT_TO_TBL, ..Default::default() }.write_to(&mut body);
    put_nlattr_u32(&mut body, crate::rtnetlink_rule::fra::FRA_PRIORITY, 844);
    put_nlattr_u32(&mut body, crate::rtnetlink_rule::fra::FRA_TABLE, 844);
    let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE]; msg.extend_from_slice(&body);
    let req = Nlmsghdr { nlmsg_len: msg.len() as u32,
        nlmsg_type: crate::rtnetlink::RTM_NEWRULE,
        nlmsg_flags: crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_CREATE,
        nlmsg_seq: 844, nlmsg_pid: 1 };
    req.write_to(&mut msg[..Nlmsghdr::SIZE]);

    assert_eq!(ack_errno(&crate::rtnetlink_rule::handle_newrule_in(ns, &req, &msg)), 0);
    assert_eq!(stack.routes6.lookup_policy_in(ns, dst, stack.policy_rules())
        .map(|route| route.iface), Some(selected));
    assert_eq!(net::policy_rule::remove(ns, net::policy_rule::AF_INET6, Some(844), Some(844)), 1);
    assert!(stack.routes6.remove_namespace(ns));
}
