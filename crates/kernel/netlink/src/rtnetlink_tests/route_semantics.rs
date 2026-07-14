use alloc::{sync::Arc, vec::Vec};

use super::*;
use crate::rtnetlink::rtnetlink_route::{put_multipath_attr, RouteNexthop};

const EEXIST: i32 = -17;
const ENOENT: i32 = -2;
const EINVAL: i32 = -22;

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
    const NS: u64 = 0x8250_2001;
    let iface = net::global_stack().ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS);
    let dst = Some(([198, 18, 82, 0], 24));
    let create_flags = crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_CREATE
        | crate::flags::NLM_F_EXCL;
    let (create, create_msg) = request(
        RTM_NEWROUTE, create_flags, dst, Some(iface.raw()), Some([192, 0, 2, 1]), &[]);
    assert_eq!(ack_errno(&handle_newroute_in(NS, &create, &create_msg)), 0);
    assert_eq!(ack_errno(&handle_newroute_in(NS, &create, &create_msg)), EEXIST);
    assert_eq!(rows_for(NS, dst).len(), 1, "exclusive collision must not duplicate route");

    let (replace, replace_msg) = request(
        RTM_NEWROUTE, crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_REPLACE,
        dst, Some(iface.raw()), Some([192, 0, 2, 9]), &[]);
    assert_eq!(ack_errno(&handle_newroute_in(NS, &replace, &replace_msg)), 0);
    let rows = rows_for(NS, dst);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].gateway, Some([192, 0, 2, 9]));
    cleanup(NS, &[iface]);
}

#[test]
fn newroute_replace_requires_existing_route_unless_create_is_set() {
    const NS: u64 = 0x8250_2002;
    let iface = net::global_stack().ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS);
    let dst = Some(([198, 18, 83, 0], 24));
    let (replace, replace_msg) = request(
        RTM_NEWROUTE, crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_REPLACE,
        dst, Some(iface.raw()), None, &[]);
    assert_eq!(ack_errno(&handle_newroute_in(NS, &replace, &replace_msg)), ENOENT);
    assert!(rows_for(NS, dst).is_empty());

    let (upsert, upsert_msg) = request(
        RTM_NEWROUTE, crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_CREATE
            | crate::flags::NLM_F_REPLACE,
        dst, Some(iface.raw()), None, &[]);
    assert_eq!(ack_errno(&handle_newroute_in(NS, &upsert, &upsert_msg)), 0);
    assert_eq!(rows_for(NS, dst).len(), 1);
    cleanup(NS, &[iface]);
}

#[test]
fn delroute_without_oif_removes_lowest_metric_matching_alias() {
    const NS: u64 = 0x8250_2003;
    let iface = net::global_stack().ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS);
    let dst = Some(([198, 18, 84, 0], 24));
    route_insert(RouteRow {
        ns: NS, table: RT_TABLE_MAIN as u32, protocol: RTPROT_STATIC,
        scope: RT_SCOPE_UNIVERSE, kind: RTN_UNICAST, dst,
        gateway: None, oif_ifindex: iface.raw(), prefsrc: None,
        metric: 41, mtu: None, flags: 0, weight: 1, nh_flags: 0,
    });
    let (del, del_msg) = request(RTM_DELROUTE, crate::flags::NLM_F_REQUEST, dst, None, None, &[]);
    assert_eq!(ack_errno(&handle_delroute_in(NS, &del, &del_msg)), 0);
    assert!(rows_for(NS, dst).is_empty());
    cleanup(NS, &[iface]);
}

#[test]
fn newroute_rejects_malformed_attributes_without_mutation() {
    const NS: u64 = 0x8250_2004;
    let iface = net::global_stack().ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS);
    let malformed_len = [3, 0, rta::RTA_DST as u8, (rta::RTA_DST >> 8) as u8];
    let (bad_len, bad_len_msg) = malformed_request(&malformed_len, 24, Some(iface.raw()));
    assert_eq!(ack_errno(&handle_newroute_in(NS, &bad_len, &bad_len_msg)), EINVAL);

    let mut short_dst = Vec::new();
    put_nlattr(&mut short_dst, rta::RTA_DST, &[198, 18, 85]);
    let (bad_dst, bad_dst_msg) = malformed_request(&short_dst, 24, Some(iface.raw()));
    assert_eq!(ack_errno(&handle_newroute_in(NS, &bad_dst, &bad_dst_msg)), EINVAL);

    let (missing_dst, missing_dst_msg) = malformed_request(&[], 24, Some(iface.raw()));
    assert_eq!(ack_errno(&handle_newroute_in(NS, &missing_dst, &missing_dst_msg)), EINVAL);
    assert!(rows_for(NS, Some(([198, 18, 85, 0], 24))).is_empty());
    cleanup(NS, &[iface]);
}

#[test]
fn weighted_multipath_preserves_hops_flags_and_gateways() {
    const NS: u64 = 0x8250_2005;
    let first = net::global_stack().ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS);
    let second = net::global_stack().ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS);
    let dst = Some(([198, 18, 86, 0], 24));
    let nexthops = [
        RouteNexthop { gateway: Some([192, 0, 2, 11]), oif: first.raw(), flags: 4, hops: 2 },
        RouteNexthop { gateway: Some([192, 0, 2, 12]), oif: second.raw(), flags: 1, hops: 6 },
    ];
    let (add, add_msg) = request(
        RTM_NEWROUTE, crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_CREATE
            | crate::flags::NLM_F_EXCL,
        dst, None, None, &nexthops);
    assert_eq!(ack_errno(&handle_newroute_in(NS, &add, &add_msg)), 0);
    let rows = rows_for(NS, dst);
    assert_eq!(rows.len(), 2);
    let first_row = rows.iter().find(|row| row.oif_ifindex == first.raw()).unwrap();
    assert_eq!((first_row.gateway, first_row.weight, first_row.nh_flags),
        (Some([192, 0, 2, 11]), 3, 4));
    let second_row = rows.iter().find(|row| row.oif_ifindex == second.raw()).unwrap();
    assert_eq!((second_row.gateway, second_row.weight, second_row.nh_flags),
        (Some([192, 0, 2, 12]), 7, 1));

    let (del, del_msg) = request(
        RTM_DELROUTE, crate::flags::NLM_F_REQUEST, dst, None, None, &nexthops);
    assert_eq!(ack_errno(&handle_delroute_in(NS, &del, &del_msg)), 0);
    assert!(rows_for(NS, dst).is_empty());
    cleanup(NS, &[first, second]);
}
