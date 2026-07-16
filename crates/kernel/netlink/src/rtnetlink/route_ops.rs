extern crate alloc;

use alloc::vec::Vec;

use crate::{flags, Nlmsghdr};

use super::ack::build_ack;
use super::attrs::{put_nlattr, put_nlattr_u32};
use super::route_state::{route_change, route_take_lowest, RouteRow};
use super::rtnetlink_route::{parse_route_attrs, put_multipath_attr, RouteAttrError, RouteNexthop};
use super::uapi::{
    rta, Rtmsg, AF_INET, AF_INET6, RTM_NEWROUTE, RTN_BLACKHOLE, RTN_LOCAL, RTN_PROHIBIT,
    RTN_THROW, RTN_UNICAST, RTN_UNREACHABLE, RTPROT_RA, RTPROT_STATIC, RT_SCOPE_HOST,
    RT_SCOPE_LINK, RT_SCOPE_UNIVERSE,
};
use syscall::errno::Errno;

fn build_errno_ack(req: &Nlmsghdr, errno: Errno) -> Vec<u8> {
    build_ack(req, -errno.as_i32())
}

fn route_kind_supported(kind: u8) -> bool {
    matches!(kind, RTN_UNICAST | RTN_LOCAL | RTN_BLACKHOLE | RTN_UNREACHABLE | RTN_PROHIBIT | RTN_THROW)
}

fn route_kind_needs_oif(kind: u8) -> bool { matches!(kind, RTN_UNICAST | RTN_LOCAL) }

fn oif_control_ready(stack: &net::NetStack, rtnl: &net::RtnlGuard<'_>,
                     net_ns: u64, oif: u32) -> bool {
    stack.ifaces.control_ready_in_ns(rtnl, net::NetIfaceId::from_raw(oif), net_ns).is_some()
}

/// Build one RTM_NEWROUTE reply.
/// # C: O(N attrs)
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_newroute_reply(
    seq: u32, pid: u32, table: u8, protocol: u8, scope: u8, kind: u8,
    dst: Option<([u8; 4], u8)>, gateway: Option<[u8; 4]>, oif_ifindex: u32, prefsrc: Option<[u8; 4]>,
    multi: bool,
) -> Vec<u8> {
    build_newroute_row_reply(seq, pid, RouteRow {
        ns: 0, table: table as u32, protocol, scope, kind, dst, gateway,
        oif_ifindex, prefsrc, metric: 0, mtu: None, flags: 0, weight: 1, nh_flags: 0,
    }, multi)
}

/// Build one RTM_NEWROUTE reply from the canonical route record. # C: O(N attrs)
pub(crate) fn build_newroute_row_reply(seq: u32, pid: u32, row: RouteRow, multi: bool) -> Vec<u8> {
    build_newroute_group_reply(seq, pid, core::slice::from_ref(&row), multi)
}

/// Build one canonical RTM_NEWROUTE reply for a route alias group. # C: O(N nexthops + attrs)
pub(crate) fn build_newroute_group_reply(
    seq: u32, pid: u32, rows: &[RouteRow], multi: bool,
) -> Vec<u8> {
    let Some(row) = rows.first().copied() else { return Vec::new(); };
    let mut body: Vec<u8> = Vec::with_capacity(64);
    let dst_len = row.dst.map(|(_, n)| n).unwrap_or(0);
    let header_table = if row.table <= u8::MAX as u32 { row.table as u8 } else { 0 };
    let rtm = Rtmsg {
        rtm_family: AF_INET,
        rtm_dst_len: dst_len,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: header_table,
        rtm_protocol: row.protocol,
        rtm_scope: row.scope,
        rtm_type: row.kind,
        rtm_flags: row.flags,
    };
    let mut rtm_buf = [0u8; Rtmsg::SIZE];
    rtm.write_to(&mut rtm_buf);
    body.extend_from_slice(&rtm_buf);

    if let Some((addr, _)) = row.dst { put_nlattr(&mut body, rta::RTA_DST, &addr); }
    if rows.len() == 1 {
        if let Some(g) = row.gateway { put_nlattr(&mut body, rta::RTA_GATEWAY, &g); }
        put_nlattr_u32(&mut body, rta::RTA_OIF, row.oif_ifindex);
    } else {
        let nexthops: Vec<_> = rows.iter().map(|row| RouteNexthop {
            gateway: row.gateway, oif: row.oif_ifindex, flags: row.nh_flags,
            hops: row.weight.saturating_sub(1).min(u8::MAX as u16) as u8,
        }).collect();
        put_multipath_attr(&mut body, &nexthops);
    }
    if let Some(s) = row.prefsrc { put_nlattr(&mut body, rta::RTA_PREFSRC, &s); }
    if row.metric != 0 { put_nlattr_u32(&mut body, rta::RTA_PRIORITY, row.metric); }
    if row.table > u8::MAX as u32 { put_nlattr_u32(&mut body, rta::RTA_TABLE, row.table); }
    if let Some(mtu) = row.mtu {
        let mut metrics = Vec::new();
        put_nlattr_u32(&mut metrics, 2, mtu);
        put_nlattr(&mut body, rta::RTA_METRICS, &metrics);
    }

    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32,
        nlmsg_type: RTM_NEWROUTE,
        nlmsg_flags: if multi { flags::NLM_F_MULTI } else { 0 },
        nlmsg_seq: seq,
        nlmsg_pid: pid,
    };
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}

/// Build one canonical IPv6 route notification. # C: O(N attrs)
pub(crate) fn build_newroute6_reply(seq: u32, pid: u32, row: net::Route6Entry,
                                    multi: bool) -> Vec<u8> {
    let is_local = row.dst.is_loopback() && row.prefix_len == 128 && row.gateway.is_none();
    let protocol = match row.origin {
        net::Route6Origin::Static => RTPROT_STATIC,
        net::Route6Origin::RouterAdvertisementDefault { .. }
        | net::Route6Origin::RouterAdvertisementPrefix { .. } => RTPROT_RA,
    };
    let scope = if is_local { RT_SCOPE_HOST }
        else if row.gateway.is_none() { RT_SCOPE_LINK } else { RT_SCOPE_UNIVERSE };
    let mut body = Vec::with_capacity(96);
    Rtmsg { rtm_family: AF_INET6, rtm_dst_len: row.prefix_len, rtm_src_len: 0, rtm_tos: 0,
        rtm_table: if row.table <= u8::MAX as u32 { row.table as u8 } else { 0 },
        rtm_protocol: protocol, rtm_scope: scope,
        rtm_type: if is_local { RTN_LOCAL } else { RTN_UNICAST }, rtm_flags: 0,
    }.write_to({ body.resize(Rtmsg::SIZE, 0); &mut body[..] });
    if row.prefix_len != 0 { put_nlattr(&mut body, rta::RTA_DST, &row.dst.0); }
    if let Some(gateway) = row.gateway { put_nlattr(&mut body, rta::RTA_GATEWAY, &gateway.0); }
    put_nlattr_u32(&mut body, rta::RTA_OIF, row.iface.raw());
    if let Some(source) = row.src_hint { put_nlattr(&mut body, rta::RTA_PREFSRC, &source.0); }
    if row.table > u8::MAX as u32 { put_nlattr_u32(&mut body, rta::RTA_TABLE, row.table); }
    let total = crate::Nlmsghdr::SIZE + body.len();
    let hdr = crate::Nlmsghdr { nlmsg_len: total as u32, nlmsg_type: RTM_NEWROUTE,
        nlmsg_flags: if multi { flags::NLM_F_MULTI } else { 0 }, nlmsg_seq: seq, nlmsg_pid: pid };
    let mut out = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; crate::Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}

struct RouteOwners {
    namespace: network_namespace::NetworkNamespaceRef,
    leases: Vec<net::netdev::IngressLease>,
}

fn route_owners(stack: &net::NetStack, net_ns: u64, records: &[net::RouteRecord])
    -> Option<RouteOwners> {
    let namespace = if net_ns == 0 { network_namespace::initial() }
        else { network_namespace::lookup_u64(net_ns)? };
    let mut leases = Vec::new();
    for record in records {
        let iface = record.route.iface;
        if iface.raw() == 0 || leases.iter().any(|lease: &net::netdev::IngressLease| {
            lease.iface() == iface
        }) { continue; }
        let lease = stack.ifaces.acquire_ingress(iface)?;
        if lease.net_ns() != net_ns { return None; }
        leases.push(lease);
    }
    Some(RouteOwners { namespace, leases })
}

fn owners_match(rtnl: &net::RtnlGuard<'_>, stack: &net::NetStack,
    net_ns: u64, records: &[net::RouteRecord], owners: &RouteOwners) -> bool {
    records.iter().all(|record| record.route.iface.raw() == 0
        || owners.leases.iter().any(|lease| {
        lease.iface() == record.route.iface && lease.net_ns() == net_ns
            && stack.ifaces.control_generation_in_ns(rtnl, lease.iface(), net_ns)
                == Some(lease.generation())
    }))
}

fn queue_route(rtnl: &net::RtnlGuard<'_>, is_del: bool, records: Vec<net::RouteRecord>,
    owners: RouteOwners) -> u64 {
    let iface_owners = owners.leases.iter().map(|lease| net::control_event::IfaceOwner {
        iface: lease.iface(), generation: lease.generation(),
    }).collect();
    net::control_event::stage(rtnl,
        net::control_event::ControlEvent::Route(net::control_event::RouteEvent {
            kind: if is_del { net::control_event::EventKind::Delete }
                else { net::control_event::EventKind::New },
            namespace: net::control_event::NamespaceOwner::Live(owners.namespace),
            owners: iface_owners, leases: owners.leases, records,
        }))
}

/// RTM_GETROUTE dump.
/// # C: O(N_ifaces)
pub fn handle_getroute(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    handle_getroute_in(net::netdev::current_net_ns(), req, full_msg)
}

/// RTM_GETROUTE against the namespace captured by the netlink socket. # C: O(N)
pub fn handle_getroute_in(net_ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    crate::rtnetlink_lookup::handle_getroute(net_ns, req, full_msg)
}

/// Convert an rtnetlink IPv4 destination prefix into a live route key.
/// # C: O(1)
pub(crate) fn route_key(dst: Option<([u8; 4], u8)>) -> (net::Ipv4Addr, u8) {
    let (addr, prefix_len) = dst.unwrap_or(([0, 0, 0, 0], 0));
    let prefix_len = prefix_len.min(32);
    let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
    (net::Ipv4Addr::from_u32(u32::from_be_bytes(addr) & mask), prefix_len)
}

/// Handle RTM_NEWROUTE.
/// # C: O(N attrs + route table)
pub fn handle_newroute(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    handle_newroute_in(net::netdev::current_net_ns(), req, full_msg)
}

/// Mutate routes in the namespace captured by the netlink socket. # C: O(N)
pub fn handle_newroute_in(net_ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let rtm_off = Nlmsghdr::SIZE;
    if full_msg.len() < rtm_off + Rtmsg::SIZE { return build_errno_ack(req, Errno::Einval); }
    let family = full_msg[rtm_off];
    let dst_len = full_msg[rtm_off + 1];
    let src_len = full_msg[rtm_off + 2];
    let tos = full_msg[rtm_off + 3];
    let header_table = full_msg[rtm_off + 4] as u32;
    let protocol = full_msg[rtm_off + 5];
    let scope = full_msg[rtm_off + 6];
    let kind = full_msg[rtm_off + 7];
    let flags = u32::from_ne_bytes(full_msg[rtm_off + 8..rtm_off + 12].try_into().unwrap());
    if family != AF_INET { return build_errno_ack(req, Errno::Eafnosupport); }
    if dst_len > 32 { return build_errno_ack(req, Errno::Einval); }
    if src_len != 0 || tos != 0 || !route_kind_supported(kind) || flags != 0 {
        return build_errno_ack(req, Errno::Eopnotsupp);
    }
    let attrs = &full_msg[rtm_off + Rtmsg::SIZE..];
    let parsed = match parse_route_attrs(attrs) {
        Ok(parsed) => parsed,
        Err(RouteAttrError::Invalid) => return build_errno_ack(req, Errno::Einval),
        Err(RouteAttrError::Unsupported) => return build_errno_ack(req, Errno::Eopnotsupp),
    };
    let table = parsed.table.unwrap_or(header_table);
    if table == 0 || (dst_len != 0 && parsed.dst.is_none()) { return build_errno_ack(req, Errno::Einval); }
    let dst = parsed.dst.map(|a| (a, dst_len));
    let mut rows = Vec::new();
    if parsed.multipath.is_empty() {
        let oif = match (parsed.oif, route_kind_needs_oif(kind)) {
            (Some(oif), _) => oif,
            (None, true) => return build_errno_ack(req, Errno::Einval),
            (None, false) => 0,
        };
        if !route_kind_needs_oif(kind) && (parsed.gateway.is_some() || parsed.prefsrc.is_some()) {
            return build_errno_ack(req, Errno::Einval);
        }
        rows.push(RouteRow {
            ns: net_ns, table, protocol, scope, kind, dst,
            gateway: parsed.gateway, oif_ifindex: oif, prefsrc: parsed.prefsrc,
            metric: parsed.metric.unwrap_or(0), mtu: parsed.mtu, flags, weight: 1, nh_flags: 0,
        });
    } else {
        if !route_kind_needs_oif(kind) { return build_errno_ack(req, Errno::Einval); }
        if parsed.gateway.is_some() { return build_errno_ack(req, Errno::Einval); }
        for nh in parsed.multipath {
            rows.push(RouteRow {
                ns: net_ns, table, protocol, scope, kind, dst,
                gateway: nh.gateway, oif_ifindex: nh.oif, prefsrc: parsed.prefsrc,
                metric: parsed.metric.unwrap_or(0), mtu: parsed.mtu, flags,
                weight: nh.hops as u16 + 1, nh_flags: nh.flags,
            });
        }
    }
    let create = req.nlmsg_flags & flags::NLM_F_CREATE != 0;
    let exclusive = req.nlmsg_flags & flags::NLM_F_EXCL != 0;
    let replace = req.nlmsg_flags & flags::NLM_F_REPLACE != 0;
    let append = req.nlmsg_flags & flags::NLM_F_APPEND != 0;
    if (exclusive && replace) || (append && replace) { return build_errno_ack(req, Errno::Einval); }
    let stack = net::global_stack();
    let records: Vec<_> = rows.iter().copied().map(super::route_state::to_record).collect();
    let mut retained = records.clone();
    if append {
        retained.extend(stack.routes.snapshot_alias_group_in(net_ns, records[0]));
    }
    let Some(owners) = route_owners(stack, net_ns, &retained) else {
        return build_errno_ack(req, Errno::Enodev);
    };
    let ticket = {
        let rtnl = stack.rtnl_lock();
        if append {
            retained = records.clone();
            retained.extend(stack.routes.snapshot_alias_group_in(net_ns, records[0]));
        }
        if !owners_match(&rtnl, stack, net_ns, &retained, &owners) || rows.iter().any(|row| {
            row.oif_ifindex != 0 && !oif_control_ready(stack, &rtnl, net_ns, row.oif_ifindex)
        }) {
            return build_errno_ack(req, Errno::Enodev);
        }
        if let Err(err) = route_change(&rtnl, &rows, create, exclusive, replace, append) {
            let errno = match err {
                net::route::RouteChangeError::Exists => Errno::Eexist,
                net::route::RouteChangeError::NotFound => Errno::Enoent,
                net::route::RouteChangeError::Invalid => Errno::Einval,
            };
            return build_errno_ack(req, errno);
        }
        let resulting = stack.routes.snapshot_alias_group_in(net_ns, records[0]);
        queue_route(&rtnl, false, resulting, owners)
    };
    net::control_event::publish(ticket);
    build_ack(req, 0)
}

/// Handle RTM_DELROUTE.
/// # C: O(N attrs + route table)
pub fn handle_delroute(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    handle_delroute_in(net::netdev::current_net_ns(), req, full_msg)
}

/// Delete routes in the namespace captured by the netlink socket. # C: O(N)
pub fn handle_delroute_in(net_ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let rtm_off = Nlmsghdr::SIZE;
    if full_msg.len() < rtm_off + Rtmsg::SIZE { return build_errno_ack(req, Errno::Einval); }
    let dst_len = full_msg[rtm_off + 1];
    let src_len = full_msg[rtm_off + 2];
    let tos = full_msg[rtm_off + 3];
    let header_table = full_msg[rtm_off + 4] as u32;
    let protocol = full_msg[rtm_off + 5];
    let scope = full_msg[rtm_off + 6];
    let kind = full_msg[rtm_off + 7];
    if full_msg[rtm_off] != AF_INET { return build_errno_ack(req, Errno::Eafnosupport); }
    if dst_len > 32 { return build_errno_ack(req, Errno::Einval); }
    if src_len != 0 || tos != 0 { return build_errno_ack(req, Errno::Eopnotsupp); }
    let attrs = &full_msg[rtm_off + Rtmsg::SIZE..];
    let parsed = match parse_route_attrs(attrs) {
        Ok(parsed) => parsed,
        Err(RouteAttrError::Invalid) => return build_errno_ack(req, Errno::Einval),
        Err(RouteAttrError::Unsupported) => return build_errno_ack(req, Errno::Eopnotsupp),
    };
    let table = parsed.table.unwrap_or(header_table);
    if dst_len != 0 && parsed.dst.is_none() { return build_errno_ack(req, Errno::Einval); }
    let dst = parsed.dst.map(|a| (a, dst_len));
    let (dst_addr, prefix_len) = route_key(dst);
    let multipath = parsed.multipath;
    let stack = net::global_stack();
    let matches = |record: &net::RouteRecord| {
        let route = record.route;
        (table == 0 || route.table == table) && route.dst == dst_addr
            && route.prefix_len == prefix_len
            && parsed.oif.is_none_or(|oif| route.iface.raw() == oif)
            && parsed.gateway.is_none_or(|gateway| route.gateway
                == Some(net::Ipv4Addr::from_u32(u32::from_be_bytes(gateway))))
            && parsed.prefsrc.is_none_or(|src| route.src_hint
                == Some(net::Ipv4Addr::from_u32(u32::from_be_bytes(src))))
            && parsed.metric.is_none_or(|metric| record.metric == metric)
            && (protocol == 0 || record.protocol == protocol)
            && (scope == 0 || record.scope == scope)
            && (kind == 0 || record.kind == kind)
            && (multipath.is_empty() || multipath.iter().any(|nh| {
                route.iface.raw() == nh.oif && nh.gateway.is_none_or(|gateway| route.gateway
                    == Some(net::Ipv4Addr::from_u32(u32::from_be_bytes(gateway))))
                    && record.nh_flags == nh.flags && record.weight == nh.hops as u16 + 1
            }))
    };
    let selected = net::RouteTable::lowest_metric_group(
        &stack.routes.snapshot_records_in(net_ns), |record| matches(record));
    if selected.is_empty() { return build_errno_ack(req, Errno::Esrch); }
    let Some(owners) = route_owners(stack, net_ns, &selected) else {
        return build_errno_ack(req, Errno::Enodev);
    };
    let ticket = {
        let rtnl = stack.rtnl_lock();
        let current = net::RouteTable::lowest_metric_group(
            &stack.routes.snapshot_records_in(net_ns), |record| matches(record));
        if current.is_empty() { return build_errno_ack(req, Errno::Esrch); }
        if current != selected || !owners_match(&rtnl, stack, net_ns, &current, &owners) {
            return build_errno_ack(req, Errno::Enodev);
        }
        let removed = route_take_lowest(&rtnl, net_ns, |record| matches(record));
        queue_route(&rtnl, true, removed.into_iter()
            .map(super::route_state::to_record).collect(), owners)
    };
    net::control_event::publish(ticket);
    build_ack(req, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    fn ack_errno(reply: &[u8]) -> i32 {
        i32::from_ne_bytes(reply[Nlmsghdr::SIZE..Nlmsghdr::SIZE + 4].try_into().unwrap())
    }

    #[test]
    fn explicit_namespace_validates_output_interface_owner() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let namespace_a = crate::netlink_tests::test_namespace();
        let namespace_b = crate::netlink_tests::test_namespace();
        let ns_a = namespace_a.id().as_u64();
        let ns_b = namespace_b.id().as_u64();
        let iface = net::global_stack().ifaces
            .register_in_ns(Arc::new(net::LoopbackDev::new()), ns_a).raw();
        let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE + Rtmsg::SIZE];
        msg[Nlmsghdr::SIZE] = AF_INET;
        msg[Nlmsghdr::SIZE + 1] = 24;
        msg[Nlmsghdr::SIZE + 4] = super::super::uapi::RT_TABLE_MAIN;
        msg[Nlmsghdr::SIZE + 5] = super::super::uapi::RTPROT_STATIC;
        msg[Nlmsghdr::SIZE + 6] = super::super::uapi::RT_SCOPE_LINK;
        msg[Nlmsghdr::SIZE + 7] = super::super::uapi::RTN_UNICAST;
        put_nlattr(&mut msg, rta::RTA_DST, &[192, 0, 2, 0]);
        put_nlattr_u32(&mut msg, rta::RTA_OIF, iface);
        let req = Nlmsghdr {
            nlmsg_len: msg.len() as u32, nlmsg_type: RTM_NEWROUTE,
            nlmsg_flags: flags::NLM_F_REQUEST | flags::NLM_F_CREATE | flags::NLM_F_EXCL,
            nlmsg_seq: 1, nlmsg_pid: 2,
        };
        req.write_to(&mut msg[..Nlmsghdr::SIZE]);
        assert_eq!(ack_errno(&handle_newroute_in(ns_b, &req, &msg)), -19);
        assert_eq!(ack_errno(&handle_newroute_in(ns_a, &req, &msg)), 0);
        assert_eq!(super::super::route_state::route_remove(ns_a,
            super::super::uapi::RT_TABLE_MAIN as u32,
            Some(([192, 0, 2, 0], 24)), iface, None), 1);
        let _ = net::global_stack().ifaces.unregister(net::NetIfaceId::from_raw(iface));
    }

    #[test]
    fn delroute_with_nonexistent_output_interface_returns_esrch() {
        const NS: u64 = 9235;
        const MISSING_IFINDEX: u32 = u32::MAX;
        let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE + Rtmsg::SIZE];
        msg[Nlmsghdr::SIZE] = AF_INET;
        msg[Nlmsghdr::SIZE + 1] = 24;
        msg[Nlmsghdr::SIZE + 4] = super::super::uapi::RT_TABLE_MAIN;
        put_nlattr(&mut msg, rta::RTA_DST, &[198, 51, 100, 0]);
        put_nlattr_u32(&mut msg, rta::RTA_OIF, MISSING_IFINDEX);
        let req = Nlmsghdr {
            nlmsg_len: msg.len() as u32, nlmsg_type: super::super::uapi::RTM_DELROUTE,
            nlmsg_flags: flags::NLM_F_REQUEST, nlmsg_seq: 3, nlmsg_pid: 4,
        };
        req.write_to(&mut msg[..Nlmsghdr::SIZE]);
        assert_eq!(ack_errno(&handle_delroute_in(NS, &req, &msg)), -3);
    }

    #[test]
    fn canonical_metadata_is_emitted() {
        let row = RouteRow {
            ns: 1, table: 1001, protocol: 4, scope: 0, kind: 1,
            dst: Some(([10, 0, 0, 0], 8)), gateway: None, oif_ifindex: 7,
            prefsrc: None, metric: 99, mtu: Some(1400), flags: 0x40, weight: 1, nh_flags: 0,
        };
        let msg = build_newroute_row_reply(1, 2, row, false);
        assert_eq!(msg[Nlmsghdr::SIZE + 4], 0);
        assert_eq!(u32::from_ne_bytes(msg[Nlmsghdr::SIZE + 8..Nlmsghdr::SIZE + 12].try_into().unwrap()), 0x40);
        let attrs = &msg[Nlmsghdr::SIZE + Rtmsg::SIZE..];
        let parsed = parse_route_attrs(attrs).unwrap();
        assert_eq!((parsed.table, parsed.metric, parsed.mtu), (Some(1001), Some(99), Some(1400)));
    }
}
