extern crate alloc;

use alloc::vec::Vec;

use crate::{flags, Nlmsghdr};

use super::ack::build_ack;
use super::attrs::{put_nlattr, put_nlattr_u32};
use super::route_state::{route_change, route_insert, route_remove, route_take_lowest, RouteRow};
use super::rtnetlink_route::{parse_route_attrs, RouteAttrError};
use super::uapi::{
    rta, Rtmsg, AF_INET, RTM_NEWROUTE, RTN_BLACKHOLE, RTN_LOCAL, RTN_PROHIBIT, RTN_THROW,
    RTN_UNICAST, RTN_UNREACHABLE,
};

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
    if let Some(g) = row.gateway { put_nlattr(&mut body, rta::RTA_GATEWAY, &g); }
    put_nlattr_u32(&mut body, rta::RTA_OIF, row.oif_ifindex);
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
    if full_msg.len() < rtm_off + Rtmsg::SIZE { return build_ack(req, -22); }
    let family = full_msg[rtm_off];
    let dst_len = full_msg[rtm_off + 1];
    let src_len = full_msg[rtm_off + 2];
    let tos = full_msg[rtm_off + 3];
    let header_table = full_msg[rtm_off + 4] as u32;
    let protocol = full_msg[rtm_off + 5];
    let scope = full_msg[rtm_off + 6];
    let kind = full_msg[rtm_off + 7];
    let flags = u32::from_ne_bytes(full_msg[rtm_off + 8..rtm_off + 12].try_into().unwrap());
    if family != AF_INET { return build_ack(req, -97); }
    if dst_len > 32 { return build_ack(req, -22); }
    if src_len != 0 || tos != 0 || !route_kind_supported(kind) || flags != 0 {
        return build_ack(req, -95);
    }
    let attrs = &full_msg[rtm_off + Rtmsg::SIZE..];
    let parsed = match parse_route_attrs(attrs) {
        Ok(parsed) => parsed,
        Err(RouteAttrError::Invalid) => return build_ack(req, -22),
        Err(RouteAttrError::Unsupported) => return build_ack(req, -95),
    };
    let table = parsed.table.unwrap_or(header_table);
    if table == 0 || (dst_len != 0 && parsed.dst.is_none()) { return build_ack(req, -22); }
    let dst = parsed.dst.map(|a| (a, dst_len));
    let mut rows = Vec::new();
    if parsed.multipath.is_empty() {
        let oif = match (parsed.oif, route_kind_needs_oif(kind)) {
            (Some(oif), _) => oif,
            (None, true) => return build_ack(req, -22),
            (None, false) => 0,
        };
        if !route_kind_needs_oif(kind) && (parsed.gateway.is_some() || parsed.prefsrc.is_some()) {
            return build_ack(req, -22);
        }
        rows.push(RouteRow {
            ns: net_ns, table, protocol, scope, kind, dst,
            gateway: parsed.gateway, oif_ifindex: oif, prefsrc: parsed.prefsrc,
            metric: parsed.metric.unwrap_or(0), mtu: parsed.mtu, flags, weight: 1, nh_flags: 0,
        });
    } else {
        if !route_kind_needs_oif(kind) { return build_ack(req, -22); }
        if parsed.gateway.is_some() { return build_ack(req, -22); }
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
    if (exclusive && replace) || (append && replace) { return build_ack(req, -22); }
    let changed = {
        let stack = net::global_stack();
        let rtnl = stack.rtnl_lock();
        if rows.iter().any(|row| row.oif_ifindex != 0
            && !oif_control_ready(stack, &rtnl, net_ns, row.oif_ifindex)) {
            return build_ack(req, -19);
        }
        route_change(&rtnl, &rows, create, exclusive, replace, append)
    };
    if let Err(err) = changed {
        let errno = match err {
            net::route::RouteChangeError::Exists => -17,
            net::route::RouteChangeError::NotFound => -2,
            net::route::RouteChangeError::Invalid => -22,
        };
        return build_ack(req, errno);
    }
    for row in rows { crate::mcast::notify_route(net_ns, false, row); }
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
    if full_msg.len() < rtm_off + Rtmsg::SIZE { return build_ack(req, -22); }
    let dst_len = full_msg[rtm_off + 1];
    let src_len = full_msg[rtm_off + 2];
    let tos = full_msg[rtm_off + 3];
    let header_table = full_msg[rtm_off + 4] as u32;
    let protocol = full_msg[rtm_off + 5];
    let scope = full_msg[rtm_off + 6];
    let kind = full_msg[rtm_off + 7];
    if full_msg[rtm_off] != AF_INET { return build_ack(req, -97); }
    if dst_len > 32 { return build_ack(req, -22); }
    if src_len != 0 || tos != 0 { return build_ack(req, -95); }
    let attrs = &full_msg[rtm_off + Rtmsg::SIZE..];
    let parsed = match parse_route_attrs(attrs) {
        Ok(parsed) => parsed,
        Err(RouteAttrError::Invalid) => return build_ack(req, -22),
        Err(RouteAttrError::Unsupported) => return build_ack(req, -95),
    };
    let table = parsed.table.unwrap_or(header_table);
    if dst_len != 0 && parsed.dst.is_none() { return build_ack(req, -22); }
    let dst = parsed.dst.map(|a| (a, dst_len));
    let (dst_addr, prefix_len) = route_key(dst);
    let multipath = parsed.multipath;
    let removed = {
        let stack = net::global_stack();
        let rtnl = stack.rtnl_lock();
        if parsed.oif.is_some_and(|oif| !oif_control_ready(stack, &rtnl, net_ns, oif))
            || multipath.iter().any(|nh| !oif_control_ready(stack, &rtnl, net_ns, nh.oif)) {
            return build_ack(req, -19);
        }
        route_take_lowest(&rtnl, net_ns, |record| {
            let route = record.route;
            (table == 0 || route.table == table) && route.dst == dst_addr && route.prefix_len == prefix_len
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
        })
    };
    if removed.is_empty() { return build_ack(req, -3); }
    for row in removed { crate::mcast::notify_route(net_ns, true, row); }
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
        const NS_A: u64 = 9233;
        const NS_B: u64 = 9234;
        let iface = net::global_stack().ifaces
            .register_in_ns(Arc::new(net::LoopbackDev::new()), NS_A).raw();
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
        assert_eq!(ack_errno(&handle_newroute_in(NS_B, &req, &msg)), -19);
        assert_eq!(ack_errno(&handle_newroute_in(NS_A, &req, &msg)), 0);
        assert_eq!(route_remove(NS_A, super::super::uapi::RT_TABLE_MAIN as u32,
            Some(([192, 0, 2, 0], 24)), iface, None), 1);
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
