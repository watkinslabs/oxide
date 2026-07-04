extern crate alloc;

use alloc::vec::Vec;

use crate::{flags, Nlmsghdr};

use super::ack::build_ack;
use super::attrs::{put_nlattr, put_nlattr_u32};
use super::route_state::{route_insert, route_remove, RouteRow};
use super::rtnetlink_route::parse_route_attrs;
use super::uapi::{rta, Rtmsg, AF_INET, RTM_NEWROUTE};

/// Build one RTM_NEWROUTE reply.
/// # C: O(N attrs)
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_newroute_reply(
    seq: u32, pid: u32, table: u8, protocol: u8, scope: u8, kind: u8,
    dst: Option<([u8; 4], u8)>, gateway: Option<[u8; 4]>, oif_ifindex: u32, prefsrc: Option<[u8; 4]>,
    multi: bool,
) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(64);
    let dst_len = dst.map(|(_, n)| n).unwrap_or(0);
    let rtm = Rtmsg {
        rtm_family: AF_INET,
        rtm_dst_len: dst_len,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: table,
        rtm_protocol: protocol,
        rtm_scope: scope,
        rtm_type: kind,
        rtm_flags: 0,
    };
    let mut rtm_buf = [0u8; Rtmsg::SIZE];
    rtm.write_to(&mut rtm_buf);
    body.extend_from_slice(&rtm_buf);

    if let Some((addr, _)) = dst { put_nlattr(&mut body, rta::RTA_DST, &addr); }
    if let Some(g) = gateway { put_nlattr(&mut body, rta::RTA_GATEWAY, &g); }
    put_nlattr_u32(&mut body, rta::RTA_OIF, oif_ifindex);
    if let Some(s) = prefsrc { put_nlattr(&mut body, rta::RTA_PREFSRC, &s); }

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
    crate::rtnetlink_lookup::handle_getroute(req, full_msg)
}

/// Convert an rtnetlink IPv4 destination prefix into a live route key.
/// # C: O(1)
pub(crate) fn route_key(dst: Option<([u8; 4], u8)>) -> (net::Ipv4Addr, u8) {
    let (addr, prefix_len) = dst.unwrap_or(([0, 0, 0, 0], 0));
    let prefix_len = prefix_len.min(32);
    let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
    (net::Ipv4Addr::from_u32(u32::from_be_bytes(addr) & mask), prefix_len)
}

/// Keep RTM_NEWROUTE connected to the actual IPv4 datapath in the init netns.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
fn sync_stack_route_add(
    table: u8, dst: Option<([u8; 4], u8)>, gateway: Option<[u8; 4]>, oif: u32, prefsrc: Option<[u8; 4]>,
) {
    if net::netdev::current_net_ns() != 0 { return; }
    sync_stack_route_del(table, dst, gateway, oif);
    let (dst, prefix_len) = route_key(dst);
    net::sock::stack().routes.add(net::route::RouteEntry {
        table: table as u32,
        dst,
        prefix_len,
        iface: net::NetIfaceId::from_raw(oif),
        gateway: gateway.map(|g| net::Ipv4Addr::from_u32(u32::from_be_bytes(g))),
        src_hint: prefsrc.map(|s| net::Ipv4Addr::from_u32(u32::from_be_bytes(s))),
    });
}

/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
fn sync_stack_route_add(_: u8, _: Option<([u8; 4], u8)>, _: Option<[u8; 4]>, _: u32, _: Option<[u8; 4]>) {}

/// Keep RTM_DELROUTE connected to the actual IPv4 datapath in the init netns.
/// # C: O(N routes)
#[cfg(target_os = "oxide-kernel")]
fn sync_stack_route_del(table: u8, dst: Option<([u8; 4], u8)>, _gateway: Option<[u8; 4]>, oif: u32) {
    if net::netdev::current_net_ns() != 0 { return; }
    let (dst, prefix_len) = route_key(dst);
    net::sock::stack().routes.retain(|e| {
        e.table != table as u32 || e.iface.raw() != oif || e.dst != dst || e.prefix_len != prefix_len
    });
}

/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
fn sync_stack_route_del(_: u8, _: Option<([u8; 4], u8)>, _: Option<[u8; 4]>, _: u32) {}

/// Handle RTM_NEWROUTE.
/// # C: O(N attrs + route table)
pub fn handle_newroute(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let rtm_off = Nlmsghdr::SIZE;
    if full_msg.len() < rtm_off + Rtmsg::SIZE { return build_ack(req, -22); }
    let family = full_msg[rtm_off];
    let dst_len = full_msg[rtm_off + 1];
    let table = full_msg[rtm_off + 4];
    let protocol = full_msg[rtm_off + 5];
    let scope = full_msg[rtm_off + 6];
    let kind = full_msg[rtm_off + 7];
    if family != AF_INET { return build_ack(req, -97); }
    let attrs = &full_msg[rtm_off + Rtmsg::SIZE..];
    let parsed = parse_route_attrs(attrs);
    let dst = parsed.dst.map(|a| (a, dst_len));
    if parsed.multipath.is_empty() {
        let Some(oif) = parsed.oif else { return build_ack(req, -22); };
        route_insert(RouteRow {
            ns: net::netdev::current_net_ns(), table, protocol, scope, kind, dst,
            gateway: parsed.gateway, oif_ifindex: oif, prefsrc: parsed.prefsrc,
        });
        sync_stack_route_add(table, dst, parsed.gateway, oif, parsed.prefsrc);
        crate::mcast::notify_route(false, table, protocol, scope, kind, dst, parsed.gateway, oif, parsed.prefsrc);
    } else {
        for nh in parsed.multipath {
            let gw = nh.gateway.or(parsed.gateway);
            route_insert(RouteRow {
                ns: net::netdev::current_net_ns(), table, protocol, scope, kind, dst,
                gateway: gw, oif_ifindex: nh.oif, prefsrc: parsed.prefsrc,
            });
            sync_stack_route_add(table, dst, gw, nh.oif, parsed.prefsrc);
            crate::mcast::notify_route(false, table, protocol, scope, kind, dst, gw, nh.oif, parsed.prefsrc);
        }
    }
    build_ack(req, 0)
}

/// Handle RTM_DELROUTE.
/// # C: O(N attrs + route table)
pub fn handle_delroute(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let rtm_off = Nlmsghdr::SIZE;
    if full_msg.len() < rtm_off + Rtmsg::SIZE { return build_ack(req, -22); }
    let dst_len = full_msg[rtm_off + 1];
    let table = full_msg[rtm_off + 4];
    let attrs = &full_msg[rtm_off + Rtmsg::SIZE..];
    let parsed = parse_route_attrs(attrs);
    let dst = parsed.dst.map(|a| (a, dst_len));
    let mut removed = 0usize;
    if parsed.multipath.is_empty() {
        let Some(oif) = parsed.oif else { return build_ack(req, -22); };
        removed = route_remove(net::netdev::current_net_ns(), table, dst, oif);
        if removed > 0 {
            sync_stack_route_del(table, dst, parsed.gateway, oif);
            crate::mcast::notify_route(true, table, 0, 0, 0, dst, parsed.gateway, oif, parsed.prefsrc);
        }
    } else {
        for nh in parsed.multipath {
            let gw = nh.gateway.or(parsed.gateway);
            let n = route_remove(net::netdev::current_net_ns(), table, dst, nh.oif);
            if n > 0 {
                sync_stack_route_del(table, dst, gw, nh.oif);
                crate::mcast::notify_route(true, table, 0, 0, 0, dst, gw, nh.oif, parsed.prefsrc);
            }
            removed += n;
        }
    }
    build_ack(req, if removed > 0 { 0 } else { -3 })
}
