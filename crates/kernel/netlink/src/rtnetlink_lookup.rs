extern crate alloc;

use alloc::vec::Vec;

use crate::{flags, nlmsg_align, Nlmsghdr};
use crate::rtnetlink::{self as rt, Rtmsg, RouteRow};

fn same_ecmp_group(a: &RouteRow, b: &RouteRow) -> bool {
    a.ns == b.ns && a.table == b.table && a.protocol == b.protocol
        && a.scope == b.scope && a.kind == b.kind && a.dst == b.dst
        && a.prefsrc == b.prefsrc
}

fn build_dump_row(req: &Nlmsghdr, rows: &[RouteRow]) -> Vec<u8> {
    if rows.len() == 1 {
        let r = rows[0];
        return rt::build_newroute_reply(req.nlmsg_seq, req.nlmsg_pid, r.table, r.protocol,
            r.scope, r.kind, r.dst, r.gateway, r.oif_ifindex, r.prefsrc, true);
    }
    let r = rows[0];
    let mut body: Vec<u8> = Vec::with_capacity(96);
    let mut rtm_buf = [0u8; Rtmsg::SIZE];
    Rtmsg {
        rtm_family: rt::AF_INET, rtm_dst_len: r.dst.map(|(_, n)| n).unwrap_or(0),
        rtm_table: r.table, rtm_protocol: r.protocol, rtm_scope: r.scope,
        rtm_type: r.kind, ..Rtmsg::default()
    }.write_to(&mut rtm_buf);
    body.extend_from_slice(&rtm_buf);
    if let Some((addr, _)) = r.dst { rt::put_nlattr(&mut body, rt::rta::RTA_DST, &addr); }
    let nexthops: Vec<(u32, Option<[u8; 4]>)> = rows.iter().map(|r| (r.oif_ifindex, r.gateway)).collect();
    rt::rtnetlink_route::put_multipath_attr(&mut body, &nexthops);
    if let Some(s) = r.prefsrc { rt::put_nlattr(&mut body, rt::rta::RTA_PREFSRC, &s); }
    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32, nlmsg_type: rt::RTM_NEWROUTE,
        nlmsg_flags: flags::NLM_F_MULTI, nlmsg_seq: req.nlmsg_seq, nlmsg_pid: req.nlmsg_pid,
    };
    let mut out = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}

fn route_dump(req: &Nlmsghdr) -> Vec<u8> {
    let mut reply: Vec<u8> = Vec::with_capacity(256);
    let rows = rt::route_snapshot_ns(net::netdev::current_net_ns());
    let mut used = alloc::vec![false; rows.len()];
    for i in 0..rows.len() {
        if used[i] { continue; }
        used[i] = true;
        let mut group = Vec::new();
        group.push(rows[i]);
        for j in i + 1..rows.len() {
            if !used[j] && same_ecmp_group(&rows[i], &rows[j]) {
                used[j] = true;
                group.push(rows[j]);
            }
        }
        reply.extend_from_slice(&build_dump_row(req, &group));
    }
    reply.extend_from_slice(&rt::done_multi(req.nlmsg_seq, req.nlmsg_pid));
    reply
}

fn parse_lookup(msg: &[u8]) -> Option<([u8; 4], u8)> {
    let off = Nlmsghdr::SIZE;
    if msg.len() < off + Rtmsg::SIZE { return None; }
    if msg[off] != rt::AF_INET { return None; }
    let dst_len = msg[off + 1].min(32);
    let mut p = off + Rtmsg::SIZE;
    while p + 4 <= msg.len() {
        let nla_len = u16::from_ne_bytes([msg[p], msg[p + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([msg[p + 2], msg[p + 3]]) & 0x3fff;
        if nla_len < 4 || p + nla_len > msg.len() { break; }
        if nla_type == rt::rta::RTA_DST && nla_len == 8 {
            let q = &msg[p + 4..p + 8];
            return Some(([q[0], q[1], q[2], q[3]], dst_len));
        }
        p += nlmsg_align(nla_len);
    }
    Some(([0, 0, 0, 0], 0))
}

fn matches(row: &RouteRow, dst: [u8; 4]) -> bool {
    let Some((net, prefix)) = row.dst else { return true; };
    let bits = prefix.min(32);
    let mask = if bits == 0 { 0 } else { !0u32 << (32 - bits) };
    (u32::from_be_bytes(dst) & mask) == (u32::from_be_bytes(net) & mask)
}

fn lookup_route(dst: [u8; 4]) -> Option<RouteRow> {
    rt::route_snapshot_ns(net::netdev::current_net_ns()).into_iter()
        .filter(|r| matches(r, dst))
        .max_by_key(|r| r.dst.map(|(_, p)| p).unwrap_or(0))
}

/// RTM_GETROUTE supports both dump requests and one-shot FIB lookup requests.
/// # C: O(N routes + N attrs)
pub fn handle_getroute(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    if req.nlmsg_flags & flags::NLM_F_DUMP != 0 { return route_dump(req); }
    let Some((dst, len)) = parse_lookup(full_msg) else { return rt::nlmsg_ack_pub(req, -22); };
    let Some(r) = lookup_route(dst) else { return rt::nlmsg_ack_pub(req, -101); };
    let reply_dst = if r.dst.is_some() { r.dst } else { Some((dst, len)) };
    rt::build_newroute_reply(req.nlmsg_seq, req.nlmsg_pid, r.table, r.protocol, r.scope, r.kind, reply_dst, r.gateway, r.oif_ifindex, r.prefsrc, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtnetlink::{route_insert, route_remove, RT_TABLE_MAIN, RTPROT_STATIC, RT_SCOPE_LINK, RTN_UNICAST};

    #[test]
    fn lookup_prefers_longest_prefix() {
        let req = Nlmsghdr { nlmsg_len: 36, nlmsg_type: rt::RTM_GETROUTE, nlmsg_flags: crate::flags::NLM_F_REQUEST, nlmsg_seq: 9, nlmsg_pid: 4 };
        route_insert(RouteRow { ns: 0, table: RT_TABLE_MAIN, protocol: RTPROT_STATIC, scope: RT_SCOPE_LINK, kind: RTN_UNICAST, dst: Some(([10, 0, 0, 0], 8)), gateway: None, oif_ifindex: 11, prefsrc: None });
        route_insert(RouteRow { ns: 0, table: RT_TABLE_MAIN, protocol: RTPROT_STATIC, scope: RT_SCOPE_LINK, kind: RTN_UNICAST, dst: Some(([10, 1, 0, 0], 16)), gateway: None, oif_ifindex: 12, prefsrc: None });
        let msg = lookup_msg(&req, [10, 1, 2, 3], 32);
        let out = handle_getroute(&req, &msg);
        assert_eq!(route_remove(0, RT_TABLE_MAIN, Some(([10, 0, 0, 0], 8)), 11), 1);
        assert_eq!(route_remove(0, RT_TABLE_MAIN, Some(([10, 1, 0, 0], 16)), 12), 1);
        assert_eq!(u16::from_ne_bytes([out[4], out[5]]), rt::RTM_NEWROUTE);
        assert_eq!(out[Nlmsghdr::SIZE + 1], 16);
        assert_eq!(attr_u32(&out, rt::rta::RTA_OIF), Some(12));
    }

    #[test]
    fn dump_groups_equal_cost_routes_as_multipath() {
        let dst = Some(([203, 0, 113, 0], 24));
        let _ = route_remove(0, RT_TABLE_MAIN, dst, 8811);
        let _ = route_remove(0, RT_TABLE_MAIN, dst, 8812);
        route_insert(RouteRow { ns: 0, table: RT_TABLE_MAIN, protocol: RTPROT_STATIC,
            scope: RT_SCOPE_LINK, kind: RTN_UNICAST, dst, gateway: Some([192, 0, 2, 1]),
            oif_ifindex: 8811, prefsrc: None });
        route_insert(RouteRow { ns: 0, table: RT_TABLE_MAIN, protocol: RTPROT_STATIC,
            scope: RT_SCOPE_LINK, kind: RTN_UNICAST, dst, gateway: Some([192, 0, 2, 2]),
            oif_ifindex: 8812, prefsrc: None });
        let req = Nlmsghdr { nlmsg_len: 28, nlmsg_type: rt::RTM_GETROUTE,
            nlmsg_flags: crate::flags::NLM_F_DUMP, nlmsg_seq: 10, nlmsg_pid: 4 };
        let out = handle_getroute(&req, &[]);
        assert_eq!(route_remove(0, RT_TABLE_MAIN, dst, 8811), 1);
        assert_eq!(route_remove(0, RT_TABLE_MAIN, dst, 8812), 1);
        assert!(dump_has_multipath_dst(&out, [203, 0, 113, 0]));
    }

    fn lookup_msg(req: &Nlmsghdr, dst: [u8; 4], prefix: u8) -> Vec<u8> {
        let mut out = alloc::vec![0u8; Nlmsghdr::SIZE + Rtmsg::SIZE];
        let mut hdr = *req;
        hdr.nlmsg_len = (Nlmsghdr::SIZE + Rtmsg::SIZE + 8) as u32;
        hdr.write_to(&mut out[..Nlmsghdr::SIZE]);
        out[Nlmsghdr::SIZE] = rt::AF_INET;
        out[Nlmsghdr::SIZE + 1] = prefix;
        rt::put_nlattr(&mut out, rt::rta::RTA_DST, &dst);
        out
    }

    fn attr_u32(msg: &[u8], ty: u16) -> Option<u32> {
        let mut p = Nlmsghdr::SIZE + Rtmsg::SIZE;
        while p + 8 <= msg.len() {
            let nla_len = u16::from_ne_bytes([msg[p], msg[p + 1]]) as usize;
            let nla_type = u16::from_ne_bytes([msg[p + 2], msg[p + 3]]) & 0x3fff;
            if nla_len < 4 || p + nla_len > msg.len() { break; }
            if nla_type == ty && nla_len == 8 {
                return Some(u32::from_ne_bytes(msg[p + 4..p + 8].try_into().ok()?));
            }
            p += nlmsg_align(nla_len);
        }
        None
    }

    fn dump_has_multipath_dst(msg: &[u8], dst: [u8; 4]) -> bool {
        let mut off = 0;
        while off + Nlmsghdr::SIZE <= msg.len() {
            let len = u32::from_ne_bytes(msg[off..off + 4].try_into().ok().unwrap()) as usize;
            let ty = u16::from_ne_bytes([msg[off + 4], msg[off + 5]]);
            if len < Nlmsghdr::SIZE || off + len > msg.len() { break; }
            if ty == rt::RTM_NEWROUTE {
                let row = &msg[off..off + len];
                if attr_bytes(row, rt::rta::RTA_DST) == Some(dst.as_slice())
                    && attr_bytes(row, rt::rta::RTA_MULTIPATH).is_some() {
                    return true;
                }
            }
            off += nlmsg_align(len);
        }
        false
    }

    fn attr_bytes(msg: &[u8], ty: u16) -> Option<&[u8]> {
        let mut p = Nlmsghdr::SIZE + Rtmsg::SIZE;
        while p + 4 <= msg.len() {
            let nla_len = u16::from_ne_bytes([msg[p], msg[p + 1]]) as usize;
            let nla_type = u16::from_ne_bytes([msg[p + 2], msg[p + 3]]) & 0x3fff;
            if nla_len < 4 || p + nla_len > msg.len() { break; }
            if nla_type == ty { return Some(&msg[p + 4..p + nla_len]); }
            p += nlmsg_align(nla_len);
        }
        None
    }
}
