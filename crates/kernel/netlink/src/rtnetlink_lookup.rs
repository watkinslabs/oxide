extern crate alloc;

use alloc::vec::Vec;

use crate::{flags, nlmsg_align, Nlmsghdr};
use crate::rtnetlink::{self as rt, Rtmsg, RouteRow};

fn same_ecmp_group(a: &RouteRow, b: &RouteRow) -> bool {
    a.ns == b.ns && a.table == b.table && a.protocol == b.protocol
        && a.scope == b.scope && a.kind == b.kind && a.dst == b.dst
        && a.prefsrc == b.prefsrc && a.metric == b.metric && a.mtu == b.mtu
        && a.flags == b.flags
}

fn build_dump_row(req: &Nlmsghdr, rows: &[RouteRow]) -> Vec<u8> {
    if rows.len() == 1 {
        let r = rows[0];
        return rt::build_newroute_row_reply(req.nlmsg_seq, req.nlmsg_pid, r, true);
    }
    let r = rows[0];
    let mut body: Vec<u8> = Vec::with_capacity(96);
    let mut rtm_buf = [0u8; Rtmsg::SIZE];
    Rtmsg {
        rtm_family: rt::AF_INET, rtm_dst_len: r.dst.map(|(_, n)| n).unwrap_or(0),
        rtm_table: if r.table <= u8::MAX as u32 { r.table as u8 } else { 0 },
        rtm_protocol: r.protocol, rtm_scope: r.scope,
        rtm_type: r.kind, rtm_flags: r.flags, ..Rtmsg::default()
    }.write_to(&mut rtm_buf);
    body.extend_from_slice(&rtm_buf);
    if let Some((addr, _)) = r.dst { rt::put_nlattr(&mut body, rt::rta::RTA_DST, &addr); }
    let nexthops: Vec<rt::rtnetlink_route::RouteNexthop> = rows.iter().map(|r|
        rt::rtnetlink_route::RouteNexthop {
            oif: rt::route_oif_for_abi(r.ns, r.oif_ifindex), gateway: r.gateway, flags: r.nh_flags,
            hops: r.weight.saturating_sub(1).min(u8::MAX as u16) as u8,
        }).collect();
    rt::rtnetlink_route::put_multipath_attr(&mut body, &nexthops);
    if let Some(s) = r.prefsrc { rt::put_nlattr(&mut body, rt::rta::RTA_PREFSRC, &s); }
    if r.metric != 0 { rt::put_nlattr_u32(&mut body, rt::rta::RTA_PRIORITY, r.metric); }
    if r.table > u8::MAX as u32 { rt::put_nlattr_u32(&mut body, rt::rta::RTA_TABLE, r.table); }
    if let Some(mtu) = r.mtu {
        let mut metrics = Vec::new();
        rt::put_nlattr_u32(&mut metrics, 2, mtu);
        rt::put_nlattr(&mut body, rt::rta::RTA_METRICS, &metrics);
    }
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

fn route_dump(net_ns: u64, req: &Nlmsghdr) -> Vec<u8> {
    let mut reply: Vec<u8> = Vec::with_capacity(256);
    let rows = rt::route_snapshot_ns(net_ns);
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
    let dst_len = msg[off + 1];
    if dst_len > 32 { return None; }
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

/// RTM_GETROUTE supports both dump requests and one-shot FIB lookup requests.
/// # C: O(N routes + N attrs)
pub fn handle_getroute(net_ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    if req.nlmsg_flags & flags::NLM_F_DUMP != 0 { return route_dump(net_ns, req); }
    let Some((dst, len)) = parse_lookup(full_msg) else { return rt::nlmsg_ack_pub(req, -22); };
    let Some(r) = rt::route_lookup_ns(net_ns, dst) else {
        return rt::nlmsg_ack_pub(req, -101);
    };
    let reply_dst = if r.dst.is_some() { r.dst } else { Some((dst, len)) };
    let mut reply = r;
    reply.dst = reply_dst;
    rt::build_newroute_row_reply(req.nlmsg_seq, req.nlmsg_pid, reply, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtnetlink::{route_insert, route_remove, RT_TABLE_MAIN, RTPROT_STATIC, RT_SCOPE_LINK, RTN_UNICAST};

    #[test]
    fn lookup_prefers_longest_prefix() {
        let req = Nlmsghdr { nlmsg_len: 36, nlmsg_type: rt::RTM_GETROUTE, nlmsg_flags: crate::flags::NLM_F_REQUEST, nlmsg_seq: 9, nlmsg_pid: 4 };
        route_insert(RouteRow { ns: 0, table: RT_TABLE_MAIN as u32, protocol: RTPROT_STATIC, scope: RT_SCOPE_LINK, kind: RTN_UNICAST, dst: Some(([10, 0, 0, 0], 8)), gateway: None, oif_ifindex: 11, prefsrc: None, metric: 0, mtu: None, flags: 0, weight: 1, nh_flags: 0 });
        route_insert(RouteRow { ns: 0, table: RT_TABLE_MAIN as u32, protocol: RTPROT_STATIC, scope: RT_SCOPE_LINK, kind: RTN_UNICAST, dst: Some(([10, 1, 0, 0], 16)), gateway: None, oif_ifindex: 12, prefsrc: None, metric: 0, mtu: None, flags: 0, weight: 1, nh_flags: 0 });
        let msg = lookup_msg(&req, [10, 1, 2, 3], 32);
        let out = handle_getroute(0, &req, &msg);
        assert_eq!(route_remove(0, RT_TABLE_MAIN as u32, Some(([10, 0, 0, 0], 8)), 11, None), 1);
        assert_eq!(route_remove(0, RT_TABLE_MAIN as u32, Some(([10, 1, 0, 0], 16)), 12, None), 1);
        assert_eq!(u16::from_ne_bytes([out[4], out[5]]), rt::RTM_NEWROUTE);
        assert_eq!(out[Nlmsghdr::SIZE + 1], 16);
        assert_eq!(attr_u32(&out, rt::rta::RTA_OIF), Some(12));
    }

    #[test]
    fn dump_groups_equal_cost_routes_as_multipath() {
        let dst = Some(([203, 0, 113, 0], 24));
        let _ = route_remove(0, RT_TABLE_MAIN as u32, dst, 8811, Some([192, 0, 2, 1]));
        let _ = route_remove(0, RT_TABLE_MAIN as u32, dst, 8812, Some([192, 0, 2, 2]));
        route_insert(RouteRow { ns: 0, table: RT_TABLE_MAIN as u32, protocol: RTPROT_STATIC,
            scope: RT_SCOPE_LINK, kind: RTN_UNICAST, dst, gateway: Some([192, 0, 2, 1]),
            oif_ifindex: 8811, prefsrc: None, metric: 0, mtu: None, flags: 0, weight: 1, nh_flags: 0 });
        route_insert(RouteRow { ns: 0, table: RT_TABLE_MAIN as u32, protocol: RTPROT_STATIC,
            scope: RT_SCOPE_LINK, kind: RTN_UNICAST, dst, gateway: Some([192, 0, 2, 2]),
            oif_ifindex: 8812, prefsrc: None, metric: 0, mtu: None, flags: 0, weight: 1, nh_flags: 0 });
        let req = Nlmsghdr { nlmsg_len: 28, nlmsg_type: rt::RTM_GETROUTE,
            nlmsg_flags: crate::flags::NLM_F_DUMP, nlmsg_seq: 10, nlmsg_pid: 4 };
        let out = handle_getroute(0, &req, &[]);
        assert_eq!(route_remove(0, RT_TABLE_MAIN as u32, dst, 8811, Some([192, 0, 2, 1])), 1);
        assert_eq!(route_remove(0, RT_TABLE_MAIN as u32, dst, 8812, Some([192, 0, 2, 2])), 1);
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
