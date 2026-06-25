extern crate alloc;

use alloc::vec::Vec;

use crate::{flags, nlmsg_align, Nlmsghdr};
use crate::rtnetlink::{self as rt, Rtmsg, RouteRow};

fn route_dump(req: &Nlmsghdr) -> Vec<u8> {
    let mut reply: Vec<u8> = Vec::with_capacity(256);
    for r in rt::route_snapshot_ns(net::netdev::current_net_ns()).iter() {
        reply.extend_from_slice(&rt::build_newroute_reply(req.nlmsg_seq, req.nlmsg_pid, r.table, r.protocol, r.scope, r.kind, r.dst, r.gateway, r.oif_ifindex, r.prefsrc, true));
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
}
