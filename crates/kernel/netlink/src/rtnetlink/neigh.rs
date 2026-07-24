extern crate alloc;

use alloc::vec::Vec;

use crate::{flags, nlmsg_align, Nlmsghdr};

use super::ack::build_ack;
use super::attrs::put_nlattr;
use super::dumps::done_multi;
use super::uapi::{nda, nud, Ndmsg, AF_INET, AF_INET6, RTM_NEWNEIGH, RTN_UNICAST};

// rtnetlink acks carry a negative errno in the NLMSG_ERROR payload; the whole
// module uses raw negatives (see `addr_ops`), named here at the boundary.
const EINVAL: i32 = -22;
const ENODEV: i32 = -19;
const ENOENT: i32 = -2;
const EAFNOSUPPORT: i32 = -97;
const AF_UNSPEC: u8 = 0;
const IPV4_ADDR_LEN: usize = 4;
const IPV6_ADDR_LEN: usize = 16;
const LLADDR_LEN: usize = 6;

/// Map the canonical IPv4 NUD state onto Linux `ndm_state` (`NUD_*`). # C: O(1)
fn nud_state(state: net::arp::NudState) -> u16 {
    match state {
        net::arp::NudState::Incomplete => nud::NUD_INCOMPLETE,
        net::arp::NudState::Reachable => nud::NUD_REACHABLE,
        net::arp::NudState::Stale => nud::NUD_STALE,
        net::arp::NudState::Delay => nud::NUD_DELAY,
        net::arp::NudState::Probe => nud::NUD_PROBE,
        net::arp::NudState::Failed => nud::NUD_FAILED,
        net::arp::NudState::Permanent => nud::NUD_PERMANENT,
    }
}

/// Build one RTM_NEWNEIGH message for a single neighbour entry. # C: O(N attrs)
fn build_newneigh_reply(seq: u32, pid: u32, family: u8, ifindex: i32, ndm_state: u16,
    dst: &[u8], mac: Option<[u8; LLADDR_LEN]>, multi: bool) -> Vec<u8>
{
    let mut body: Vec<u8> = Vec::with_capacity(48);
    let ndm = Ndmsg { ndm_family: family, __pad1: 0, __pad2: 0, ndm_ifindex: ifindex,
        ndm_state, ndm_flags: 0, ndm_type: RTN_UNICAST };
    let mut ndm_buf = [0u8; Ndmsg::SIZE];
    ndm.write_to(&mut ndm_buf);
    body.extend_from_slice(&ndm_buf);
    put_nlattr(&mut body, nda::NDA_DST, dst);
    if let Some(m) = mac { put_nlattr(&mut body, nda::NDA_LLADDR, &m); }

    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32,
        nlmsg_type: RTM_NEWNEIGH,
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

/// Handle RTM_GETNEIGH in the socket's captured namespace, dumping the
/// canonical ARP (v4) + NDP (v6) caches. # C: O(N neighbours)
pub fn handle_getneigh_in(ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    // Optional `ip neigh show dev X` / family filters carried in the ndmsg.
    let filter = Ndmsg::parse(&full_msg[Nlmsghdr::SIZE.min(full_msg.len())..]);
    let want_family = filter.map(|n| n.ndm_family).unwrap_or(AF_UNSPEC);
    let want_ifindex = filter.map(|n| n.ndm_ifindex).unwrap_or(0);
    let match_ifindex = |ifindex: u32| want_ifindex == 0 || want_ifindex == ifindex as i32;

    let stack = net::global_stack();
    let mut reply: Vec<u8> = Vec::with_capacity(256);
    if want_family == AF_UNSPEC || want_family == AF_INET {
        for row in stack.neigh_snapshot_v4_ns(ns) {
            if !match_ifindex(row.ifindex) { continue; }
            reply.extend_from_slice(&build_newneigh_reply(
                req.nlmsg_seq, req.nlmsg_pid, AF_INET, row.ifindex as i32,
                nud_state(row.state), &row.ip.octets(), row.mac.map(|m| m.0), true));
        }
    }
    if want_family == AF_UNSPEC || want_family == AF_INET6 {
        for (ifindex, ip, mac) in stack.neigh_snapshot_v6_ns(ns) {
            if !match_ifindex(ifindex) { continue; }
            reply.extend_from_slice(&build_newneigh_reply(
                req.nlmsg_seq, req.nlmsg_pid, AF_INET6, ifindex as i32,
                nud::NUD_REACHABLE, &ip.0, Some(mac.0), true));
        }
    }
    reply.extend_from_slice(&done_multi(req.nlmsg_seq, req.nlmsg_pid));
    reply
}

struct NeighAttrs {
    dst: Vec<u8>,
    lladdr: Option<[u8; LLADDR_LEN]>,
}

/// Parse NDA_DST + NDA_LLADDR from an RTM_*NEIGH request. # C: O(N attrs)
fn parse_neigh_attrs(attrs: &[u8]) -> Option<NeighAttrs> {
    let mut off = 0;
    let mut dst = None;
    let mut lladdr = None;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if nla_len < 4 || off + nla_len > attrs.len() { return None; }
        let next = off.checked_add(nlmsg_align(nla_len))?;
        if next > attrs.len() { return None; }
        let payload = &attrs[off + 4..off + nla_len];
        if nla_type == nda::NDA_DST {
            dst = Some(payload.to_vec());
        } else if nla_type == nda::NDA_LLADDR && payload.len() == LLADDR_LEN {
            let mut m = [0u8; LLADDR_LEN];
            m.copy_from_slice(payload);
            lladdr = Some(m);
        } else if nla_type == nda::NDA_LLADDR {
            return None;
        }
        off = next;
    }
    Some(NeighAttrs { dst: dst?, lladdr })
}

fn admin_errno(err: net::stack::NeighAdminError) -> i32 {
    match err {
        net::stack::NeighAdminError::NoDev => ENODEV,
        net::stack::NeighAdminError::NotFound => ENOENT,
    }
}

/// Handle RTM_NEWNEIGH: add/update a neighbour in the canonical cache. # C: O(log N)
pub fn handle_newneigh_in(ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let ndm_off = Nlmsghdr::SIZE;
    let Some(ndm) = Ndmsg::parse(&full_msg[ndm_off.min(full_msg.len())..]) else {
        return build_ack(req, EINVAL);
    };
    if ndm.ndm_ifindex <= 0 { return build_ack(req, EINVAL); }
    let Some(attrs) = parse_neigh_attrs(&full_msg[ndm_off + Ndmsg::SIZE..]) else {
        return build_ack(req, EINVAL);
    };
    // `ip neigh add` without an explicit nud state installs a PERMANENT entry.
    let permanent = ndm.ndm_state == 0 || (ndm.ndm_state & nud::NUD_PERMANENT) != 0;
    let Some(mac) = attrs.lladdr else { return build_ack(req, EINVAL); };
    let stack = net::global_stack();
    let result = match ndm.ndm_family {
        AF_INET => {
            if attrs.dst.len() != IPV4_ADDR_LEN { return build_ack(req, EINVAL); }
            let ip = net::Ipv4Addr::from_u32(u32::from_be_bytes(
                [attrs.dst[0], attrs.dst[1], attrs.dst[2], attrs.dst[3]]));
            stack.neigh_add_v4(ns, ndm.ndm_ifindex as u32, ip, net::MacAddr(mac), permanent)
        }
        AF_INET6 => {
            if attrs.dst.len() != IPV6_ADDR_LEN { return build_ack(req, EINVAL); }
            let mut raw = [0u8; IPV6_ADDR_LEN];
            raw.copy_from_slice(&attrs.dst);
            stack.neigh_add_v6(ns, ndm.ndm_ifindex as u32, net::Ipv6Addr(raw), net::MacAddr(mac))
        }
        _ => return build_ack(req, EAFNOSUPPORT),
    };
    match result { Ok(()) => build_ack(req, 0), Err(e) => build_ack(req, admin_errno(e)) }
}

/// Handle RTM_DELNEIGH: remove a neighbour from the canonical cache. # C: O(log N)
pub fn handle_delneigh_in(ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let ndm_off = Nlmsghdr::SIZE;
    let Some(ndm) = Ndmsg::parse(&full_msg[ndm_off.min(full_msg.len())..]) else {
        return build_ack(req, EINVAL);
    };
    if ndm.ndm_ifindex <= 0 { return build_ack(req, EINVAL); }
    let Some(attrs) = parse_neigh_attrs(&full_msg[ndm_off + Ndmsg::SIZE..]) else {
        return build_ack(req, EINVAL);
    };
    let stack = net::global_stack();
    let result = match ndm.ndm_family {
        AF_INET => {
            if attrs.dst.len() != IPV4_ADDR_LEN { return build_ack(req, EINVAL); }
            let ip = net::Ipv4Addr::from_u32(u32::from_be_bytes(
                [attrs.dst[0], attrs.dst[1], attrs.dst[2], attrs.dst[3]]));
            stack.neigh_del_v4(ns, ndm.ndm_ifindex as u32, ip)
        }
        AF_INET6 => {
            if attrs.dst.len() != IPV6_ADDR_LEN { return build_ack(req, EINVAL); }
            let mut raw = [0u8; IPV6_ADDR_LEN];
            raw.copy_from_slice(&attrs.dst);
            stack.neigh_del_v6(ns, ndm.ndm_ifindex as u32, net::Ipv6Addr(raw))
        }
        _ => return build_ack(req, EAFNOSUPPORT),
    };
    match result { Ok(()) => build_ack(req, 0), Err(e) => build_ack(req, admin_errno(e)) }
}
