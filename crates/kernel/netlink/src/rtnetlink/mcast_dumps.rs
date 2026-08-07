//! Rtnetlink multicast and anycast dumps from canonical stack ownership.

extern crate alloc;

use alloc::vec::Vec;

use crate::{flags, Nlmsghdr};

use super::attrs::put_nlattr;
use super::dumps::done_multi;
use super::rtnetlink_addr::IfaCacheInfo;
use super::uapi::{ifa, AF_INET, AF_INET6, Ifaddrmsg, RTM_GETANYCAST, RTM_GETMULTICAST,
    RT_SCOPE_LINK, RT_SCOPE_UNIVERSE};

fn special_addr_reply(seq: u32, pid: u32, typ: u16, family: u8, prefixlen: u8, scope: u8,
                      ifindex: u32, attr: u16, addr: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(32);
    let ifa = Ifaddrmsg {
        ifa_family: family, ifa_prefixlen: prefixlen,
        ifa_flags: net::iface_addr::IFA_F_PERMANENT as u8,
        ifa_scope: scope, ifa_index: ifindex,
    };
    let mut ifa_buf = [0u8; Ifaddrmsg::SIZE];
    ifa.write_to(&mut ifa_buf);
    body.extend_from_slice(&ifa_buf);
    put_nlattr(&mut body, attr, addr);
    let mut ci = [0u8; IfaCacheInfo::SIZE];
    IfaCacheInfo::PERMANENT.write_to(&mut ci);
    put_nlattr(&mut body, ifa::IFA_CACHEINFO, &ci);
    let hdr = Nlmsghdr {
        nlmsg_len: (Nlmsghdr::SIZE + body.len()) as u32, nlmsg_type: typ,
        nlmsg_flags: flags::NLM_F_MULTI, nlmsg_seq: seq, nlmsg_pid: pid,
    };
    let mut out = Vec::with_capacity(hdr.nlmsg_len as usize);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}

/// Dump every live interface multicast membership in one network namespace. # C: O(N groups)
pub fn handle_getmulticast_in(ns: u64, req: &Nlmsghdr, _full_msg: &[u8], _strict: bool) -> Vec<u8> {
    let stack = net::global_stack();
    let mut reply = Vec::new();
    for (iface, group) in stack.v4_multicast_snapshot_in(ns) {
        let Some(ifindex) = stack.ifaces.ifindex_in_ns(iface, ns) else { continue; };
        reply.extend_from_slice(&special_addr_reply(req.nlmsg_seq, req.nlmsg_pid, RTM_GETMULTICAST,
            AF_INET, 32, RT_SCOPE_UNIVERSE, ifindex, ifa::IFA_MULTICAST, &group.octets()));
    }
    for (iface, group) in stack.v6_multicast_snapshot_in(ns) {
        let Some(ifindex) = stack.ifaces.ifindex_in_ns(iface, ns) else { continue; };
        let scope = if group.is_link_local() { RT_SCOPE_LINK } else { RT_SCOPE_UNIVERSE };
        reply.extend_from_slice(&special_addr_reply(req.nlmsg_seq, req.nlmsg_pid, RTM_GETMULTICAST,
            AF_INET6, 128, scope, ifindex, ifa::IFA_MULTICAST, &group.0));
    }
    reply.extend_from_slice(&done_multi(req.nlmsg_seq, req.nlmsg_pid));
    reply
}

/// Dump every live IPv6 anycast address in one network namespace. # C: O(N addresses)
pub fn handle_getanycast_in(ns: u64, req: &Nlmsghdr, _full_msg: &[u8], _strict: bool) -> Vec<u8> {
    let stack = net::global_stack();
    let mut reply = Vec::new();
    for (iface, addr) in stack.v6_anycast_snapshot_in(ns) {
        let Some(ifindex) = stack.ifaces.ifindex_in_ns(iface, ns) else { continue; };
        let scope = if addr.is_link_local() { RT_SCOPE_LINK } else { RT_SCOPE_UNIVERSE };
        reply.extend_from_slice(&special_addr_reply(req.nlmsg_seq, req.nlmsg_pid, RTM_GETANYCAST,
            AF_INET6, 128, scope, ifindex, ifa::IFA_ANYCAST, &addr.0));
    }
    reply.extend_from_slice(&done_multi(req.nlmsg_seq, req.nlmsg_pid));
    reply
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use super::*;

    fn request(typ: u16) -> Nlmsghdr {
        Nlmsghdr { nlmsg_len: Nlmsghdr::SIZE as u32, nlmsg_type: typ,
            nlmsg_flags: flags::NLM_F_DUMP, nlmsg_seq: 3, nlmsg_pid: 7 }
    }

    fn has_addr(reply: &[u8], typ: u16, attr: u16, wanted: &[u8]) -> bool {
        let mut off = 0;
        while off + Nlmsghdr::SIZE <= reply.len() {
            let Some(hdr) = Nlmsghdr::parse(&reply[off..]) else { return false; };
            let len = hdr.nlmsg_len as usize;
            if len < Nlmsghdr::SIZE || off + len > reply.len() { return false; }
            if hdr.nlmsg_type == typ {
                let mut at = off + Nlmsghdr::SIZE + Ifaddrmsg::SIZE;
                while at + 4 <= off + len {
                    let attr_len = u16::from_ne_bytes([reply[at], reply[at + 1]]) as usize;
                    let attr_type = u16::from_ne_bytes([reply[at + 2], reply[at + 3]]) & 0x3fff;
                    if attr_len < 4 || at + attr_len > off + len { return false; }
                    if attr_type == attr && &reply[at + 4..at + attr_len] == wanted { return true; }
                    at += crate::nlmsg_align(attr_len);
                }
            }
            off += crate::nlmsg_align(len);
        }
        false
    }

    #[test]
    fn multicast_dump_reads_the_interface_membership_owner() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let stack = net::global_stack();
        let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), 0);
        let group = net::Ipv4Addr::new(239, 1, 2, 3);
        let member = net::mcast_filter::SocketMcast::new();
        member.change_v4(stack, iface, group, net::Ipv4Addr::LOOPBACK, true).unwrap();

        let req = request(RTM_GETMULTICAST);
        let reply = handle_getmulticast_in(0, &req, &[], false);
        assert!(has_addr(&reply, RTM_GETMULTICAST, ifa::IFA_MULTICAST, &group.octets()));
    }

    #[test]
    fn anycast_dump_reads_the_device_anycast_owner() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let stack = net::global_stack();
        let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), 0);
        stack.add_v6_addr_meta(iface,
            net::Ipv6Addr::from_segments([0x2001, 0xdb8, 1, 0, 0, 0, 0, 1]), 64, u32::MAX, u32::MAX);
        let addr = net::Ipv6Addr::from_segments([0xfe80, 0, 0, 0, 0, 0, 0, 9]);
        let socket = net::sock::InetSocket::new_udp6();
        socket.change_v6_anycast(iface.raw(), addr, true).unwrap();

        let req = request(RTM_GETANYCAST);
        let reply = handle_getanycast_in(0, &req, &[], false);
        assert!(has_addr(&reply, RTM_GETANYCAST, ifa::IFA_ANYCAST, &addr.0));
    }
}
