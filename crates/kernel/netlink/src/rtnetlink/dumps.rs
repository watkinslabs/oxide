extern crate alloc;

use alloc::vec::Vec;

use crate::{flags, Nlmsghdr};

use super::attrs::{put_nlattr, put_nlattr_str, put_nlattr_u32, put_nlattr_u8};
use super::iface::ifaces_snapshot_in;
use super::rtnetlink_addr::IfaCacheInfo;
use super::rtnetlink_link::{put_link_stats64, LinkStats64};
use super::uapi::{
    ifa, ifla, iff, AF_INET, AF_INET6, Ifaddrmsg, Ifinfomsg,
    RTM_NEWADDR, RTM_NEWLINK, RT_SCOPE_HOST, RT_SCOPE_LINK, RT_SCOPE_UNIVERSE,
};

const IF_OPER_UP: u8 = 6;
const IF_OPER_DOWN: u8 = 2;

/// Build a single RTM_NEWLINK reply for one iface.
/// # C: O(N attrs)
pub(crate) fn build_newlink_reply(
    seq: u32, pid: u32, ifindex: i32, name: &str, mac: [u8; 6], broadcast: &[u8], mtu: u32, is_loopback: bool,
    flags: u32, stats: LinkStats64, multi: bool,
) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(128);
    let mut ifi = Ifinfomsg::default();
    ifi.ifi_family = 0;
    ifi.ifi_type = if is_loopback { net::uapi::ARPHRD_LOOPBACK } else { net::uapi::ARPHRD_ETHER };
    ifi.ifi_index = ifindex;
    ifi.ifi_flags = flags;
    ifi.ifi_change = 0;
    let mut ifi_buf = [0u8; Ifinfomsg::SIZE];
    ifi.write_to(&mut ifi_buf);
    body.extend_from_slice(&ifi_buf);

    put_nlattr_str(&mut body, ifla::IFLA_IFNAME, name);
    put_nlattr(&mut body, ifla::IFLA_ADDRESS, &mac);
    put_nlattr(&mut body, ifla::IFLA_BROADCAST, broadcast);
    put_nlattr_u32(&mut body, ifla::IFLA_MTU, mtu);
    put_nlattr_u32(&mut body, ifla::IFLA_TXQLEN, 1000);
    let carrier = flags & iff::IFF_RUNNING != 0;
    let operstate = if carrier { IF_OPER_UP } else { IF_OPER_DOWN };
    put_nlattr_u8(&mut body, ifla::IFLA_OPERSTATE, operstate);
    put_nlattr_u8(&mut body, ifla::IFLA_LINKMODE, 0);
    put_nlattr_u8(&mut body, ifla::IFLA_CARRIER, carrier as u8);
    put_link_stats64(&mut body, stats);

    let total = Nlmsghdr::SIZE + body.len();
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32,
        nlmsg_type: RTM_NEWLINK,
        nlmsg_flags: if multi { flags::NLM_F_MULTI } else { 0 },
        nlmsg_seq: seq,
        nlmsg_pid: pid,
    };
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}

/// NLMSG_DONE terminator for a multi-part dump.
/// # C: O(1)
pub fn done_multi(seq: u32, pid: u32) -> Vec<u8> {
    let mut v = alloc::vec![0u8; Nlmsghdr::SIZE + 4];
    let mut done = Nlmsghdr::done(seq, pid);
    done.nlmsg_len = (Nlmsghdr::SIZE + 4) as u32;
    done.nlmsg_flags = flags::NLM_F_MULTI;
    done.write_to(&mut v[..Nlmsghdr::SIZE]);
    v
}

/// Handle a single RTM_GETLINK request.
/// # C: O(N_ifaces)
pub fn handle_getlink(req: &Nlmsghdr) -> Vec<u8> {
    handle_getlink_in(net::netdev::current_net_ns(), req)
}

/// Handle RTM_GETLINK in the socket's captured network namespace.
/// # C: O(N_ifaces)
pub fn handle_getlink_in(ns: u64, req: &Nlmsghdr) -> Vec<u8> {
    let mut reply: Vec<u8> = Vec::with_capacity(256);
    let entries = ifaces_snapshot_in(ns);
    for (id, name, mac, broadcast, mtu, is_lo, flags, stats) in entries.iter() {
        let one = build_newlink_reply(
            req.nlmsg_seq, req.nlmsg_pid, *id as i32, name, *mac, &broadcast.bytes[..broadcast.len as usize], *mtu, *is_lo, *flags, *stats, true,
        );
        reply.extend_from_slice(&one);
    }
    #[cfg(feature = "debug-netlink")]
    {
        klog::write_raw(b"[NL-GETLINK ns=");
        klog::write_dec_u64(ns);
        klog::write_raw(b" n=");
        klog::write_dec_u64(entries.len() as u64);
        for (id, name, _mac, _bc, _mtu, is_lo, flags, _st) in entries.iter() {
            klog::write_raw(b" ifidx="); klog::write_dec_u64(*id as u64);
            klog::write_raw(b":"); klog::write_raw(name.as_bytes());
            klog::write_raw(b"/lo="); klog::write_dec_u64(*is_lo as u64);
            klog::write_raw(b"/fl="); klog::write_dec_u64(*flags as u64);
        }
        klog::write_raw(b"]\n");
    }
    reply.extend_from_slice(&done_multi(req.nlmsg_seq, req.nlmsg_pid));
    reply
}

/// Build a single RTM_NEWADDR reply for one iface's IPv4 address.
/// # C: O(N attrs)
pub(crate) fn build_newaddr_reply(
    seq: u32, pid: u32, ifindex: i32, label: &str, addr: [u8; 4], peer: Option<[u8; 4]>,
    prefixlen: u8, scope: u8, flags: u32, cacheinfo: IfaCacheInfo, multi: bool,
) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(96);
    let ifa = Ifaddrmsg {
        ifa_family: AF_INET,
        ifa_prefixlen: prefixlen,
        ifa_flags: flags as u8,
        ifa_scope: scope,
        ifa_index: ifindex as u32,
    };
    let mut ifa_buf = [0u8; Ifaddrmsg::SIZE];
    ifa.write_to(&mut ifa_buf);
    body.extend_from_slice(&ifa_buf);

    put_nlattr(&mut body, ifa::IFA_LOCAL, &addr);
    put_nlattr(&mut body, ifa::IFA_ADDRESS, &peer.unwrap_or(addr));
    if peer.is_none() && scope != RT_SCOPE_HOST {
        let host_mask = if prefixlen >= 32 { 0u32 } else { (1u32 << (32 - prefixlen)) - 1 };
        let a = u32::from_be_bytes(addr);
        let bcast = ((a & !host_mask) | host_mask).to_be_bytes();
        put_nlattr(&mut body, ifa::IFA_BROADCAST, &bcast);
    }
    put_nlattr_str(&mut body, ifa::IFA_LABEL, label);
    put_nlattr_u32(&mut body, ifa::IFA_FLAGS, flags);
    let mut ci = [0u8; IfaCacheInfo::SIZE];
    cacheinfo.write_to(&mut ci);
    put_nlattr(&mut body, ifa::IFA_CACHEINFO, &ci);

    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32,
        nlmsg_type: RTM_NEWADDR,
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

/// Build a single RTM_NEWADDR reply for one iface's IPv6 address.
/// # C: O(N attrs)
pub(crate) fn build_newaddr6_reply(
    seq: u32, pid: u32, ifindex: i32, label: &str, addr: [u8; 16], prefixlen: u8, scope: u8,
    flags: u32, cacheinfo: IfaCacheInfo, multi: bool,
) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(96);
    let ifa = Ifaddrmsg {
        ifa_family: AF_INET6,
        ifa_prefixlen: prefixlen,
        ifa_flags: flags as u8,
        ifa_scope: scope,
        ifa_index: ifindex as u32,
    };
    let mut ifa_buf = [0u8; Ifaddrmsg::SIZE];
    ifa.write_to(&mut ifa_buf);
    body.extend_from_slice(&ifa_buf);
    put_nlattr(&mut body, ifa::IFA_LOCAL, &addr);
    put_nlattr(&mut body, ifa::IFA_ADDRESS, &addr);
    put_nlattr_str(&mut body, ifa::IFA_LABEL, label);
    put_nlattr_u32(&mut body, ifa::IFA_FLAGS, flags);
    let mut ci = [0u8; IfaCacheInfo::SIZE];
    cacheinfo.write_to(&mut ci);
    put_nlattr(&mut body, ifa::IFA_CACHEINFO, &ci);

    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32,
        nlmsg_type: RTM_NEWADDR,
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

/// RTM_GETADDR dump.
/// # C: O(N_ifaces)
pub fn handle_getaddr(req: &Nlmsghdr) -> Vec<u8> {
    handle_getaddr_in(net::netdev::current_net_ns(), req)
}

/// Handle RTM_GETADDR in the socket's captured network namespace.
/// # C: O(N_ifaces)
pub fn handle_getaddr_in(ns: u64, req: &Nlmsghdr) -> Vec<u8> {
    let mut reply: Vec<u8> = Vec::with_capacity(256);
    let ifaces = ifaces_snapshot_in(ns);
    for row in super::rtnetlink_addr::addr_snapshot_ns(ns).iter() {
        let Some(ifindex) = net::global_stack().ifaces.ifindex_in_ns(
            net::NetIfaceId::from_raw(row.ifindex), ns) else { continue; };
        let name = match ifaces.iter().find(|(id, _, _, _, _, _, _, _)| *id == ifindex) {
            Some((_, n, _, _, _, _, _, _)) => n.as_str(),
            None => continue,
        };
        let one = build_newaddr_reply(
            req.nlmsg_seq, req.nlmsg_pid, ifindex as i32, name, row.addr, row.peer,
            row.prefixlen, row.scope, row.flags, row.cacheinfo, true,
        );
        reply.extend_from_slice(&one);
    }
    #[cfg(target_os = "oxide-kernel")]
    for (iface, row) in net::sock::stack().v6_addr_snapshot_in(ns) {
        let Some(ifindex) = net::global_stack().ifaces.ifindex_in_ns(iface, ns) else { continue; };
        let name = match ifaces.iter().find(|(id, _, _, _, _, _, _, _)| *id == ifindex) {
            Some((_, n, _, _, _, _, _, _)) => n.as_str(),
            None => continue,
        };
        let addr = row.addr;
        let scope = if addr.is_loopback() { RT_SCOPE_HOST }
        else if addr.is_link_local() { RT_SCOPE_LINK }
        else { RT_SCOPE_UNIVERSE };
        let cacheinfo = IfaCacheInfo { preferred: row.preferred, valid: row.valid, cstamp: 0, tstamp: 0 };
        reply.extend_from_slice(&build_newaddr6_reply(
            req.nlmsg_seq, req.nlmsg_pid, ifindex as i32, name, addr.0, row.prefixlen, scope,
            row.flags(), cacheinfo, true,
        ));
    }
    reply.extend_from_slice(&done_multi(req.nlmsg_seq, req.nlmsg_pid));
    reply
}
