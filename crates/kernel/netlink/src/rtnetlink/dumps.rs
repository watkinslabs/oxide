extern crate alloc;

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::{flags, Nlmsghdr};

use super::attrs::{put_nlattr, put_nlattr_i32, put_nlattr_str, put_nlattr_u32, put_nlattr_u8};
use super::iface::ifaces_snapshot_in;
use super::rtnetlink_addr::IfaCacheInfo;
use super::rtnetlink_link::{put_link_stats64, LinkStats64};
use super::uapi::{
    ifa, if_oper, ifla, iff, AF_INET, AF_INET6, Ifaddrmsg, Ifinfomsg,
    RTM_NEWADDR, RTM_NEWLINK, RT_SCOPE_HOST, RT_SCOPE_LINK, RT_SCOPE_UNIVERSE,
};

/// Build a single RTM_NEWLINK reply for one iface.
/// # C: O(N attrs)
pub(crate) fn build_newlink_reply(
    seq: u32, pid: u32, ifindex: i32, name: &str, mac: [u8; 6], broadcast: &[u8], mtu: u32, is_loopback: bool,
    flags: u32, stats: LinkStats64, multi: bool, target_nsid: Option<i32>,
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

    if let Some(nsid) = target_nsid { put_nlattr_i32(&mut body, ifla::IFLA_TARGET_NETNSID, nsid); }
    put_nlattr_str(&mut body, ifla::IFLA_IFNAME, name);
    put_nlattr(&mut body, ifla::IFLA_ADDRESS, &mac);
    put_nlattr(&mut body, ifla::IFLA_BROADCAST, broadcast);
    put_nlattr_u32(&mut body, ifla::IFLA_MTU, mtu);
    put_nlattr_u32(&mut body, ifla::IFLA_TXQLEN, 1000);
    // The reference reports these two, it does not store them: `dev_get_flags`
    // derives them while the device is running — `IFF_RUNNING` from the
    // operational state and `IFF_LOWER_UP` from the driver's carrier. Reporting
    // the stored word verbatim left `IFF_LOWER_UP` permanently clear, which is
    // the bit a network manager reads to decide a link can carry traffic; it
    // therefore held the device at "unavailable" with `CARRIER: off` even after
    // taking ownership and bringing the link up itself.
    // The flags arriving here are already the REPORTED set (`dev_get_flags`),
    // so carrier is read back out of them rather than derived a second time.
    let carrier = flags & iff::IFF_LOWER_UP != 0;
    let operstate = if carrier && flags & iff::IFF_UP != 0 {
        if_oper::UP
    } else { if_oper::DOWN };
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

/// The lifetimes a readback reports: what remains, not what was asked for.
/// # C: O(1)
fn age_cacheinfo(ci: IfaCacheInfo, flags: u32) -> IfaCacheInfo {
    let aged = net::iface_addr::age(super::rtnetlink_addr::cache_to_net(ci), flags,
        net::iface_addr::now_centisecs());
    IfaCacheInfo { preferred: aged.preferred, valid: aged.valid,
                   cstamp: aged.cstamp, tstamp: aged.tstamp }
}

/// Build a single RTM_NEWADDR reply for one iface's IPv4 address.
/// # C: O(N attrs)
pub(crate) fn build_newaddr_reply(
    seq: u32, pid: u32, ifindex: i32, label: &str, addr: [u8; 4], peer: Option<[u8; 4]>,
    broadcast: Option<[u8; 4]>, prefixlen: u8, scope: u8, flags: u32, proto: u8,
    rt_priority: u32, cacheinfo: IfaCacheInfo, msg_flags: u16, target_nsid: Option<i32>,
) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(96);
    let ifa = Ifaddrmsg {
        ifa_family: AF_INET,
        ifa_prefixlen: prefixlen,
        // The header field is a u8 and holds only the low eight bits; the whole
        // 32-bit value goes in `IFA_FLAGS`.
        ifa_flags: flags as u8,
        ifa_scope: scope,
        ifa_index: ifindex as u32,
    };
    let mut ifa_buf = [0u8; Ifaddrmsg::SIZE];
    ifa.write_to(&mut ifa_buf);
    body.extend_from_slice(&ifa_buf);

    if let Some(nsid) = target_nsid { put_nlattr_i32(&mut body, ifa::IFA_TARGET_NETNSID, nsid); }

    // Every attribute is reported only when it was actually set, in the order
    // the reference emits them. A synthesized value reads back as one the
    // setter never asked for, and an agent that reconciles its own state
    // against this reply re-applies the address forever trying to correct it.
    put_nlattr(&mut body, ifa::IFA_ADDRESS, &peer.unwrap_or(addr));
    put_nlattr(&mut body, ifa::IFA_LOCAL, &addr);
    if let Some(bcast) = broadcast { put_nlattr(&mut body, ifa::IFA_BROADCAST, &bcast); }
    put_nlattr_str(&mut body, ifa::IFA_LABEL, label);
    if proto != 0 { put_nlattr_u8(&mut body, ifa::IFA_PROTO, proto); }
    put_nlattr_u32(&mut body, ifa::IFA_FLAGS, flags);
    if rt_priority != 0 { put_nlattr_u32(&mut body, ifa::IFA_RT_PRIORITY, rt_priority); }
    let mut ci = [0u8; IfaCacheInfo::SIZE];
    age_cacheinfo(cacheinfo, flags).write_to(&mut ci);
    put_nlattr(&mut body, ifa::IFA_CACHEINFO, &ci);

    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32,
        nlmsg_type: RTM_NEWADDR,
        nlmsg_flags: msg_flags,
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
    flags: u32, cacheinfo: IfaCacheInfo, msg_flags: u16, target_nsid: Option<i32>,
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
    if let Some(nsid) = target_nsid { put_nlattr_i32(&mut body, ifa::IFA_TARGET_NETNSID, nsid); }
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
        nlmsg_flags: msg_flags,
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
    handle_getaddr_in(net::netdev::current_net_ns(), req, &[], false)
}

/// Handle RTM_GETADDR with the caller's target-namespace capability decision.
/// # C: O(N addresses)
pub(crate) fn handle_getaddr_with_access<F>(ns: u64, req: &Nlmsghdr, full_msg: &[u8], strict: bool,
                                            target_access: F) -> Vec<u8>
where F: Fn(&network_namespace::NetworkNamespaceRef) -> bool
{
    handle_getaddr_impl(ns, req, full_msg, strict, target_access)
}

/// Handle RTM_GETADDR in the socket's captured network namespace.
///
/// Under `NETLINK_GET_STRICT_CHK` the request header is validated and its
/// `ifa_index` selects one device; without it every address in the namespace
/// is reported, which is what a client asking for one device used to receive.
/// # C: O(N_ifaces)
pub fn handle_getaddr_in(ns: u64, req: &Nlmsghdr, full_msg: &[u8], strict: bool) -> Vec<u8> {
    handle_getaddr_impl(ns, req, full_msg, strict, |_| true)
}

fn handle_getaddr_impl<F>(ns: u64, req: &Nlmsghdr, full_msg: &[u8], strict: bool,
                          target_access: F) -> Vec<u8>
where F: Fn(&network_namespace::NetworkNamespaceRef) -> bool
{
    let (ns, want, target_nsid) = match super::dump_req::validate_addr_dump(strict, full_msg) {
        super::dump_req::AddrDump::Err(e) => return super::ack::build_ack(req, -(e.as_i32())),
        super::dump_req::AddrDump::All => (ns, None, None),
        super::dump_req::AddrDump::OneDevice(index) => (ns, Some(index), None),
        super::dump_req::AddrDump::Target { nsid, ifindex } => {
            let Some(caller) = network_namespace::lookup_u64(ns) else {
                return super::ack::build_ack(req, -(Errno::Einval.as_i32()));
            };
            let Some(target) = caller.peer_by_id(nsid) else {
                return super::ack::build_ack(req, -(Errno::Einval.as_i32()));
            };
            if !target_access(&target) {
                return super::ack::build_ack(req, -(Errno::Eacces.as_i32()));
            }
            (target.id().as_u64(), ifindex, Some(nsid))
        }
    };
    let msg_flags = flags::NLM_F_MULTI
        | if want.is_some() { super::dump_req::NLM_F_DUMP_FILTERED } else { 0 };
    let mut reply: Vec<u8> = Vec::with_capacity(256);
    let ifaces = ifaces_snapshot_in(ns);
    if want.is_some_and(|w| !ifaces.iter().any(|(id, ..)| *id == w)) {
        return super::ack::build_ack(req, -(Errno::Enodev.as_i32()));
    }
    for row in super::rtnetlink_addr::addr_snapshot_ns(ns).iter() {
        let Some(ifindex) = net::global_stack().ifaces.ifindex_in_ns(row.iface, ns) else { continue; };
        if want.is_some_and(|w| w != ifindex) { continue; }
        let name = match ifaces.iter().find(|(id, _, _, _, _, _, _, _)| *id == ifindex) {
            Some((_, n, _, _, _, _, _, _)) => n.as_str(),
            None => continue,
        };
        let one = build_newaddr_reply(
            req.nlmsg_seq, req.nlmsg_pid, ifindex as i32, name, row.addr.octets(),
            row.peer.map(net::Ipv4Addr::octets), row.broadcast.map(net::Ipv4Addr::octets),
            row.prefixlen, row.scope, row.flags, row.proto, row.rt_priority,
            super::rtnetlink_addr::cache_from_net(row.cacheinfo), msg_flags, target_nsid,
        );
        reply.extend_from_slice(&one);
    }
    for (iface, row) in net::sock::stack().v6_addr_snapshot_in(ns) {
        let Some(ifindex) = net::global_stack().ifaces.ifindex_in_ns(iface, ns) else { continue; };
        if want.is_some_and(|w| w != ifindex) { continue; }
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
            row.flags(), cacheinfo, msg_flags, target_nsid,
        ));
    }
    reply.extend_from_slice(&done_multi(req.nlmsg_seq, req.nlmsg_pid));
    reply
}
