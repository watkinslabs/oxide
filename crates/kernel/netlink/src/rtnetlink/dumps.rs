extern crate alloc;

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::{flags, Nlmsghdr};

use super::attrs::{put_nlattr, put_nlattr_str, put_nlattr_u32, put_nlattr_u8};
use super::iface::ifaces_snapshot_in;
use super::rtnetlink_addr::IfaCacheInfo;
use super::rtnetlink_link::{put_link_stats64, LinkStats64};
use super::uapi::{
    ifa, ifla, iff, AF_INET, AF_INET6, Ifaddrmsg, Ifinfomsg,
    RTM_NEWADDR, RTM_NEWLINK, RT_SCOPE_HOST,
};
#[cfg(target_os = "oxide-kernel")]
use super::uapi::{RT_SCOPE_LINK, RT_SCOPE_UNIVERSE};

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

/// Handle an RTM_GETLINK request carrying no body — the dump form.
/// # C: O(N_ifaces)
pub fn handle_getlink(req: &Nlmsghdr) -> Vec<u8> {
    let mut only_header = [0u8; Nlmsghdr::SIZE];
    req.write_to(&mut only_header);
    handle_getlink_in(net::netdev::current_net_ns(), req, &only_header, false)
}

/// The non-dump `RTM_GETLINK`: one device, named by `ifi_index` or by
/// `IFLA_IFNAME`, answered with a single non-multipart `RTM_NEWLINK`.
///
/// The reference returns `-ENODEV` when the name or index matches nothing, and
/// `-EINVAL` when the request is too short to carry an `ifinfomsg`.
/// # C: O(N_ifaces)
fn getlink_one(ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let off = Nlmsghdr::SIZE;
    if full_msg.len() < off + Ifinfomsg::SIZE { return super::ack::build_ack(req, -22); }
    let want_index = i32::from_ne_bytes([
        full_msg[off + 4], full_msg[off + 5], full_msg[off + 6], full_msg[off + 7],
    ]);
    let want_name = ifname_attr(&full_msg[off + Ifinfomsg::SIZE..]);
    let entries = ifaces_snapshot_in(ns);
    let found = entries.iter().find(|(id, name, _, _, _, _, _, _)| {
        (want_index > 0 && *id as i32 == want_index)
            || want_name.as_deref().is_some_and(|w| w == name.as_str())
    });
    let Some((id, name, mac, broadcast, mtu, is_lo, flags, stats)) = found
        else { return super::ack::build_ack(req, -19) };
    build_newlink_reply(req.nlmsg_seq, req.nlmsg_pid, *id as i32, name, *mac,
        &broadcast.bytes[..broadcast.len as usize], *mtu, *is_lo, *flags, *stats, false)
}

/// `IFLA_IFNAME` out of a request's attribute area, if present.
/// # C: O(attr bytes)
fn ifname_attr(mut attrs: &[u8]) -> Option<alloc::string::String> {
    while attrs.len() >= 4 {
        let len = u16::from_ne_bytes([attrs[0], attrs[1]]) as usize;
        let kind = u16::from_ne_bytes([attrs[2], attrs[3]]);
        if len < 4 || len > attrs.len() { return None; }
        if kind == ifla::IFLA_IFNAME {
            let body = &attrs[4..len];
            let end = body.iter().position(|b| *b == 0).unwrap_or(body.len());
            return core::str::from_utf8(&body[..end]).ok().map(alloc::string::String::from);
        }
        attrs = &attrs[(len + 3) & !3..];
    }
    None
}

/// Handle RTM_GETLINK in the socket's captured network namespace: a dump
/// when the caller set `NLM_F_DUMP`, otherwise the one device it named.
/// # C: O(N_ifaces)
pub fn handle_getlink_in(ns: u64, req: &Nlmsghdr, full_msg: &[u8], strict: bool) -> Vec<u8> {
    // A GETLINK is two different requests, and answering both with a dump is
    // what made `ip link show eth0` print `lo`.
    //
    // With NLM_F_DUMP the reference walks every device and terminates with
    // NLMSG_DONE. WITHOUT it, it resolves the one device the caller named — by
    // `ifi_index`, else by IFLA_IFNAME — and replies with a SINGLE RTM_NEWLINK
    // carrying no multipart flag and no DONE, or ENODEV when nothing matches.
    //
    // Replying to the single form with a full dump hands the caller the FIRST
    // device in the table as if it were the one asked for. Every client that
    // queries a device by name or index therefore read loopback's identity and
    // loopback's flags — including the network manager, which is why it
    // believed a down, unaddressed `eth0` was already up and externally
    // configured.
    if req.nlmsg_flags & crate::wire::flags::NLM_F_DUMP != crate::wire::flags::NLM_F_DUMP {
        return getlink_one(ns, req, full_msg);
    }
    // A link dump defines no device filter: a non-zero `ifi_index` is refused
    // rather than answered with every device, which would read as though the
    // filter had been honoured.
    if let super::dump_req::LinkDump::Err(e) = super::dump_req::validate_link_dump(strict, full_msg) {
        return super::ack::build_ack(req, -(e.as_i32()));
    }
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
    prefixlen: u8, scope: u8, flags: u32, cacheinfo: IfaCacheInfo, msg_flags: u16,
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
    flags: u32, cacheinfo: IfaCacheInfo, msg_flags: u16,
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

/// Handle RTM_GETADDR in the socket's captured network namespace.
///
/// Under `NETLINK_GET_STRICT_CHK` the request header is validated and its
/// `ifa_index` selects one device; without it every address in the namespace
/// is reported, which is what a client asking for one device used to receive.
/// # C: O(N_ifaces)
pub fn handle_getaddr_in(ns: u64, req: &Nlmsghdr, full_msg: &[u8], strict: bool) -> Vec<u8> {
    let want = match super::dump_req::validate_addr_dump(strict, full_msg) {
        super::dump_req::AddrDump::Err(e) => return super::ack::build_ack(req, -(e.as_i32())),
        super::dump_req::AddrDump::All => None,
        super::dump_req::AddrDump::OneDevice(index) => Some(index),
    };
    let msg_flags = flags::NLM_F_MULTI
        | if want.is_some() { super::dump_req::NLM_F_DUMP_FILTERED } else { 0 };
    let mut reply: Vec<u8> = Vec::with_capacity(256);
    let ifaces = ifaces_snapshot_in(ns);
    if want.is_some_and(|w| !ifaces.iter().any(|(id, ..)| *id == w)) {
        return super::ack::build_ack(req, -(Errno::Enodev.as_i32()));
    }
    for row in super::rtnetlink_addr::addr_snapshot_ns(ns).iter() {
        let Some(ifindex) = net::global_stack().ifaces.ifindex_in_ns(
            net::NetIfaceId::from_raw(row.ifindex), ns) else { continue; };
        if want.is_some_and(|w| w != ifindex) { continue; }
        let name = match ifaces.iter().find(|(id, _, _, _, _, _, _, _)| *id == ifindex) {
            Some((_, n, _, _, _, _, _, _)) => n.as_str(),
            None => continue,
        };
        let one = build_newaddr_reply(
            req.nlmsg_seq, req.nlmsg_pid, ifindex as i32, name, row.addr, row.peer,
            row.prefixlen, row.scope, row.flags, row.cacheinfo, msg_flags,
        );
        reply.extend_from_slice(&one);
    }
    #[cfg(target_os = "oxide-kernel")]
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
            row.flags(), cacheinfo, msg_flags,
        ));
    }
    reply.extend_from_slice(&done_multi(req.nlmsg_seq, req.nlmsg_pid));
    reply
}

#[cfg(test)]
mod getlink_form_tests {
    use super::*;

    fn request(flags: u16, ifindex: i32, name: Option<&str>) -> (Nlmsghdr, alloc::vec::Vec<u8>) {
        let mut body = alloc::vec![0u8; Ifinfomsg::SIZE];
        body[4..8].copy_from_slice(&ifindex.to_ne_bytes());
        if let Some(n) = name {
            let payload = n.as_bytes();
            let len = 4 + payload.len() + 1;
            body.extend_from_slice(&(len as u16).to_ne_bytes());
            body.extend_from_slice(&ifla::IFLA_IFNAME.to_ne_bytes());
            body.extend_from_slice(payload);
            body.push(0);
            while body.len() % 4 != 0 { body.push(0); }
        }
        let hdr = Nlmsghdr {
            nlmsg_len: (Nlmsghdr::SIZE + body.len()) as u32,
            nlmsg_type: super::super::RTM_GETLINK,
            nlmsg_flags: crate::wire::flags::NLM_F_REQUEST | flags,
            nlmsg_seq: 5, nlmsg_pid: 9,
        };
        let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE];
        hdr.write_to(&mut msg[..]);
        msg.extend_from_slice(&body);
        (hdr, msg)
    }

    /// `IFLA_IFNAME` is read out of the attribute area, which is what lets a
    /// client name a device instead of numbering it.
    #[test]
    fn the_interface_name_attribute_is_parsed() {
        let (_h, msg) = request(0, 0, Some("eth0"));
        let attrs = &msg[Nlmsghdr::SIZE + Ifinfomsg::SIZE..];
        assert_eq!(ifname_attr(attrs).as_deref(), Some("eth0"));
    }

    #[test]
    fn an_absent_name_attribute_reads_as_none() {
        let (_h, msg) = request(0, 2, None);
        assert_eq!(ifname_attr(&msg[Nlmsghdr::SIZE + Ifinfomsg::SIZE..]), None);
    }

    /// A truncated attribute must not be trusted or walked past.
    #[test]
    fn a_malformed_attribute_header_is_refused() {
        assert_eq!(ifname_attr(&[3, 0, 3, 0]), None);
        assert_eq!(ifname_attr(&[255, 255, 3, 0]), None);
    }

    /// The single-device form answers ENODEV for a device that does not exist,
    /// rather than handing back whatever happens to be first in the table —
    /// which is what made a by-name query read loopback's identity.
    #[test]
    fn a_single_get_for_an_unknown_device_reports_enodev() {
        let (hdr, msg) = request(0, 0, Some("nosuchdev0"));
        let reply = getlink_one(0, &hdr, &msg);
        assert_eq!(u16::from_ne_bytes([reply[4], reply[5]]), crate::msg::NLMSG_ERROR);
        let err = i32::from_ne_bytes([reply[16], reply[17], reply[18], reply[19]]);
        assert_eq!(err, -19, "ENODEV");
    }

    /// A request too short to carry an `ifinfomsg` is EINVAL, as the reference
    /// reports it.
    #[test]
    fn a_truncated_single_get_is_einval() {
        let (hdr, _msg) = request(0, 1, None);
        let short = alloc::vec![0u8; Nlmsghdr::SIZE];
        let reply = getlink_one(0, &hdr, &short);
        let err = i32::from_ne_bytes([reply[16], reply[17], reply[18], reply[19]]);
        assert_eq!(err, -22, "EINVAL");
    }
}
