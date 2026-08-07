//! One-shot IPv6 address lookups.

extern crate alloc;

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::Nlmsghdr;

use super::dumps::build_newaddr6_reply;
use super::iface::ifaces_snapshot_in;
use super::rtnetlink_addr::IfaCacheInfo;
use super::uapi::{ifa, AF_INET6, Ifaddrmsg, RT_SCOPE_HOST, RT_SCOPE_LINK, RT_SCOPE_UNIVERSE};

/// Handle a one-shot IPv6 `RTM_GETADDR` in the socket's network namespace.
/// # C: O(N addresses)
pub fn handle_getaddr6_one_in(ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    handle_getaddr6_one_with_access(ns, req, full_msg, |_| true)
}

/// Handle a one-shot IPv6 `RTM_GETADDR` with target-namespace access checking.
/// # C: O(N addresses)
pub(crate) fn handle_getaddr6_one_with_access<F>(
    ns: u64, req: &Nlmsghdr, full_msg: &[u8], target_access: F,
) -> Vec<u8>
where
    F: Fn(&network_namespace::NetworkNamespaceRef) -> bool,
{
    let off = Nlmsghdr::SIZE;
    if full_msg.len() < off + Ifaddrmsg::SIZE || full_msg[off] != AF_INET6 {
        return einval(req);
    }
    let ifindex = u32::from_ne_bytes(full_msg[off + 4..off + 8].try_into().unwrap());
    let mut attr = &full_msg[off + Ifaddrmsg::SIZE..];
    let mut wanted = None;
    let mut target_nsid = None;
    while attr.len() >= 4 {
        let len = u16::from_ne_bytes([attr[0], attr[1]]) as usize;
        let ty = u16::from_ne_bytes([attr[2], attr[3]]) & 0x3fff;
        if len < 4 || len > attr.len() { return einval(req); }
        match ty {
            ifa::IFA_ADDRESS | ifa::IFA_LOCAL if len == 20 => {
                let mut raw = [0u8; 16];
                raw.copy_from_slice(&attr[4..20]);
                wanted = Some(raw);
            }
            ifa::IFA_TARGET_NETNSID if len == 8 && target_nsid.is_none() => {
                target_nsid = Some(i32::from_ne_bytes(attr[4..8].try_into().unwrap()));
            }
            ifa::IFA_TARGET_NETNSID => return einval(req),
            _ => {}
        }
        let next = (len + 3) & !3;
        if next > attr.len() { return einval(req); }
        attr = &attr[next..];
    }
    let Some(wanted) = wanted else { return einval(req); };
    let target_ns = match target_nsid {
        None => ns,
        Some(nsid) => {
            let Some(caller) = network_namespace::lookup_u64(ns) else { return einval(req); };
            let Some(target) = caller.peer_by_id(nsid) else { return einval(req); };
            if !target_access(&target) { return super::ack::build_ack(req, -(Errno::Eacces.as_i32())); }
            target.id().as_u64()
        }
    };
    let ifaces = ifaces_snapshot_in(target_ns);
    let found = net::sock::stack().v6_addr_snapshot_in(target_ns).into_iter().find(|(iface, row)|
        net::global_stack().ifaces.ifindex_in_ns(*iface, target_ns) == Some(ifindex) && row.addr.0 == wanted);
    let Some((_, row)) = found else { return super::ack::build_ack(req, -(Errno::Enoent.as_i32())); };
    let Some((_, name, _, _, _, _, _, _)) = ifaces.iter().find(|(id, ..)| *id == ifindex) else {
        return super::ack::build_ack(req, -(Errno::Enodev.as_i32()));
    };
    let scope = if row.addr.is_loopback() { RT_SCOPE_HOST } else if row.addr.is_link_local() { RT_SCOPE_LINK } else { RT_SCOPE_UNIVERSE };
    build_newaddr6_reply(req.nlmsg_seq, req.nlmsg_pid, ifindex as i32, name, row.addr.0, row.prefixlen,
        scope, row.flags(), IfaCacheInfo { preferred: row.preferred, valid: row.valid, cstamp: 0, tstamp: 0 }, 0, target_nsid)
}

fn einval(req: &Nlmsghdr) -> Vec<u8> {
    super::ack::build_ack(req, -(Errno::Einval.as_i32()))
}
