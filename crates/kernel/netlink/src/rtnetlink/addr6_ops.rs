//! `RTM_NEWADDR` / `RTM_DELADDR` for `AF_INET6`.
//!
//! Split from `addr_ops` because the two families validate differently: an
//! IPv6 address attribute is sixteen bytes with minimum-length policy, the
//! scope is derived from the address rather than taken from the setter, the
//! prefix-length ceiling is 128, and the errno order differs — an IPv6 add
//! resolves the interface before it rejects a prefix length, while an IPv6
//! delete rejects the prefix length first.
//!
//! Module manifest:
//! - `decide`: the ungated flag/lifetime/address-type decisions and their tests.
//!
//! This file owns the `ifa_ipv6_policy` attribute parse and the two handlers.

extern crate alloc;

use alloc::vec::Vec;

use crate::{nlmsg_align, Nlmsghdr};
use crate::flags;

use super::ack::build_ack;
use super::uapi::{ifa, Ifaddrmsg};

#[path = "addr6_ops/decide.rs"]
pub(crate) mod decide;

use decide::{errno, AddrType, Lifetimes, USER_FLAG_MASK};

const IN6_ADDR_LEN: usize = 16;
const CACHEINFO_LEN: usize = 16;
const MAX_PREFIXLEN6: u8 = 128;

/// One parsed `ifa_ipv6_policy` attribute set.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NewAddr6Attrs {
    pub(crate) address: Option<[u8; IN6_ADDR_LEN]>,
    pub(crate) local: Option<[u8; IN6_ADDR_LEN]>,
    pub(crate) flags: Option<u32>,
    pub(crate) proto: u8,
    pub(crate) rt_priority: u32,
    /// `(ifa_prefered, ifa_valid)`; the two stamps the setter sends are the
    /// kernel's to publish and are ignored on the way in.
    pub(crate) cacheinfo: Option<(u32, u32)>,
}

/// Parse the IPv6 address attributes. `None` names a policy violation, which
/// the reference answers with EINVAL.
///
/// Minimum-length, not exact-length: `ifa_ipv6_policy` states `.len` for
/// `IFA_ADDRESS`, `IFA_LOCAL`, `IFA_CACHEINFO`, `IFA_FLAGS` and
/// `IFA_RT_PRIORITY`, which admits a longer payload and reads the leading
/// bytes. `IFA_PROTO` and `IFA_TARGET_NETNSID` carry a scalar type and are
/// exact. A short attribute, or a header whose length runs past the message,
/// is the violation. Trailing bytes that cannot start an attribute are not:
/// this message is parsed liberally, so the reference logs them and proceeds.
/// # C: O(N attrs)
pub(crate) fn parse_newaddr6_attrs(attrs: &[u8]) -> Option<NewAddr6Attrs> {
    let mut out = NewAddr6Attrs::default();
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if nla_len < 4 || off + nla_len > attrs.len() { break; }
        let payload = &attrs[off + 4..off + nla_len];
        match nla_type {
            ifa::IFA_ADDRESS => {
                if payload.len() < IN6_ADDR_LEN { return None; }
                out.address = Some(payload[..IN6_ADDR_LEN].try_into().unwrap());
            }
            ifa::IFA_LOCAL => {
                if payload.len() < IN6_ADDR_LEN { return None; }
                out.local = Some(payload[..IN6_ADDR_LEN].try_into().unwrap());
            }
            ifa::IFA_CACHEINFO => {
                if payload.len() < CACHEINFO_LEN { return None; }
                out.cacheinfo = Some((u32::from_ne_bytes(payload[0..4].try_into().unwrap()),
                                      u32::from_ne_bytes(payload[4..8].try_into().unwrap())));
            }
            ifa::IFA_FLAGS => {
                if payload.len() < 4 { return None; }
                out.flags = Some(u32::from_ne_bytes(payload[0..4].try_into().unwrap()));
            }
            ifa::IFA_RT_PRIORITY => {
                if payload.len() < 4 { return None; }
                out.rt_priority = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
            }
            ifa::IFA_PROTO => {
                if payload.len() != 1 { return None; }
                out.proto = payload[0];
            }
            ifa::IFA_TARGET_NETNSID => { if payload.len() != 4 { return None; } }
            _ => {}
        }
        off = off.checked_add(nlmsg_align(nla_len))?;
    }
    Some(out)
}

/// The local address and the point-to-point peer the setter named. `IFA_LOCAL`
/// wins as the local address; `IFA_ADDRESS` becomes the peer when both are
/// present and differ.
/// # C: O(1)
pub(crate) fn extract_addr6(parsed: &NewAddr6Attrs)
    -> Option<([u8; IN6_ADDR_LEN], Option<[u8; IN6_ADDR_LEN]>)>
{
    match (parsed.local, parsed.address) {
        (Some(local), Some(address)) if local != address => Some((local, Some(address))),
        (Some(local), _) => Some((local, None)),
        (None, Some(address)) => Some((address, None)),
        (None, None) => None,
    }
}

/// The fixed part of an `RTM_NEWADDR`/`RTM_DELADDR` request.
struct Ifa6Header {
    prefixlen: u8,
    ifa_flags: u32,
    ifindex: u32,
}

fn parse_header(full_msg: &[u8]) -> Option<Ifa6Header> {
    let off = Nlmsghdr::SIZE;
    if full_msg.len() < off + Ifaddrmsg::SIZE { return None; }
    Some(Ifa6Header {
        prefixlen: full_msg[off + 1],
        ifa_flags: full_msg[off + 2] as u32,
        ifindex: u32::from_ne_bytes([full_msg[off + 4], full_msg[off + 5],
                                     full_msg[off + 6], full_msg[off + 7]]),
    })
}

/// Handle `RTM_NEWADDR` for `AF_INET6` in the socket's network namespace.
/// # C: O(N attrs + addr_table size)
pub fn handle_newaddr6_in(ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let Some(hdr) = parse_header(full_msg) else { return build_ack(req, errno::EINVAL) };
    let attrs = &full_msg[Nlmsghdr::SIZE + Ifaddrmsg::SIZE..];
    let Some(parsed) = parse_newaddr6_attrs(attrs) else { return build_ack(req, errno::EINVAL) };
    let Some((local, peer)) = extract_addr6(&parsed) else { return build_ack(req, errno::EINVAL) };
    let user_flags = parsed.flags.unwrap_or(hdr.ifa_flags) & USER_FLAG_MASK;
    let Some(lifetimes) = Lifetimes::from_cacheinfo(parsed.cacheinfo) else {
        return build_ack(req, errno::EINVAL);
    };

    let addr = net::Ipv6Addr(local);
    let stack = net::global_stack();
    let Some((iface, _)) = stack.ifaces.lookup_ifindex_in_ns(hdr.ifindex, ns) else {
        return build_ack(req, errno::ENODEV);
    };
    let Some(lease) = stack.ifaces.acquire_ingress(iface) else {
        return build_ack(req, errno::ENODEV);
    };
    if lease.net_ns() != ns { return build_ack(req, errno::ENODEV); }
    let Some(label) = stack.ifaces.name_in_ns(iface, ns) else {
        return build_ack(req, errno::ENODEV);
    };
    let meta = net::stack_ipv6::Ipv6AddrMeta {
        user_flags, proto: parsed.proto, rt_priority: parsed.rt_priority,
        valid_lft: lifetimes.valid, preferred_lft: lifetimes.preferred,
    };
    let dev_flags = stack.ifaces.iface_flags(iface).unwrap_or(0);
    let dad = net::stack_ipv6::dad_applies(dev_flags, user_flags);
    let (ticket, published) = {
        let rtnl = stack.rtnl_lock();
        if stack.ifaces.control_ready_in_ns(&rtnl, iface, ns).is_none() {
            return build_ack(req, errno::ENODEV);
        }
        let generation = lease.generation();
        let Some(present) = stack.ipv6_addr_present_rtnl(&rtnl, ns, iface, generation, addr)
            else { return build_ack(req, errno::ENODEV) };
        let row = if present {
            // The reference screens by address alone, so a repeat add of one
            // address is EEXIST whatever prefix length it names, and a replace
            // keeps the row's identity and DAD state rather than recreating it.
            if req.nlmsg_flags & flags::NLM_F_EXCL != 0
                || req.nlmsg_flags & flags::NLM_F_REPLACE == 0
            {
                return build_ack(req, errno::EEXIST);
            }
            stack.modify_ipv6_prefix_generation_rtnl(&rtnl, ns, iface, generation, addr,
                peer.map(net::Ipv6Addr), meta)
        } else {
            if hdr.prefixlen > MAX_PREFIXLEN6 { return build_ack(req, errno::EINVAL); }
            if let Some(err) = decide::reject_manage_tempaddr(user_flags, hdr.prefixlen) {
                return build_ack(req, err);
            }
            if net::stack_ipv6::ipv6_disabled_in(ns) { return build_ack(req, errno::EACCES); }
            let loopback_dev = dev_flags & net::netdev::iff::IFF_LOOPBACK != 0;
            if let Some(err) = decide::reject_address_type(AddrType::of(addr), user_flags,
                                                          loopback_dev) {
                return build_ack(req, err);
            }
            stack.add_ipv6_prefix_generation_rtnl(&rtnl, ns, iface, generation, addr,
                peer.map(net::Ipv6Addr), hdr.prefixlen, meta, dad)
        };
        let Some(row) = row else { return build_ack(req, errno::ENODEV) };
        let published = row.addr;
        (stack.stage_addr6_rtnl(&rtnl, &lease, label, net::control_event::EventKind::New, row),
            published)
    };
    if let Some(ticket) = ticket { net::control_event::publish(ticket); }
    // The reference kicks DAD from this path rather than waiting for the next
    // address-verification pass, so a solicitation leaves before the caller's
    // ack does.
    if dad { stack.start_manual_dad(iface, published); }
    build_ack(req, 0)
}

/// Handle `RTM_DELADDR` for `AF_INET6` in the socket's network namespace.
/// # C: O(N attrs + addr_table size)
pub fn handle_deladdr6_in(ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let Some(hdr) = parse_header(full_msg) else { return build_ack(req, errno::EINVAL) };
    let attrs = &full_msg[Nlmsghdr::SIZE + Ifaddrmsg::SIZE..];
    let Some(parsed) = parse_newaddr6_attrs(attrs) else { return build_ack(req, errno::EINVAL) };
    let Some((local, _)) = extract_addr6(&parsed) else { return build_ack(req, errno::EINVAL) };
    // A delete rejects the prefix length before it resolves the interface;
    // an add resolves the interface first. The order is the reference's.
    if hdr.prefixlen > MAX_PREFIXLEN6 { return build_ack(req, errno::EINVAL); }

    let addr = net::Ipv6Addr(local);
    let stack = net::global_stack();
    let Some((iface, _)) = stack.ifaces.lookup_ifindex_in_ns(hdr.ifindex, ns) else {
        return build_ack(req, errno::ENODEV);
    };
    let Some(lease) = stack.ifaces.acquire_ingress(iface) else {
        return build_ack(req, errno::ENODEV);
    };
    if lease.net_ns() != ns { return build_ack(req, errno::ENODEV); }
    // No IPv6 on the device is ENXIO here, not the add path's EACCES.
    if net::stack_ipv6::ipv6_disabled_in(ns) { return build_ack(req, errno::ENXIO); }
    let Some(label) = stack.ifaces.name_in_ns(iface, ns) else {
        return build_ack(req, errno::ENODEV);
    };
    let ticket = {
        let rtnl = stack.rtnl_lock();
        if stack.ifaces.control_ready_in_ns(&rtnl, iface, ns).is_none() {
            return build_ack(req, errno::ENODEV);
        }
        let generation = lease.generation();
        // Generation gate first, so an interface replaced under the request
        // reports ENODEV rather than borrowing the missing-address errno.
        if stack.ipv6_addr_present_rtnl(&rtnl, ns, iface, generation, addr).is_none() {
            return build_ack(req, errno::ENODEV);
        }
        let Some(row) = stack.remove_ipv6_prefix_generation_rtnl(&rtnl, ns, iface,
            generation, addr, hdr.prefixlen)
            else { return build_ack(req, errno::EADDRNOTAVAIL) };
        stack.stage_addr6_rtnl(&rtnl, &lease, label, net::control_event::EventKind::Delete, row)
    };
    if let Some(ticket) = ticket { net::control_event::publish(ticket); }
    build_ack(req, 0)
}
