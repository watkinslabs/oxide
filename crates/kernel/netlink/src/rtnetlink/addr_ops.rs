extern crate alloc;

use alloc::vec::Vec;

use crate::{nlmsg_align, Nlmsghdr};
use crate::flags;

use super::ack::build_ack;
use super::rtnetlink_addr::{cache_to_net, IfaCacheInfo};
use super::uapi::{ifa, Ifaddrmsg, AF_INET};

#[derive(Copy, Clone)]
struct NewAddrAttrs {
    local: [u8; 4],
    address: Option<[u8; 4]>,
    flags: Option<u32>,
    cacheinfo: Option<IfaCacheInfo>,
}

/// Parse address attrs from RTM_NEWADDR/DELADDR. # C: O(N attrs)
fn parse_newaddr_attrs(attrs: &[u8]) -> Option<NewAddrAttrs> {
    let mut off = 0;
    let mut local = None;
    let mut address = None;
    let mut flags = None;
    let mut cacheinfo = None;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if nla_len < 4 || off + nla_len > attrs.len() { return None; }
        let next = off.checked_add(nlmsg_align(nla_len))?;
        if next > attrs.len() { return None; }
        let payload = &attrs[off + 4..off + nla_len];
        if nla_type == ifa::IFA_LOCAL && payload.len() == 4 {
            local = Some([payload[0], payload[1], payload[2], payload[3]]);
        } else if nla_type == ifa::IFA_ADDRESS && payload.len() == 4 {
            address = Some([payload[0], payload[1], payload[2], payload[3]]);
        } else if nla_type == ifa::IFA_FLAGS && payload.len() == 4 {
            flags = Some(u32::from_ne_bytes(payload[0..4].try_into().unwrap()));
        } else if nla_type == ifa::IFA_CACHEINFO && payload.len() == IfaCacheInfo::SIZE {
            cacheinfo = Some(IfaCacheInfo {
                preferred: u32::from_ne_bytes(payload[0..4].try_into().unwrap()),
                valid: u32::from_ne_bytes(payload[4..8].try_into().unwrap()),
                cstamp: u32::from_ne_bytes(payload[8..12].try_into().unwrap()),
                tstamp: u32::from_ne_bytes(payload[12..16].try_into().unwrap()),
            });
        } else if matches!(nla_type, ifa::IFA_LOCAL | ifa::IFA_ADDRESS | ifa::IFA_FLAGS
            | ifa::IFA_CACHEINFO) {
            return None;
        }
        off = next;
    }
    if off != attrs.len() { return None; }
    let local = local.or(address)?;
    Some(NewAddrAttrs { local, address, flags, cacheinfo })
}

/// Handle RTM_NEWADDR.
/// # C: O(N attrs + addr_table size)
pub fn handle_newaddr(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    handle_newaddr_in(net::netdev::current_net_ns(), req, full_msg)
}

/// Handle RTM_NEWADDR in the socket's captured network namespace.
/// # C: O(N attrs + addr_table size)
pub fn handle_newaddr_in(ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let ifa_off = Nlmsghdr::SIZE;
    if full_msg.len() < ifa_off + Ifaddrmsg::SIZE { return build_ack(req, -22); }
    let family = full_msg[ifa_off];
    let prefixlen = full_msg[ifa_off + 1];
    let ifa_flags = full_msg[ifa_off + 2] as u32;
    let scope = full_msg[ifa_off + 3];
    let ifindex = u32::from_ne_bytes([
        full_msg[ifa_off + 4], full_msg[ifa_off + 5], full_msg[ifa_off + 6], full_msg[ifa_off + 7],
    ]);
    if family != AF_INET { return build_ack(req, -97); }
    if prefixlen > 32 { return build_ack(req, -22); }
    let attrs = &full_msg[ifa_off + Ifaddrmsg::SIZE..];
    let parsed = match parse_newaddr_attrs(attrs) {
        Some(a) => a,
        None => return build_ack(req, -22),
    };
    let addr = parsed.local;
    let peer = parsed.address.filter(|address| *address != addr);
    let flags = parsed.flags.unwrap_or_else(|| {
        if parsed.cacheinfo.is_some() { ifa_flags } else { ifa_flags | net::iface_addr::IFA_F_PERMANENT }
    });
    let cacheinfo = parsed.cacheinfo.unwrap_or(IfaCacheInfo::PERMANENT);
    let stack = net::global_stack();
    let id = net::NetIfaceId::from_raw(ifindex);
    let Some(lease) = stack.ifaces.acquire_ingress(id) else {
        return build_ack(req, -19);
    };
    if lease.net_ns() != ns { return build_ack(req, -19); }
    let Some(label) = stack.ifaces.lookup_in_ns(id, ns)
        .map(|dev| alloc::string::String::from(dev.name())) else { return build_ack(req, -19) };
    let ticket = {
        let rtnl = stack.rtnl_lock();
        let Some(_) = stack.ifaces.control_ready_in_ns(&rtnl, id, ns) else {
            return build_ack(req, -19);
        };
        if stack.ifaces.control_generation_in_ns(&rtnl, id, ns) != Some(lease.generation()) {
            return build_ack(req, -19);
        }
        let exists = net::iface_addr::snapshot_ns(ns).iter().any(|row| {
            row.iface == id && row.addr == net::Ipv4Addr::from_u32(u32::from_be_bytes(addr))
                && row.prefixlen == prefixlen
        });
        if exists && (req.nlmsg_flags & flags::NLM_F_EXCL != 0
            || req.nlmsg_flags & flags::NLM_F_REPLACE == 0)
        {
            return build_ack(req, -17);
        }
        let Some(effect) = stack.set_ipv4_prefix_meta_generation_rtnl(&rtnl, ns, id,
            lease.generation(), net::Ipv4Addr::from_u32(u32::from_be_bytes(addr)),
            peer.map(|peer| net::Ipv4Addr::from_u32(u32::from_be_bytes(peer))), prefixlen,
            scope, flags, cache_to_net(cacheinfo)) else {
            return build_ack(req, -19);
        };
        let row = net::iface_addr::Ipv4IfaceAddr {
            ns, iface: id, addr: net::Ipv4Addr::from_u32(u32::from_be_bytes(addr)),
            peer: peer.map(|peer| net::Ipv4Addr::from_u32(u32::from_be_bytes(peer))),
            prefixlen, mask: if prefixlen == 0 { 0 }
                else { u32::MAX << (32 - prefixlen.min(32)) },
            broadcast: None,
            scope, flags, cacheinfo: cache_to_net(cacheinfo),
        };
        net::control_event::stage_addr(&rtnl, net::control_event::AddrEvent {
            kind: net::control_event::EventKind::New,
            namespace: net::control_event::NamespaceOwner::Live(lease.namespace()),
            owner: net::control_event::IfaceOwner { iface: id, generation: lease.generation() },
            label, row,
        }, effect)
    };
    net::control_event::publish(ticket);
    build_ack(req, 0)
}

/// Handle RTM_DELADDR.
/// # C: O(N attrs + addr_table size)
pub fn handle_deladdr(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    handle_deladdr_in(net::netdev::current_net_ns(), req, full_msg)
}

/// Handle RTM_DELADDR in the socket's captured network namespace.
/// # C: O(N attrs + addr_table size)
pub fn handle_deladdr_in(ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let ifa_off = Nlmsghdr::SIZE;
    if full_msg.len() < ifa_off + Ifaddrmsg::SIZE { return build_ack(req, -22); }
    let family = full_msg[ifa_off];
    let prefixlen = full_msg[ifa_off + 1];
    let ifindex = u32::from_ne_bytes([
        full_msg[ifa_off + 4], full_msg[ifa_off + 5], full_msg[ifa_off + 6], full_msg[ifa_off + 7],
    ]);
    if family != AF_INET { return build_ack(req, -97); }
    if prefixlen > 32 { return build_ack(req, -22); }
    let attrs = &full_msg[ifa_off + Ifaddrmsg::SIZE..];
    let parsed = match parse_newaddr_attrs(attrs) {
        Some(a) => a,
        None => return build_ack(req, -22),
    };
    let addr = parsed.local;
    let stack = net::global_stack();
    let id = net::NetIfaceId::from_raw(ifindex);
    let Some(lease) = stack.ifaces.acquire_ingress(id) else {
        return build_ack(req, -19);
    };
    if lease.net_ns() != ns { return build_ack(req, -19); }
    let Some(label) = stack.ifaces.lookup_in_ns(id, ns)
        .map(|dev| alloc::string::String::from(dev.name())) else { return build_ack(req, -19) };
    let ticket = {
        let rtnl = stack.rtnl_lock();
        let Some(_) = stack.ifaces.control_ready_in_ns(&rtnl, id, ns) else {
            return build_ack(req, -19);
        };
        if stack.ifaces.control_generation_in_ns(&rtnl, id, ns) != Some(lease.generation()) {
            return build_ack(req, -19);
        }
        let Some((row, effect)) = stack.remove_ipv4_prefix_generation_rtnl(&rtnl, ns, id,
            lease.generation(), net::Ipv4Addr::from_u32(u32::from_be_bytes(addr)),
            parsed.address.map(|address| {
                net::Ipv4Addr::from_u32(u32::from_be_bytes(address))
            }), prefixlen)
            else { return build_ack(req, -99) };
        net::control_event::stage_addr(&rtnl, net::control_event::AddrEvent {
            kind: net::control_event::EventKind::Delete,
            namespace: net::control_event::NamespaceOwner::Live(lease.namespace()),
            owner: net::control_event::IfaceOwner { iface: id, generation: lease.generation() },
            label, row,
        }, effect)
    };
    net::control_event::publish(ticket);
    build_ack(req, 0)
}
