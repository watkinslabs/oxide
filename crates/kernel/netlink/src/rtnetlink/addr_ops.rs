extern crate alloc;

use alloc::vec::Vec;

use crate::{nlmsg_align, Nlmsghdr};

use super::ack::build_ack;
use super::rtnetlink_addr::{addr_remove, cache_to_net, IfaCacheInfo};
use super::uapi::{ifa, Ifaddrmsg, AF_INET};

#[derive(Copy, Clone)]
struct NewAddrAttrs {
    addr: [u8; 4],
    flags: Option<u32>,
    cacheinfo: Option<IfaCacheInfo>,
}

/// Parse address attrs from RTM_NEWADDR/DELADDR. # C: O(N attrs)
fn parse_newaddr_attrs(attrs: &[u8]) -> Option<NewAddrAttrs> {
    let mut off = 0;
    let mut addr = None;
    let mut flags = None;
    let mut cacheinfo = None;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if nla_len < 4 || off + nla_len > attrs.len() { break; }
        let payload = &attrs[off + 4..off + nla_len];
        if (nla_type == ifa::IFA_LOCAL || nla_type == ifa::IFA_ADDRESS) && payload.len() == 4 {
            addr = Some([payload[0], payload[1], payload[2], payload[3]]);
        } else if nla_type == ifa::IFA_FLAGS && payload.len() >= 4 {
            flags = Some(u32::from_ne_bytes(payload[0..4].try_into().unwrap()));
        } else if nla_type == ifa::IFA_CACHEINFO && payload.len() >= IfaCacheInfo::SIZE {
            cacheinfo = Some(IfaCacheInfo {
                preferred: u32::from_ne_bytes(payload[0..4].try_into().unwrap()),
                valid: u32::from_ne_bytes(payload[4..8].try_into().unwrap()),
                cstamp: u32::from_ne_bytes(payload[8..12].try_into().unwrap()),
                tstamp: u32::from_ne_bytes(payload[12..16].try_into().unwrap()),
            });
        }
        off += nlmsg_align(nla_len);
    }
    addr.map(|addr| NewAddrAttrs { addr, flags, cacheinfo })
}

/// Handle RTM_NEWADDR.
/// # C: O(N attrs + addr_table size)
pub fn handle_newaddr(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
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
    let attrs = &full_msg[ifa_off + Ifaddrmsg::SIZE..];
    let parsed = match parse_newaddr_attrs(attrs) {
        Some(a) => a,
        None => return build_ack(req, -22),
    };
    let addr = parsed.addr;
    let flags = parsed.flags.unwrap_or_else(|| {
        if parsed.cacheinfo.is_some() { ifa_flags } else { ifa_flags | net::iface_addr::IFA_F_PERMANENT }
    });
    let ns = net::netdev::current_net_ns();
    net::iface_addr::set_prefix_meta(
        ns,
        net::NetIfaceId::from_raw(ifindex),
        net::Ipv4Addr::from_u32(u32::from_be_bytes(addr)),
        prefixlen,
        scope,
        flags,
        cache_to_net(parsed.cacheinfo.unwrap_or(IfaCacheInfo::PERMANENT)),
    );
    crate::mcast::notify_addr(false, ifindex, addr, prefixlen, scope);
    build_ack(req, 0)
}

/// Handle RTM_DELADDR.
/// # C: O(N attrs + addr_table size)
pub fn handle_deladdr(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let ifa_off = Nlmsghdr::SIZE;
    if full_msg.len() < ifa_off + Ifaddrmsg::SIZE { return build_ack(req, -22); }
    let prefixlen = full_msg[ifa_off + 1];
    let ifindex = u32::from_ne_bytes([
        full_msg[ifa_off + 4], full_msg[ifa_off + 5], full_msg[ifa_off + 6], full_msg[ifa_off + 7],
    ]);
    let attrs = &full_msg[ifa_off + Ifaddrmsg::SIZE..];
    let addr = match parse_newaddr_attrs(attrs) {
        Some(a) => a,
        None => return build_ack(req, -22),
    }.addr;
    let n = addr_remove(net::netdev::current_net_ns(), ifindex, addr, prefixlen);
    if n > 0 { crate::mcast::notify_addr(true, ifindex, addr, prefixlen, 0); }
    build_ack(req, if n > 0 { 0 } else { -2 })
}
