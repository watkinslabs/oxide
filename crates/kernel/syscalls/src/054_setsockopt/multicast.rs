#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use hal::USER_VA_END;
use syscall::errno::Errno;

use crate::net_common::errno_from_neterr;

use super::main::read_u8_or_i32;

#[derive(Copy, Clone)]
pub(super) enum SourceOp { Join, Leave, Block, Unblock }

pub(super) fn read_ipv4_at(ptr: u64) -> Option<net::Ipv4Addr> {
    if ptr + 4 > USER_VA_END { return None; }
    // SAFETY: ptr+4 was checked; in_addr is a network-order u32.
    let be = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    Some(net::Ipv4Addr::from_u32(u32::from_be(be)))
}

fn iface_for_v4_addr(addr: net::Ipv4Addr) -> Option<net::NetIfaceId> {
    net::sock::stack().routes.snapshot().into_iter()
        .find(|r| r.src_hint == Some(addr))
        .map(|r| r.iface)
}

fn default_v4_mcast_iface(sock: &Arc<net::sock::InetSocket>, group: net::Ipv4Addr) -> Option<net::NetIfaceId> {
    let raw = sock.opts.ip_mcast_ifindex.load(core::sync::atomic::Ordering::Acquire);
    if raw != 0 { return Some(net::NetIfaceId::from_raw(raw)); }
    let addr = net::Ipv4Addr::from_u32(sock.opts.ip_mcast_ifaddr.load(core::sync::atomic::Ordering::Acquire));
    if !addr.is_unspecified() { return iface_for_v4_addr(addr); }
    let bound = sock.opts.bound_ifindex.load(core::sync::atomic::Ordering::Acquire);
    if bound != 0 { return Some(net::NetIfaceId::from_raw(bound)); }
    if let Some(r) = net::sock::stack().routes.lookup(group) { return Some(r.iface); }
    let routes = net::sock::stack().routes.snapshot();
    if routes.len() == 1 { Some(routes[0].iface) } else { None }
}

pub(super) fn ipv4_mcast_if(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32) -> i64 {
    if sock.family.load(core::sync::atomic::Ordering::Acquire) != net::sock::AF_INET {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    if optlen < 4 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(addr) = read_ipv4_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let ifindex = if optlen >= 12 {
        // SAFETY: ip_mreqn ifindex sits at byte 8 and optlen/range were checked.
        unsafe { core::ptr::read_volatile((optval + 8) as *const i32).max(0) as u32 }
    } else { 0 };
    if ifindex != 0 && net::sock::stack().ifaces.lookup(net::NetIfaceId::from_raw(ifindex)).is_none() {
        return -(Errno::Enodev.as_i32() as i64);
    }
    if ifindex == 0 && !addr.is_unspecified() && iface_for_v4_addr(addr).is_none() {
        return -(Errno::Enodev.as_i32() as i64);
    }
    sock.opts.ip_mcast_ifaddr.store(addr.as_u32(), core::sync::atomic::Ordering::Release);
    sock.opts.ip_mcast_ifindex.store(ifindex, core::sync::atomic::Ordering::Release);
    0
}

pub(super) fn ipv4_mcast_membership(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32, join: bool) -> i64 {
    if sock.family.load(core::sync::atomic::Ordering::Acquire) != net::sock::AF_INET {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    if optlen < 8 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(group) = read_ipv4_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(req_src) = read_ipv4_at(optval + 4) else { return -(Errno::Efault.as_i32() as i64); };
    if !group.is_multicast() { return -(Errno::Einval.as_i32() as i64); }
    let req_if = if optlen >= 12 {
        // SAFETY: ip_mreqn ifindex sits at byte 8 and optlen/range were checked.
        unsafe { core::ptr::read_volatile((optval + 8) as *const i32).max(0) as u32 }
    } else { 0 };
    let iface = if req_if != 0 {
        net::NetIfaceId::from_raw(req_if)
    } else if !req_src.is_unspecified() {
        match iface_for_v4_addr(req_src) {
            Some(i) => i,
            None => return -(Errno::Enodev.as_i32() as i64),
        }
    } else {
        match default_v4_mcast_iface(sock, group) {
            Some(i) => i,
            None => return -(Errno::Enodev.as_i32() as i64),
        }
    };
    if net::sock::stack().ifaces.lookup(iface).is_none() {
        return -(Errno::Enodev.as_i32() as i64);
    }
    let src = if !req_src.is_unspecified() { req_src } else { *sock.local_ip.lock() };
    let result = if join { net::sock::stack().join_ipv4_multicast(iface, group, src) }
    else { net::sock::stack().leave_ipv4_multicast(iface, group, src) };
    match result { Ok(()) => 0, Err(e) => errno_from_neterr(e) }
}

fn read_u32_at(ptr: u64) -> Option<u32> {
    if ptr + 4 > USER_VA_END { return None; }
    // SAFETY: ptr+4 was checked; scalar ABI field read.
    Some(unsafe { core::ptr::read_volatile(ptr as *const u32) })
}

fn read_sockaddr_storage_v4(ptr: u64) -> Option<net::Ipv4Addr> {
    const AF_INET: u16 = 2;
    if ptr + 16 > USER_VA_END { return None; }
    // SAFETY: sockaddr_storage begins with sockaddr_in-compatible fields.
    let family = unsafe { core::ptr::read_volatile(ptr as *const u16) };
    if family != AF_INET { return None; }
    read_ipv4_at(ptr + 4)
}

fn udp_port(sock: &Arc<net::sock::InetSocket>) -> Result<u16, i64> {
    if !matches!(&*sock.kind.lock(), net::sock::SockKind::Udp) { return Err(-(Errno::Einval.as_i32() as i64)); }
    sock.ensure_bound().map_err(errno_from_neterr)
}

fn resolve_v4_mcast_iface(sock: &Arc<net::sock::InetSocket>, group: net::Ipv4Addr, ifindex: u32, ifaddr: net::Ipv4Addr) -> Result<net::NetIfaceId, i64> {
    let iface = if ifindex != 0 {
        net::NetIfaceId::from_raw(ifindex)
    } else if !ifaddr.is_unspecified() {
        iface_for_v4_addr(ifaddr).ok_or(-(Errno::Enodev.as_i32() as i64))?
    } else {
        default_v4_mcast_iface(sock, group).ok_or(-(Errno::Enodev.as_i32() as i64))?
    };
    if net::sock::stack().ifaces.lookup(iface).is_none() { return Err(-(Errno::Enodev.as_i32() as i64)); }
    Ok(iface)
}

fn apply_source_op(sock: &Arc<net::sock::InetSocket>, group: net::Ipv4Addr, iface: net::NetIfaceId, source: net::Ipv4Addr, op: SourceOp) -> i64 {
    use net::mcast_filter;
    if !group.is_multicast() || source.is_unspecified() { return -(Errno::Einval.as_i32() as i64); }
    let port = match udp_port(sock) { Ok(p) => p, Err(e) => return e };
    match op {
        SourceOp::Join => {
            let local = *sock.local_ip.lock();
            if let Err(e) = net::sock::stack().join_ipv4_multicast(iface, group, local) {
                return errno_from_neterr(e);
            }
            mcast_filter::add_source(port, iface, group, source);
        }
        SourceOp::Leave => mcast_filter::drop_source(port, iface, group, source),
        SourceOp::Block => mcast_filter::block_source(port, iface, group, source),
        SourceOp::Unblock => mcast_filter::unblock_source(port, iface, group, source),
    }
    0
}

pub(super) fn ipv4_mcast_source_req(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32, op: SourceOp) -> i64 {
    if sock.family.load(core::sync::atomic::Ordering::Acquire) != net::sock::AF_INET {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    if optlen < 12 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(group) = read_ipv4_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(ifaddr) = read_ipv4_at(optval + 4) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(source) = read_ipv4_at(optval + 8) else { return -(Errno::Efault.as_i32() as i64); };
    let iface = match resolve_v4_mcast_iface(sock, group, 0, ifaddr) { Ok(i) => i, Err(e) => return e };
    apply_source_op(sock, group, iface, source, op)
}

pub(super) fn ipv4_msfilter(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32) -> i64 {
    if sock.family.load(core::sync::atomic::Ordering::Acquire) != net::sock::AF_INET {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    if optlen < 16 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(group) = read_ipv4_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(ifaddr) = read_ipv4_at(optval + 4) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(mode_raw) = read_u32_at(optval + 8) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(numsrc) = read_u32_at(optval + 12) else { return -(Errno::Efault.as_i32() as i64); };
    if !group.is_multicast() || 16u64.saturating_add(numsrc as u64 * 4) > optlen as u64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mode = match net::mcast_filter::FilterMode::from_u32(mode_raw) { Ok(m) => m, Err(e) => return errno_from_neterr(e) };
    let iface = match resolve_v4_mcast_iface(sock, group, 0, ifaddr) { Ok(i) => i, Err(e) => return e };
    let port = match udp_port(sock) { Ok(p) => p, Err(e) => return e };
    let mut sources = alloc::vec::Vec::new();
    for i in 0..numsrc as u64 {
        let Some(src) = read_ipv4_at(optval + 16 + i * 4) else { return -(Errno::Efault.as_i32() as i64); };
        if src.is_unspecified() { return -(Errno::Einval.as_i32() as i64); }
        sources.push(src);
    }
    net::mcast_filter::set(port, iface, group, mode, &sources);
    let local = *sock.local_ip.lock();
    match net::sock::stack().join_ipv4_multicast(iface, group, local) { Ok(()) => 0, Err(e) => errno_from_neterr(e) }
}

pub(super) fn ipv4_mcast_group_req(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32, join: bool) -> i64 {
    if sock.family.load(core::sync::atomic::Ordering::Acquire) != net::sock::AF_INET {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    if optlen < 136 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v4(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    if !group.is_multicast() { return -(Errno::Einval.as_i32() as i64); }
    let iface = match resolve_v4_mcast_iface(sock, group, ifindex, net::Ipv4Addr::ANY) { Ok(i) => i, Err(e) => return e };
    let src = *sock.local_ip.lock();
    let result = if join {
        net::sock::stack().join_ipv4_multicast(iface, group, src)
    } else {
        if let Ok(port) = udp_port(sock) { net::mcast_filter::clear_group(port, iface, group); }
        net::sock::stack().leave_ipv4_multicast(iface, group, src)
    };
    match result { Ok(()) => 0, Err(e) => errno_from_neterr(e) }
}

pub(super) fn ipv4_mcast_group_source_req(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32, op: SourceOp) -> i64 {
    if sock.family.load(core::sync::atomic::Ordering::Acquire) != net::sock::AF_INET {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    if optlen < 264 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v4(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    let Some(source) = read_sockaddr_storage_v4(optval + 136) else { return -(Errno::Einval.as_i32() as i64); };
    let iface = match resolve_v4_mcast_iface(sock, group, ifindex, net::Ipv4Addr::ANY) { Ok(i) => i, Err(e) => return e };
    apply_source_op(sock, group, iface, source, op)
}

pub(super) fn ipv4_group_filter(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32) -> i64 {
    if sock.family.load(core::sync::atomic::Ordering::Acquire) != net::sock::AF_INET {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    if optlen < 144 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v4(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    let Some(mode_raw) = read_u32_at(optval + 136) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(numsrc) = read_u32_at(optval + 140) else { return -(Errno::Efault.as_i32() as i64); };
    if !group.is_multicast() || 144u64.saturating_add(numsrc as u64 * 128) > optlen as u64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mode = match net::mcast_filter::FilterMode::from_u32(mode_raw) { Ok(m) => m, Err(e) => return errno_from_neterr(e) };
    let iface = match resolve_v4_mcast_iface(sock, group, ifindex, net::Ipv4Addr::ANY) { Ok(i) => i, Err(e) => return e };
    let port = match udp_port(sock) { Ok(p) => p, Err(e) => return e };
    let mut sources = alloc::vec::Vec::new();
    for i in 0..numsrc as u64 {
        let Some(src) = read_sockaddr_storage_v4(optval + 144 + i * 128) else { return -(Errno::Einval.as_i32() as i64); };
        if src.is_unspecified() { return -(Errno::Einval.as_i32() as i64); }
        sources.push(src);
    }
    net::mcast_filter::set(port, iface, group, mode, &sources);
    let local = *sock.local_ip.lock();
    match net::sock::stack().join_ipv4_multicast(iface, group, local) { Ok(()) => 0, Err(e) => errno_from_neterr(e) }
}

pub(super) fn ipv6_mcast_membership(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32, join: bool) -> i64 {
    const IPV6_MREQ_LEN: u64 = 20;
    if sock.family.load(core::sync::atomic::Ordering::Acquire) != net::sock::AF_INET6 {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    if (optlen as u64) < IPV6_MREQ_LEN { return -(Errno::Einval.as_i32() as i64); }
    let Some(end) = optval.checked_add(IPV6_MREQ_LEN) else { return -(Errno::Efault.as_i32() as i64); };
    if end > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let mut addr = [0u8; 16];
    for i in 0..addr.len() {
        // SAFETY: optval + sizeof(ipv6_mreq) was validated in user range.
        addr[i] = unsafe { core::ptr::read_volatile((optval + i as u64) as *const u8) };
    }
    // SAFETY: ipv6_mreq is 16-byte in6_addr followed by a u32 ifindex.
    let req_if = unsafe { core::ptr::read_volatile((optval + 16) as *const u32) };
    let group = net::Ipv6Addr(addr);
    if !group.is_multicast() { return -(Errno::Einval.as_i32() as i64); }
    let iface = if req_if != 0 {
        net::NetIfaceId::from_raw(req_if)
    } else {
        let raw = sock.opts.bound_ifindex.load(core::sync::atomic::Ordering::Acquire);
        if raw == 0 { return -(Errno::Enodev.as_i32() as i64); }
        net::NetIfaceId::from_raw(raw)
    };
    if net::sock::stack().ifaces.lookup(iface).is_none() { return -(Errno::Enodev.as_i32() as i64); }
    let src = *sock.local_ip6.lock();
    let result = if join { net::sock::stack().join_ipv6_multicast(iface, group, src) }
    else { net::sock::stack().leave_ipv6_multicast(iface, group, src) };
    match result { Ok(()) => 0, Err(e) => errno_from_neterr(e) }
}
