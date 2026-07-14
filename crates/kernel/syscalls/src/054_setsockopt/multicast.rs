#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use hal::USER_VA_END;
use syscall::errno::Errno;

use crate::net_common::errno_from_neterr;

use super::main::read_u8_or_i32;

pub(super) use net::mcast_filter::SourceOp;

fn supports_ipv4(sock: &net::sock::InetSocket) -> bool {
    matches!(sock.family.load(core::sync::atomic::Ordering::Acquire), net::sock::AF_INET | net::sock::AF_INET6)
}

pub(super) fn read_ipv4_at(ptr: u64) -> Option<net::Ipv4Addr> {
    if ptr + 4 > USER_VA_END { return None; }
    // SAFETY: ptr+4 was checked; in_addr is a network-order u32.
    let be = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    Some(net::Ipv4Addr::from_u32(u32::from_be(be)))
}

pub(super) fn ipv4_mcast_if(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32) -> i64 {
    if !supports_ipv4(sock) { return -(Errno::Enoprotoopt.as_i32() as i64); }
    if optlen < 4 { return -(Errno::Einval.as_i32() as i64); }
    let copy_len = if optlen >= 12 { 12 } else if optlen >= 8 { 8 } else { 4 };
    let Some(end) = optval.checked_add(copy_len) else { return -(Errno::Efault.as_i32() as i64); };
    if end > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let addr_off = if optlen >= 8 { 4 } else { 0 };
    let Some(addr) = read_ipv4_at(optval + addr_off) else { return -(Errno::Efault.as_i32() as i64); };
    let ifindex = if optlen >= 12 {
        // SAFETY: ip_mreqn ifindex sits at byte 8 and optlen/range were checked.
        let raw = unsafe { core::ptr::read_volatile((optval + 8) as *const i32) };
        if raw < 0 { return -(Errno::Eaddrnotavail.as_i32() as i64); }
        raw as u32
    } else { 0 };
    match sock.set_v4_mcast_iface(addr, ifindex) {
        Ok(()) => 0,
        Err(net::NetError::Enodev) => -(Errno::Eaddrnotavail.as_i32() as i64),
        Err(error) => errno_from_neterr(error),
    }
}

pub(super) fn ipv4_mcast_membership(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32, join: bool) -> i64 {
    if super::main::is_tcp(sock) { return -(Errno::Eproto.as_i32() as i64); }
    if !supports_ipv4(sock) { return -(Errno::Enoprotoopt.as_i32() as i64); }
    if optlen < 8 { return -(Errno::Einval.as_i32() as i64); }
    let copy_len = if optlen >= 12 { 12 } else { 8 };
    let Some(end) = optval.checked_add(copy_len) else { return -(Errno::Efault.as_i32() as i64); };
    if optval == 0 || end > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let Some(group) = read_ipv4_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(req_src) = read_ipv4_at(optval + 4) else { return -(Errno::Efault.as_i32() as i64); };
    if !group.is_multicast() { return -(Errno::Einval.as_i32() as i64); }
    let req_if = if optlen >= 12 {
        // SAFETY: ip_mreqn ifindex sits at byte 8 and optlen/range were checked.
        let raw = unsafe { core::ptr::read_volatile((optval + 8) as *const i32) };
        if raw < 0 { return -(Errno::Enodev.as_i32() as i64); }
        raw as u32
    } else { 0 };
    let result = sock.change_v4_mcast_req(req_if, req_src, group, join);
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

fn read_ipv6_at(ptr: u64) -> Option<net::Ipv6Addr> {
    if ptr + 16 > USER_VA_END { return None; }
    let mut addr = [0u8; 16];
    for (index, byte) in addr.iter_mut().enumerate() {
        // SAFETY: ptr + sizeof(in6_addr) was validated in user range.
        *byte = unsafe { core::ptr::read_volatile((ptr + index as u64) as *const u8) };
    }
    Some(net::Ipv6Addr(addr))
}

fn read_sockaddr_storage_v6(ptr: u64) -> Option<net::Ipv6Addr> {
    const AF_INET6: u16 = 10;
    if ptr + 28 > USER_VA_END { return None; }
    // SAFETY: sockaddr_storage starts with a native-endian address family.
    let family = unsafe { core::ptr::read_volatile(ptr as *const u16) };
    if family != AF_INET6 { return None; }
    read_ipv6_at(ptr + 8)
}

pub(super) fn ipv4_mcast_source_req(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32, op: SourceOp) -> i64 {
    if !supports_ipv4(sock) { return -(Errno::Enoprotoopt.as_i32() as i64); }
    if optlen != 12 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(group) = read_ipv4_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(ifaddr) = read_ipv4_at(optval + 4) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(source) = read_ipv4_at(optval + 8) else { return -(Errno::Efault.as_i32() as i64); };
    if !group.is_multicast() || source.is_unspecified() { return -(Errno::Einval.as_i32() as i64); }
    match sock.source_v4_mcast_req(0, ifaddr, group, source, op) {
        Ok(()) => 0, Err(error) => errno_from_neterr(error),
    }
}

pub(super) fn ipv4_msfilter(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32) -> i64 {
    if !supports_ipv4(sock) { return -(Errno::Enoprotoopt.as_i32() as i64); }
    if optlen < 16 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(group) = read_ipv4_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(ifaddr) = read_ipv4_at(optval + 4) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(mode_raw) = read_u32_at(optval + 8) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(numsrc) = read_u32_at(optval + 12) else { return -(Errno::Efault.as_i32() as i64); };
    if !group.is_multicast() || 16u64.saturating_add(numsrc as u64 * 4) > optlen as u64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mode = match net::mcast_filter::FilterMode::from_u32(mode_raw) { Ok(m) => m, Err(e) => return errno_from_neterr(e) };
    let mut sources = alloc::vec::Vec::new();
    for i in 0..numsrc as u64 {
        let Some(src) = read_ipv4_at(optval + 16 + i * 4) else { return -(Errno::Efault.as_i32() as i64); };
        if src.is_unspecified() { return -(Errno::Einval.as_i32() as i64); }
        sources.push(src);
    }
    match sock.set_v4_mcast_filter_req(0, ifaddr, group, mode, &sources) {
        Ok(()) => 0, Err(error) => errno_from_neterr(error),
    }
}

pub(super) fn ipv4_mcast_group_req(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32, join: bool) -> i64 {
    if !supports_ipv4(sock) { return -(Errno::Enoprotoopt.as_i32() as i64); }
    if optlen < 136 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v4(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    if !group.is_multicast() { return -(Errno::Einval.as_i32() as i64); }
    let result = sock.change_v4_mcast_req(ifindex, net::Ipv4Addr::ANY, group, join);
    match result { Ok(()) => 0, Err(e) => errno_from_neterr(e) }
}

pub(super) fn ipv4_mcast_group_source_req(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32, op: SourceOp) -> i64 {
    if !supports_ipv4(sock) { return -(Errno::Enoprotoopt.as_i32() as i64); }
    if optlen != 264 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v4(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    let Some(source) = read_sockaddr_storage_v4(optval + 136) else { return -(Errno::Einval.as_i32() as i64); };
    if !group.is_multicast() || source.is_unspecified() { return -(Errno::Einval.as_i32() as i64); }
    match sock.source_v4_mcast_req(ifindex, net::Ipv4Addr::ANY, group, source, op) {
        Ok(()) => 0, Err(error) => errno_from_neterr(error),
    }
}

pub(super) fn ipv4_group_filter(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32) -> i64 {
    if !supports_ipv4(sock) { return -(Errno::Enoprotoopt.as_i32() as i64); }
    if optlen < 144 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v4(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    let Some(mode_raw) = read_u32_at(optval + 136) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(numsrc) = read_u32_at(optval + 140) else { return -(Errno::Efault.as_i32() as i64); };
    if !group.is_multicast() || 144u64.saturating_add(numsrc as u64 * 128) > optlen as u64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mode = match net::mcast_filter::FilterMode::from_u32(mode_raw) { Ok(m) => m, Err(e) => return errno_from_neterr(e) };
    let mut sources = alloc::vec::Vec::new();
    for i in 0..numsrc as u64 {
        let Some(src) = read_sockaddr_storage_v4(optval + 144 + i * 128) else { return -(Errno::Einval.as_i32() as i64); };
        if src.is_unspecified() { return -(Errno::Einval.as_i32() as i64); }
        sources.push(src);
    }
    match sock.set_v4_mcast_filter_req(ifindex, net::Ipv4Addr::ANY, group, mode, &sources) {
        Ok(()) => 0, Err(error) => errno_from_neterr(error),
    }
}

pub(super) fn ipv6_mcast_membership(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32, join: bool) -> i64 {
    const IPV6_MREQ_LEN: u64 = 20;
    if sock.family.load(core::sync::atomic::Ordering::Acquire) != net::sock::AF_INET6 {
        return -(Errno::Enoprotoopt.as_i32() as i64);
    }
    if (optlen as u64) < IPV6_MREQ_LEN { return -(Errno::Einval.as_i32() as i64); }
    if super::main::is_tcp(sock) { return -(Errno::Eproto.as_i32() as i64); }
    let Some(end) = optval.checked_add(IPV6_MREQ_LEN) else { return -(Errno::Efault.as_i32() as i64); };
    if optval == 0 || end > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let mut addr = [0u8; 16];
    for i in 0..addr.len() {
        // SAFETY: optval + sizeof(ipv6_mreq) was validated in user range.
        addr[i] = unsafe { core::ptr::read_volatile((optval + i as u64) as *const u8) };
    }
    // SAFETY: ipv6_mreq is 16-byte in6_addr followed by a u32 ifindex.
    let req_if = unsafe { core::ptr::read_volatile((optval + 16) as *const u32) };
    let group = net::Ipv6Addr(addr);
    if !group.is_multicast() { return -(Errno::Einval.as_i32() as i64); }
    let result = sock.change_v6_mcast(req_if, group, join);
    match result { Ok(()) => 0, Err(e) => errno_from_neterr(e) }
}

pub(super) fn ipv6_mcast_group_req(sock: &Arc<net::sock::InetSocket>, optval: u64,
                                   optlen: u32, join: bool) -> i64 {
    if sock.family.load(core::sync::atomic::Ordering::Acquire) != net::sock::AF_INET6 {
        return -(Errno::Enoprotoopt.as_i32() as i64);
    }
    if optlen < 136 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v6(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    if !group.is_multicast() { return -(Errno::Einval.as_i32() as i64); }
    match sock.change_v6_mcast(ifindex, group, join) {
        Ok(()) => 0, Err(error) => errno_from_neterr(error),
    }
}

pub(super) fn ipv6_mcast_group_source_req(sock: &Arc<net::sock::InetSocket>, optval: u64,
                                          optlen: u32, op: SourceOp) -> i64 {
    if sock.family.load(core::sync::atomic::Ordering::Acquire) != net::sock::AF_INET6 {
        return -(Errno::Enoprotoopt.as_i32() as i64);
    }
    if optlen < 264 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v6(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    let Some(source) = read_sockaddr_storage_v6(optval + 136) else { return -(Errno::Einval.as_i32() as i64); };
    if !group.is_multicast() || source.is_unspecified() || source.is_multicast() {
        return -(Errno::Einval.as_i32() as i64);
    }
    match sock.source_v6_mcast(ifindex, group, source, op) {
        Ok(()) => 0, Err(error) => errno_from_neterr(error),
    }
}

pub(super) fn ipv6_group_filter(sock: &Arc<net::sock::InetSocket>, optval: u64,
                                optlen: u32) -> i64 {
    if sock.family.load(core::sync::atomic::Ordering::Acquire) != net::sock::AF_INET6 {
        return -(Errno::Enoprotoopt.as_i32() as i64);
    }
    if optlen < 144 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v6(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    let Some(mode_raw) = read_u32_at(optval + 136) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(numsrc) = read_u32_at(optval + 140) else { return -(Errno::Efault.as_i32() as i64); };
    if !group.is_multicast() || 144u64.saturating_add(numsrc as u64 * 128) > optlen as u64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mode = match net::mcast_filter::FilterMode::from_u32(mode_raw) {
        Ok(mode) => mode, Err(error) => return errno_from_neterr(error),
    };
    let mut sources = alloc::vec::Vec::new();
    for index in 0..numsrc as u64 {
        let Some(source) = read_sockaddr_storage_v6(optval + 144 + index * 128) else {
            return -(Errno::Einval.as_i32() as i64);
        };
        if source.is_unspecified() || source.is_multicast() { return -(Errno::Einval.as_i32() as i64); }
        sources.push(source);
    }
    match sock.set_v6_mcast_filter(ifindex, group, mode, &sources) {
        Ok(()) => 0, Err(error) => errno_from_neterr(error),
    }
}
