use alloc::sync::Arc;

use hal::USER_VA_END;
use syscall::errno::Errno;

use crate::net_errno::errno_from_neterr;

pub(super) use net::mcast_filter::SourceOp;

fn encode(result: net::NetResult<()>) -> i64 {
    match result { Ok(()) => 0, Err(error) => errno_from_neterr(error) }
}

fn preflight(sock: &net::sock::InetSocket, op: net::sock_mcast::McastSetOp) -> Result<(), i64> {
    sock.preflight_mcast_set(op).map_err(errno_from_neterr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_multicast_errors_cross_syscall_boundary_exactly() {
        assert_eq!(encode(Err(net::NetError::Eproto)), -(Errno::Eproto.as_i32() as i64));
        assert_eq!(encode(Err(net::NetError::Enoprotoopt)), -(Errno::Enoprotoopt.as_i32() as i64));
        assert_eq!(encode(Err(net::NetError::Eopnotsupp)), -(Errno::Eopnotsupp.as_i32() as i64));
        assert_eq!(encode(Err(net::NetError::Eaddrnotavail)), -(Errno::Eaddrnotavail.as_i32() as i64));
        assert_eq!(encode(Err(net::NetError::Enodev)), -(Errno::Enodev.as_i32() as i64));
        assert_eq!(encode(Err(net::NetError::Einval)), -(Errno::Einval.as_i32() as i64));
    }

    #[test]
    fn multicast_uapi_short_buffers_fail_before_access() {
        let sock4 = Arc::new(net::sock::InetSocket::new_udp());
        let sock6 = Arc::new(net::sock::InetSocket::new_udp6());
        assert_eq!(ipv4_mcast_if(&sock4, 0, 3), -(Errno::Einval.as_i32() as i64));
        assert_eq!(ipv4_mcast_membership(&sock4, 0, 7, true), -(Errno::Einval.as_i32() as i64));
        assert_eq!(ipv6_mcast_membership(&sock6, 0, 19, true), -(Errno::Einval.as_i32() as i64));
    }

    #[test]
    fn multicast_set_preflight_precedes_uapi_with_linux_errors() {
        let unix = Arc::new(net::sock::InetSocket::new_unix());
        let tcp4 = Arc::new(net::sock::InetSocket::new_tcp());
        let udp4 = Arc::new(net::sock::InetSocket::new_udp());
        assert_eq!(ipv4_mcast_membership(&unix, 0, 0, true),
            -(Errno::Eopnotsupp.as_i32() as i64));
        assert_eq!(ipv6_mcast_membership(&unix, 0, 0, true),
            -(Errno::Eopnotsupp.as_i32() as i64));
        assert_eq!(ipv4_mcast_membership(&tcp4, 0, 0, true),
            -(Errno::Eproto.as_i32() as i64));
        assert_eq!(ipv6_mcast_membership(&udp4, 0, 0, true),
            -(Errno::Enoprotoopt.as_i32() as i64));
    }
}

pub(super) fn read_ipv4_at(ptr: u64) -> Option<net::Ipv4Addr> {
    let mut bytes = [0u8; 4];
    uaccess::copy_from_user(&mut bytes, ptr).ok()?;
    let be = u32::from_ne_bytes(bytes);
    Some(net::Ipv4Addr::from_u32(u32::from_be(be)))
}

pub(super) fn ipv4_mcast_if(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32) -> i64 {
    if let Err(error) = preflight(sock, net::sock_mcast::McastSetOp::V4Iface) { return error; }
    if optlen < 4 { return -(Errno::Einval.as_i32() as i64); }
    let copy_len = if optlen >= 12 { 12 } else if optlen >= 8 { 8 } else { 4 };
    let Some(end) = optval.checked_add(copy_len) else { return -(Errno::Efault.as_i32() as i64); };
    if end > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let addr_off = if optlen >= 8 { 4 } else { 0 };
    let Some(addr) = read_ipv4_at(optval + addr_off) else { return -(Errno::Efault.as_i32() as i64); };
    let ifindex = if optlen >= 12 {
        let Some(value) = read_u32_at(optval + 8) else { return -(Errno::Efault.as_i32() as i64); };
        value as i32
    } else { 0 };
    encode(sock.set_mcast_scalar(net::sock_mcast::McastScalar::V4Iface { addr, ifindex }))
}

pub(super) fn ipv4_mcast_membership(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32, join: bool) -> i64 {
    if let Err(error) = preflight(sock, net::sock_mcast::McastSetOp::V4Membership) { return error; }
    if optlen < 8 { return -(Errno::Einval.as_i32() as i64); }
    let copy_len = if optlen >= 12 { 12 } else { 8 };
    let Some(end) = optval.checked_add(copy_len) else { return -(Errno::Efault.as_i32() as i64); };
    if optval == 0 || end > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let Some(group) = read_ipv4_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(req_src) = read_ipv4_at(optval + 4) else { return -(Errno::Efault.as_i32() as i64); };
    let req_if = if optlen >= 12 {
        let Some(value) = read_u32_at(optval + 8) else { return -(Errno::Efault.as_i32() as i64); };
        value as i32
    } else { 0 };
    encode(sock.change_v4_mcast_membership(req_if, req_src, group, join))
}

fn read_u32_at(ptr: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    uaccess::copy_from_user(&mut bytes, ptr).ok()?;
    Some(u32::from_ne_bytes(bytes))
}

fn read_sockaddr_storage_v4(ptr: u64) -> Option<net::Ipv4Addr> {
    const AF_INET: u16 = 2;
    let mut bytes = [0u8; 16];
    uaccess::copy_from_user(&mut bytes, ptr).ok()?;
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    if family != AF_INET { return None; }
    Some(net::Ipv4Addr::from_u32(u32::from_be_bytes(bytes[4..8].try_into().unwrap())))
}

fn read_ipv6_at(ptr: u64) -> Option<net::Ipv6Addr> {
    let mut addr = [0u8; 16];
    uaccess::copy_from_user(&mut addr, ptr).ok()?;
    Some(net::Ipv6Addr(addr))
}

fn read_sockaddr_storage_v6(ptr: u64) -> Option<net::Ipv6Addr> {
    const AF_INET6: u16 = 10;
    let mut bytes = [0u8; 28];
    uaccess::copy_from_user(&mut bytes, ptr).ok()?;
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    if family != AF_INET6 { return None; }
    Some(net::Ipv6Addr(bytes[8..24].try_into().unwrap()))
}

pub(super) fn ipv4_mcast_source_req(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32, op: SourceOp) -> i64 {
    if let Err(error) = preflight(sock, net::sock_mcast::McastSetOp::V4Other) { return error; }
    if optlen != 12 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(group) = read_ipv4_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(ifaddr) = read_ipv4_at(optval + 4) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(source) = read_ipv4_at(optval + 8) else { return -(Errno::Efault.as_i32() as i64); };
    encode(sock.source_v4_mcast_req(0, ifaddr, group, source, op))
}

pub(super) fn ipv4_msfilter(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32) -> i64 {
    if let Err(error) = preflight(sock, net::sock_mcast::McastSetOp::V4Other) { return error; }
    if optlen < 16 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(group) = read_ipv4_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(ifaddr) = read_ipv4_at(optval + 4) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(mode_raw) = read_u32_at(optval + 8) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(numsrc) = read_u32_at(optval + 12) else { return -(Errno::Efault.as_i32() as i64); };
    if 16u64.saturating_add(numsrc as u64 * 4) > optlen as u64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mut sources = alloc::vec::Vec::new();
    for i in 0..numsrc as u64 {
        let Some(src) = read_ipv4_at(optval + 16 + i * 4) else { return -(Errno::Efault.as_i32() as i64); };
        sources.push(src);
    }
    encode(sock.set_v4_mcast_filter_raw_req(0, ifaddr, group, mode_raw, &sources))
}

pub(super) fn ipv4_mcast_group_req(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32, join: bool) -> i64 {
    if let Err(error) = preflight(sock, net::sock_mcast::McastSetOp::V4Other) { return error; }
    if optlen < 136 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v4(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    encode(sock.change_v4_mcast_req(ifindex, net::Ipv4Addr::ANY, group, join))
}

pub(super) fn ipv4_mcast_group_source_req(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32, op: SourceOp) -> i64 {
    if let Err(error) = preflight(sock, net::sock_mcast::McastSetOp::V4Other) { return error; }
    if optlen != 264 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v4(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    let Some(source) = read_sockaddr_storage_v4(optval + 136) else { return -(Errno::Einval.as_i32() as i64); };
    encode(sock.source_v4_mcast_req(ifindex, net::Ipv4Addr::ANY, group, source, op))
}

pub(super) fn ipv4_group_filter(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32) -> i64 {
    if let Err(error) = preflight(sock, net::sock_mcast::McastSetOp::V4Other) { return error; }
    if optlen < 144 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v4(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    let Some(mode_raw) = read_u32_at(optval + 136) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(numsrc) = read_u32_at(optval + 140) else { return -(Errno::Efault.as_i32() as i64); };
    if 144u64.saturating_add(numsrc as u64 * 128) > optlen as u64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mut sources = alloc::vec::Vec::new();
    for i in 0..numsrc as u64 {
        let Some(src) = read_sockaddr_storage_v4(optval + 144 + i * 128) else { return -(Errno::Einval.as_i32() as i64); };
        sources.push(src);
    }
    encode(sock.set_v4_mcast_filter_raw_req(ifindex, net::Ipv4Addr::ANY, group, mode_raw, &sources))
}

pub(super) fn ipv6_mcast_membership(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32, join: bool) -> i64 {
    if let Err(error) = preflight(sock, net::sock_mcast::McastSetOp::V6Membership) { return error; }
    const IPV6_MREQ_LEN: u64 = 20;
    if (optlen as u64) < IPV6_MREQ_LEN { return -(Errno::Einval.as_i32() as i64); }
    let Some(end) = optval.checked_add(IPV6_MREQ_LEN) else { return -(Errno::Efault.as_i32() as i64); };
    if optval == 0 || end > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let Some(group) = read_ipv6_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(req_if) = read_u32_at(optval + 16) else { return -(Errno::Efault.as_i32() as i64); };
    encode(sock.change_v6_mcast_membership(req_if, group, join))
}

pub(super) fn ipv6_mcast_group_req(sock: &Arc<net::sock::InetSocket>, optval: u64,
                                   optlen: u32, join: bool) -> i64 {
    if let Err(error) = preflight(sock, net::sock_mcast::McastSetOp::V6Other) { return error; }
    if optlen < 136 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v6(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    encode(sock.change_v6_mcast(ifindex, group, join))
}

pub(super) fn ipv6_mcast_group_source_req(sock: &Arc<net::sock::InetSocket>, optval: u64,
                                          optlen: u32, op: SourceOp) -> i64 {
    if let Err(error) = preflight(sock, net::sock_mcast::McastSetOp::V6Other) { return error; }
    if optlen < 264 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v6(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    let Some(source) = read_sockaddr_storage_v6(optval + 136) else { return -(Errno::Einval.as_i32() as i64); };
    encode(sock.source_v6_mcast(ifindex, group, source, op))
}

pub(super) fn ipv6_group_filter(sock: &Arc<net::sock::InetSocket>, optval: u64,
                                optlen: u32) -> i64 {
    if let Err(error) = preflight(sock, net::sock_mcast::McastSetOp::V6Other) { return error; }
    if optlen < 144 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v6(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    let Some(mode_raw) = read_u32_at(optval + 136) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(numsrc) = read_u32_at(optval + 140) else { return -(Errno::Efault.as_i32() as i64); };
    if 144u64.saturating_add(numsrc as u64 * 128) > optlen as u64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mut sources = alloc::vec::Vec::new();
    for index in 0..numsrc as u64 {
        let Some(source) = read_sockaddr_storage_v6(optval + 144 + index * 128) else {
            return -(Errno::Einval.as_i32() as i64);
        };
        sources.push(source);
    }
    encode(sock.set_v6_mcast_filter_raw(ifindex, group, mode_raw, &sources))
}
