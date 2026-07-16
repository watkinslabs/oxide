use hal::USER_VA_END;
use syscall::errno::Errno;

use crate::net_errno::errno_from_neterr;

fn preflight(s: &net::sock::InetSocket, op: net::sock_mcast::McastGetOp) -> Result<(), i64> {
    s.preflight_mcast_get(op).map_err(errno_from_neterr)
}

pub(super) fn scalar_get(s: &alloc::sync::Arc<net::sock::InetSocket>,
                         option: net::sock_mcast::McastScalarGet,
                         back: &impl Fn(i32) -> i64) -> i64 {
    match s.get_mcast_scalar(option) {
        Ok(value) => back(value), Err(error) => errno_from_neterr(error),
    }
}

fn read_u32_at(ptr: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    uaccess::copy_from_user(&mut bytes, ptr).ok()?;
    Some(u32::from_ne_bytes(bytes))
}

fn write_u32_at(ptr: u64, value: u32) -> bool {
    uaccess::copy_to_user(ptr, &value.to_ne_bytes()).is_ok()
}

fn read_ipv4_at(ptr: u64) -> Option<net::Ipv4Addr> {
    let be = read_u32_at(ptr)?;
    Some(net::Ipv4Addr::from_u32(u32::from_be(be)))
}

fn write_ipv4_at(ptr: u64, addr: net::Ipv4Addr) -> bool {
    write_u32_at(ptr, addr.as_u32().to_be())
}

fn read_sockaddr_storage_v4(ptr: u64) -> Option<net::Ipv4Addr> {
    const AF_INET: u16 = 2;
    if ptr + 16 > USER_VA_END { return None; }
    // SAFETY: sockaddr_storage begins with sockaddr_in-compatible fields.
    let mut bytes = [0u8; 16];
    uaccess::copy_from_user(&mut bytes, ptr).ok()?;
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    if family != AF_INET { return None; }
    read_ipv4_at(ptr + 4)
}

fn write_sockaddr_storage_v4(ptr: u64, addr: net::Ipv4Addr) -> bool {
    const AF_INET: u16 = 2;
    let mut bytes = [0u8; 128];
    bytes[..2].copy_from_slice(&AF_INET.to_ne_bytes());
    bytes[4..8].copy_from_slice(&addr.as_u32().to_be_bytes());
    uaccess::copy_to_user(ptr, &bytes).is_ok()
}

fn read_ipv6_at(ptr: u64) -> Option<net::Ipv6Addr> {
    let mut addr = [0u8; 16];
    uaccess::copy_from_user(&mut addr, ptr).ok()?;
    Some(net::Ipv6Addr(addr))
}

fn read_sockaddr_storage_v6(ptr: u64) -> Option<net::Ipv6Addr> {
    const AF_INET6: u16 = 10;
    if ptr + 28 > USER_VA_END { return None; }
    // SAFETY: sockaddr_storage starts with a native-endian address family.
    let mut bytes = [0u8; 28];
    uaccess::copy_from_user(&mut bytes, ptr).ok()?;
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    if family != AF_INET6 { return None; }
    read_ipv6_at(ptr + 8)
}

fn write_sockaddr_storage_v6(ptr: u64, addr: net::Ipv6Addr) -> bool {
    const AF_INET6: u16 = 10;
    let mut bytes = [0u8; 128];
    bytes[..2].copy_from_slice(&AF_INET6.to_ne_bytes());
    bytes[8..24].copy_from_slice(&addr.0);
    uaccess::copy_to_user(ptr, &bytes).is_ok()
}

pub(super) fn ipv4_msfilter_get(s: &alloc::sync::Arc<net::sock::InetSocket>,
                                optval: u64, optlen_p: u64) -> i64 {
    if let Err(error) = preflight(s, net::sock_mcast::McastGetOp::V4) { return error; }
    if optval == 0 || optval >= USER_VA_END || optlen_p == 0 || optlen_p >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cap = match read_u32_at(optlen_p) { Some(v) => v as u64, None => return -(Errno::Efault.as_i32() as i64) };
    if cap < 16 || optval + cap > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(group) = read_ipv4_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(ifaddr) = read_ipv4_at(optval + 4) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(requested) = read_u32_at(optval + 12) else { return -(Errno::Efault.as_i32() as i64); };
    let f = match s.get_v4_mcast_filter_req(0, ifaddr, group) {
        Ok(filter) => filter, Err(error) => return errno_from_neterr(error),
    };
    let n = core::cmp::min(requested as usize, f.sources.len());
    if 16u64 + n as u64 * 4 > cap { return -(Errno::Erange.as_i32() as i64); }
    if !write_u32_at(optval + 8, f.mode.as_u32())
        || !write_u32_at(optval + 12, f.sources.len() as u32) {
        return -(Errno::Efault.as_i32() as i64);
    }
    for i in 0..n {
        if !write_ipv4_at(optval + 16 + i as u64 * 4, f.sources[i]) {
            return -(Errno::Efault.as_i32() as i64);
        }
    }
    if !write_u32_at(optlen_p, (16 + n * 4) as u32) { return -(Errno::Efault.as_i32() as i64); }
    0
}

pub(super) fn ipv4_group_filter_get(s: &alloc::sync::Arc<net::sock::InetSocket>,
                                    optval: u64, optlen_p: u64) -> i64 {
    if let Err(error) = preflight(s, net::sock_mcast::McastGetOp::V4) { return error; }
    if optval == 0 || optval >= USER_VA_END || optlen_p == 0 || optlen_p >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cap = match read_u32_at(optlen_p) { Some(v) => v as u64, None => return -(Errno::Efault.as_i32() as i64) };
    if cap < 144 || optval + cap > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v4(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    let Some(requested) = read_u32_at(optval + 140) else { return -(Errno::Efault.as_i32() as i64); };
    let f = match s.get_v4_mcast_filter_req(ifindex, net::Ipv4Addr::ANY, group) {
        Ok(filter) => filter, Err(error) => return errno_from_neterr(error),
    };
    let n = core::cmp::min(requested as usize, f.sources.len());
    if 144u64 + n as u64 * 128 > cap { return -(Errno::Erange.as_i32() as i64); }
    if !write_u32_at(optval + 136, f.mode.as_u32())
        || !write_u32_at(optval + 140, f.sources.len() as u32) {
        return -(Errno::Efault.as_i32() as i64);
    }
    for i in 0..n {
        if !write_sockaddr_storage_v4(optval + 144 + i as u64 * 128, f.sources[i]) {
            return -(Errno::Efault.as_i32() as i64);
        }
    }
    if !write_u32_at(optlen_p, (144 + n * 128) as u32) { return -(Errno::Efault.as_i32() as i64); }
    0
}

pub(super) fn ipv6_group_filter_get(s: &alloc::sync::Arc<net::sock::InetSocket>,
                                    optval: u64, optlen_p: u64) -> i64 {
    if let Err(error) = preflight(s, net::sock_mcast::McastGetOp::V6) { return error; }
    if optval == 0 || optval >= USER_VA_END || optlen_p == 0 || optlen_p >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cap = match read_u32_at(optlen_p) {
        Some(value) => value as u64, None => return -(Errno::Efault.as_i32() as i64),
    };
    if cap < 144 || optval + cap > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v6(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    let Some(requested) = read_u32_at(optval + 140) else { return -(Errno::Efault.as_i32() as i64); };
    let filter = match s.get_v6_mcast_filter(ifindex, group) {
        Ok(filter) => filter, Err(error) => return errno_from_neterr(error),
    };
    let count = core::cmp::min(requested as usize, filter.sources.len());
    if 144u64 + count as u64 * 128 > cap { return -(Errno::Erange.as_i32() as i64); }
    if !write_u32_at(optval + 136, filter.mode.as_u32())
        || !write_u32_at(optval + 140, filter.sources.len() as u32) {
        return -(Errno::Efault.as_i32() as i64);
    }
    for index in 0..count {
        if !write_sockaddr_storage_v6(optval + 144 + index as u64 * 128, filter.sources[index]) {
            return -(Errno::Efault.as_i32() as i64);
        }
    }
    if !write_u32_at(optlen_p, (144 + count * 128) as u32) { return -(Errno::Efault.as_i32() as i64); }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    #[test]
    fn wrong_family_multicast_get_precedes_uapi_with_eopnotsupp() {
        let udp4 = Arc::new(net::sock::InetSocket::new_udp());
        let unix = Arc::new(net::sock::InetSocket::new_unix());
        assert_eq!(ipv6_group_filter_get(&udp4, 0, 0),
            -(Errno::Eopnotsupp.as_i32() as i64));
        assert_eq!(ipv4_msfilter_get(&unix, 0, 0),
            -(Errno::Eopnotsupp.as_i32() as i64));
        assert_eq!(ipv4_group_filter_get(&unix, 0, 0),
            -(Errno::Eopnotsupp.as_i32() as i64));
    }

    #[test]
    fn valid_family_filter_get_reaches_uapi_checks() {
        let udp4 = Arc::new(net::sock::InetSocket::new_udp());
        let udp6 = Arc::new(net::sock::InetSocket::new_udp6());
        assert_eq!(ipv4_msfilter_get(&udp4, 0, 0), -(Errno::Efault.as_i32() as i64));
        assert_eq!(ipv6_group_filter_get(&udp6, 0, 0), -(Errno::Efault.as_i32() as i64));
    }

    #[test]
    fn scalar_get_rejects_family_before_encoding() {
        let udp4 = Arc::new(net::sock::InetSocket::new_udp());
        let called = core::cell::Cell::new(false);
        let back = |_: i32| { called.set(true); 0 };
        assert_eq!(scalar_get(&udp4, net::sock_mcast::McastScalarGet::V6Loop, &back),
            -(Errno::Eopnotsupp.as_i32() as i64));
        assert!(!called.get());
    }
}
