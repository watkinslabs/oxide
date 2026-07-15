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
    if ptr + 4 > USER_VA_END { return None; }
    // SAFETY: ptr+4 was checked; scalar ABI field read.
    Some(unsafe { core::ptr::read_volatile(ptr as *const u32) })
}

fn write_u32_at(ptr: u64, value: u32) {
    // SAFETY: caller validated the containing user buffer.
    unsafe { core::ptr::write_volatile(ptr as *mut u32, value); }
}

fn read_ipv4_at(ptr: u64) -> Option<net::Ipv4Addr> {
    let be = read_u32_at(ptr)?;
    Some(net::Ipv4Addr::from_u32(u32::from_be(be)))
}

fn write_ipv4_at(ptr: u64, addr: net::Ipv4Addr) {
    write_u32_at(ptr, addr.as_u32().to_be());
}

fn read_sockaddr_storage_v4(ptr: u64) -> Option<net::Ipv4Addr> {
    const AF_INET: u16 = 2;
    if ptr + 16 > USER_VA_END { return None; }
    // SAFETY: sockaddr_storage begins with sockaddr_in-compatible fields.
    let family = unsafe { core::ptr::read_volatile(ptr as *const u16) };
    if family != AF_INET { return None; }
    read_ipv4_at(ptr + 4)
}

fn write_sockaddr_storage_v4(ptr: u64, addr: net::Ipv4Addr) {
    const AF_INET: u16 = 2;
    for i in 0..128u64 {
        // SAFETY: caller validated the whole sockaddr_storage slot.
        unsafe { core::ptr::write_volatile((ptr + i) as *mut u8, 0); }
    }
    // SAFETY: caller validated the slot; sockaddr_in-compatible fields.
    unsafe { core::ptr::write_volatile(ptr as *mut u16, AF_INET); }
    write_ipv4_at(ptr + 4, addr);
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

fn write_sockaddr_storage_v6(ptr: u64, addr: net::Ipv6Addr) {
    const AF_INET6: u16 = 10;
    for index in 0..128u64 {
        // SAFETY: caller validated the complete sockaddr_storage slot.
        unsafe { core::ptr::write_volatile((ptr + index) as *mut u8, 0); }
    }
    // SAFETY: caller validated sockaddr_in6 family and address fields.
    unsafe { core::ptr::write_volatile(ptr as *mut u16, AF_INET6); }
    for (index, byte) in addr.0.iter().enumerate() {
        // SAFETY: sockaddr_in6 address occupies bytes 8 through 23.
        unsafe { core::ptr::write_volatile((ptr + 8 + index as u64) as *mut u8, *byte); }
    }
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
    write_u32_at(optval + 8, f.mode.as_u32());
    write_u32_at(optval + 12, f.sources.len() as u32);
    for i in 0..n { write_ipv4_at(optval + 16 + i as u64 * 4, f.sources[i]); }
    write_u32_at(optlen_p, (16 + n * 4) as u32);
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
    write_u32_at(optval + 136, f.mode.as_u32());
    write_u32_at(optval + 140, f.sources.len() as u32);
    for i in 0..n { write_sockaddr_storage_v4(optval + 144 + i as u64 * 128, f.sources[i]); }
    write_u32_at(optlen_p, (144 + n * 128) as u32);
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
    write_u32_at(optval + 136, filter.mode.as_u32());
    write_u32_at(optval + 140, filter.sources.len() as u32);
    for index in 0..count {
        write_sockaddr_storage_v6(optval + 144 + index as u64 * 128, filter.sources[index]);
    }
    write_u32_at(optlen_p, (144 + count * 128) as u32);
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
