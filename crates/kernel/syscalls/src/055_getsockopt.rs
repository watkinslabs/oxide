// 055 getsockopt — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;
use net::sock::SockKind;
use crate::net_common::{errno_from_neterr, peercred_for_fd, socket_from_fd};

/// `getsockopt(fd, level, optname, optval, optlen)` slot 55.
///
/// Honored:
///   SOL_SOCKET (1) / SO_PEERCRED (17): writes back a `struct ucred`
///     {pid, uid, gid} (12 bytes) for AF_UNIX-paired fds. v1 reports
///     the calling task's tid + 0/0 (no real uid); sufficient for
///     systemd-class peer-credential checks to receive a non-zero pid.
///   SOL_SOCKET / SO_TYPE (3): writes back the SOCK_* shape.
///   Everything else: zero-length opt + return 0.
/// # C: O(1)
pub fn sys_getsockopt(args: &SyscallArgs) -> i64 {
    const SOL_SOCKET:   u64 = 1;
    const SO_BINDTODEVICE: u64 = 25;
    const SO_PASSCRED: u64 = 16;
    const SO_ERROR:     u64 = 4;
    const SO_TYPE:      u64 = 3;
    const SO_PEERCRED:  u64 = 17;
    const SO_PROTOCOL:  u64 = 38;
    const SO_DOMAIN:    u64 = 39;
    const SO_ACCEPTCONN: u64 = 30;
    const SO_SNDBUF: u64 = 7;
    const SO_RCVBUF: u64 = 8;
    const SO_SNDBUFFORCE: u64 = 32;
    const SO_RCVBUFFORCE: u64 = 33;
    const SO_TIMESTAMP_OLD: u64 = 29;
    const SO_TIMESTAMPNS_OLD: u64 = 35;
    const SO_TIMESTAMPING_OLD: u64 = 37;
    const SO_TIMESTAMP_NEW: u64 = 63;
    const SO_TIMESTAMPNS_NEW: u64 = 64;
    const SO_TIMESTAMPING_NEW: u64 = 65;
    let _fd     = args.a0;
    let level   = args.a1;
    let optname = args.a2;
    let optval  = args.a3;
    let optlen_p = args.a4;
    let i32_back = |val: i32| -> i64 {
        let mut raw_len = [0u8; 4];
        if uaccess::copy_from_user(&mut raw_len, optlen_p).is_err() { return -(Errno::Efault.as_i32() as i64); }
        let requested = i32::from_ne_bytes(raw_len);
        if requested < 0 { return -(Errno::Einval.as_i32() as i64); }
        let take = core::cmp::min(requested as usize, core::mem::size_of::<i32>());
        if take != 0 && uaccess::copy_to_user(optval, &val.to_ne_bytes()[..take]).is_err() {
            return -(Errno::Efault.as_i32() as i64);
        }
        if uaccess::copy_to_user(optlen_p, &(take as u32).to_ne_bytes()).is_err() {
            return -(Errno::Efault.as_i32() as i64);
        }
        0
    };
    if level == SOL_SOCKET && optname == SO_ERROR {
        let target = match crate::recvmsg::lookup(_fd) { Ok(target) => target, Err(e) => return e };
        let pending = target.take_error();
        return i32_back(pending);
    }
    if crate::netlink_fd::is_netlink(_fd) {
        return crate::netlink_fd::getsockopt(_fd, level, optname, optval, optlen_p);
    }
    if level == SOL_SOCKET && optname == SO_PEERCRED
       && optval != 0 && optval < USER_VA_END
       && optlen_p != 0 && optlen_p < USER_VA_END
    {
        // Real peer creds for a connected AF_UNIX fd (snapshotted at
        // socketpair/connect/accept); falls back to the caller's own
        // {pid,euid,egid} for non-unix/unconnected sockets.
        let (pid, uid, gid) = peercred_for_fd(args.a0 as i32).unwrap_or_else(|| {
            use core::sync::atomic::Ordering;
            sched::live::current()
                .map(|c| (c.visible_pid(),
                          c.creds.euid.load(Ordering::Relaxed),
                          c.creds.egid.load(Ordering::Relaxed)))
                .unwrap_or((0, 0, 0))
        });
        // DIAG (debug-dbus): log every SO_PEERCRED read + the returned peer
        // {pid,uid,gid}. dbus-broker calls this at accept to learn a client's
        // pid; if it returns pid=0 (or a wrong pid) for mutter's connection, the
        // bus can't tell logind mutter's pid → GetSessionByPID(0) → NoSessionForPID.
        #[cfg(feature = "debug-dbus")]
        {
            klog::write_raw(b"[PEERCRED fd=");
            klog::write_dec_u64(args.a0 as u64);
            klog::write_raw(b" -> pid=");
            klog::write_dec_u64(pid as u64);
            klog::write_raw(b" uid=");
            klog::write_dec_u64(uid as u64);
            klog::write_raw(b" by=");
            if let Some(c) = sched::live::current() {
                klog::write_dec_u64(c.tid as u64);
                klog::write_raw(b"/");
                klog::write_raw(c.name.as_bytes());
            }
            klog::write_raw(b"]\n");
        }
        // SAFETY: optval+optlen_p validated < USER_VA_END; struct ucred is 12 bytes; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile( optval        as *mut u32, pid);
            core::ptr::write_volatile((optval +  4)  as *mut u32, uid);
            core::ptr::write_volatile((optval +  8)  as *mut u32, gid);
            core::ptr::write_volatile(optlen_p as *mut u32, 12);
        }
        return 0;
    }
    // Read-back of options stored via setsockopt.
    use core::sync::atomic::Ordering;
    const IPPROTO_TCP: u64 = 6;
    const IPPROTO_IP: u64 = 0;
    const IPPROTO_IPV6: u64 = 41;
    const IP_TOS: u64 = 1;
    const IP_TTL: u64 = 2;
    const IP_HDRINCL: u64 = 3;
    const IP_PKTINFO: u64 = 8;
    const IP_RECVERR: u64 = 11;
    const IP_MTU_DISCOVER: u64 = 10;
    const IP_MTU: u64 = 14;
    const IP_MULTICAST_TTL: u64 = 33;
    const IP_MULTICAST_LOOP: u64 = 34;
    const IP_MSFILTER: u64 = 41;
    const MCAST_MSFILTER: u64 = 48;
    const IPV6_UNICAST_HOPS: u64 = 16;
    const IPV6_CHECKSUM: u64 = 7;
    const IPV6_MULTICAST_IF: u64 = 17;
    const IPV6_MULTICAST_HOPS: u64 = 18;
    const IPV6_MULTICAST_LOOP: u64 = 19;
    const IPV6_MTU: u64 = 24;
    const IPV6_MTU_DISCOVER: u64 = 23;
    const IPV6_RECVERR: u64 = 25;
    const IPV6_V6ONLY: u64 = 26;
    const IPV6_HDRINCL: u64 = 36;
    const IPV6_RECVPKTINFO: u64 = 49;
    const IPV6_RECVHOPLIMIT: u64 = 51;
    const IPPROTO_ICMP: u8 = 1;
    const IPPROTO_ICMPV6: u8 = 58;
    const SOL_ICMPV6: u64 = 58;
    const IPPROTO_RAW: u64 = 255;
    const ICMP_FILTER: u64 = 1;
    const ICMP6_FILTER: u64 = 1;
    const TCP_CORK: u64 = 3;
    const TCP_KEEPIDLE: u64 = 4;
    const TCP_KEEPINTVL: u64 = 5;
    const TCP_KEEPCNT: u64 = 6;
    let fd = args.a0;
    let sock = socket_from_fd(fd);
    if let Some(s) = sock {
        let bytes_back = |value: &[u8]| -> i64 {
            let mut raw_len = [0u8; 4];
            if uaccess::copy_from_user(&mut raw_len, optlen_p).is_err() { return -(Errno::Efault.as_i32() as i64); }
            let requested = i32::from_ne_bytes(raw_len);
            if requested < 0 { return -(Errno::Einval.as_i32() as i64); }
            let take = core::cmp::min(requested as usize, value.len());
            if uaccess::copy_to_user(optlen_p, &(take as u32).to_ne_bytes()).is_err() { return -(Errno::Efault.as_i32() as i64); }
            if take != 0 && uaccess::copy_to_user(optval, &value[..take]).is_err() { return -(Errno::Efault.as_i32() as i64); }
            0
        };
        match (level, optname) {
            (SOL_SOCKET, 2)  => return i32_back(s.opts.reuseaddr.load(Ordering::Acquire)),
            (SOL_SOCKET, 15) => return i32_back(s.opts.reuseport.load(Ordering::Acquire)),
            (SOL_SOCKET, 9)  => return i32_back(s.opts.keepalive.load(Ordering::Acquire)),
            (SOL_SOCKET, 6)  => return i32_back(s.opts.broadcast.load(Ordering::Acquire)),
            (SOL_SOCKET, SO_SNDBUF) | (SOL_SOCKET, SO_SNDBUFFORCE) =>
                return i32_back(s.opts.sndbuf.load(Ordering::Acquire)),
            (SOL_SOCKET, SO_RCVBUF) | (SOL_SOCKET, SO_RCVBUFFORCE) =>
                return i32_back(s.opts.rcvbuf.load(Ordering::Acquire)),
            (SOL_SOCKET, SO_PASSCRED) => return i32_back(s.opts.passcred.load(Ordering::Acquire)),
            (SOL_SOCKET, SO_TIMESTAMP_OLD) | (SOL_SOCKET, SO_TIMESTAMPNS_OLD)
            | (SOL_SOCKET, SO_TIMESTAMPING_OLD) | (SOL_SOCKET, SO_TIMESTAMP_NEW)
            | (SOL_SOCKET, SO_TIMESTAMPNS_NEW) | (SOL_SOCKET, SO_TIMESTAMPING_NEW) =>
                return i32_back(s.opts.timestamping.load(Ordering::Acquire)),
            (SOL_SOCKET, 12) => return i32_back(s.opts.priority.load(Ordering::Acquire)),
            (SOL_SOCKET, 36) => return i32_back(s.opts.mark.load(Ordering::Acquire)),
            (SOL_SOCKET, SO_TYPE) => return i32_back(socket_type(&s)),
            (SOL_SOCKET, SO_ACCEPTCONN) => return i32_back(socket_acceptconn(&s)),
            (SOL_SOCKET, SO_DOMAIN) => return i32_back(s.family.load(Ordering::Acquire) as i32),
            (SOL_SOCKET, SO_PROTOCOL) => return i32_back(socket_protocol(&s)),
            (SOL_SOCKET, SO_BINDTODEVICE) => return bind_to_device_name(&s, optval, optlen_p),
            (IPPROTO_IP, IP_HDRINCL) => match &*s.kind.lock() {
                SockKind::Raw4(endpoint) => return i32_back(i32::from(endpoint.hdrincl())),
                _ => return -(Errno::Enoprotoopt.as_i32() as i64),
            },
            (IPPROTO_RAW, ICMP_FILTER) => match &*s.kind.lock() {
                SockKind::Raw4(endpoint) if endpoint.protocol() == IPPROTO_ICMP => {
                    let value = endpoint.icmp_filter().to_ne_bytes();
                    return bytes_back(&value);
                }
                SockKind::Raw4(_) => return -(Errno::Eopnotsupp.as_i32() as i64),
                _ => return -(Errno::Enoprotoopt.as_i32() as i64),
            },
            (IPPROTO_IP, IP_TOS) => return i32_back(s.opts.ip_tos.load(Ordering::Acquire)),
            (IPPROTO_IP, IP_TTL) => return i32_back(s.opts.ip_ttl.load(Ordering::Acquire)),
            (IPPROTO_IP, IP_PKTINFO) => return i32_back(s.opts.ip_pktinfo.load(Ordering::Acquire)),
            (IPPROTO_IP, IP_MTU_DISCOVER) => return i32_back(s.opts.ip_mtu_discover.load(Ordering::Acquire)),
            (IPPROTO_IP, IP_MTU) => return socket_path_mtu(&s, false, &i32_back),
            (IPPROTO_IP, IP_RECVERR) => return i32_back(i32::from(s.error.recverr4())),
            (IPPROTO_IP, IP_MULTICAST_TTL) => return i32_back(s.opts.ip_mcast_ttl.load(Ordering::Acquire)),
            (IPPROTO_IP, IP_MULTICAST_LOOP) => return i32_back(s.opts.ip_mcast_loop.load(Ordering::Acquire)),
            (IPPROTO_IP, IP_MSFILTER) => return ipv4_msfilter_get(&s, optval, optlen_p),
            (IPPROTO_IP, MCAST_MSFILTER) => return ipv4_group_filter_get(&s, optval, optlen_p),
            (IPPROTO_IPV6, IPV6_V6ONLY) => return i32_back(s.opts.ipv6_v6only.load(Ordering::Acquire)),
            (IPPROTO_IPV6, IPV6_HDRINCL) => match &*s.kind.lock() {
                SockKind::Raw6(endpoint) => return i32_back(i32::from(endpoint.header_included())),
                _ => return -(Errno::Enoprotoopt.as_i32() as i64),
            },
            (IPPROTO_IPV6, IPV6_CHECKSUM) | (IPPROTO_RAW, IPV6_CHECKSUM) => match &*s.kind.lock() {
                SockKind::Raw6(endpoint) => return i32_back(endpoint.checksum().linux_value()),
                _ => return -(Errno::Enoprotoopt.as_i32() as i64),
            },
            (SOL_ICMPV6, ICMP6_FILTER) => match &*s.kind.lock() {
                SockKind::Raw6(endpoint) if endpoint.protocol() == IPPROTO_ICMPV6 => {
                    let words = endpoint.icmp_filter().words();
                    // SAFETY: eight initialized u32 words occupy exactly 32 readable bytes.
                    let bytes = unsafe { core::slice::from_raw_parts(words.as_ptr().cast::<u8>(), 32) };
                    return bytes_back(bytes);
                }
                SockKind::Raw6(_) => return -(Errno::Eopnotsupp.as_i32() as i64),
                _ => return -(Errno::Enoprotoopt.as_i32() as i64),
            },
            (IPPROTO_IPV6, IPV6_UNICAST_HOPS) => return i32_back(s.opts.ipv6_ucast_hops.load(Ordering::Acquire)),
            (IPPROTO_IPV6, IPV6_MULTICAST_HOPS) => return i32_back(s.opts.ipv6_mcast_hops.load(Ordering::Acquire)),
            (IPPROTO_IPV6, IPV6_MULTICAST_LOOP) => return i32_back(s.opts.ipv6_mcast_loop.load(Ordering::Acquire)),
            (IPPROTO_IPV6, IPV6_MTU) => return socket_path_mtu(&s, true, &i32_back),
            (IPPROTO_IPV6, IPV6_MTU_DISCOVER) =>
                return i32_back(s.opts.ipv6_mtu_discover.load(Ordering::Acquire)),
            (IPPROTO_IPV6, IPV6_RECVERR) => return i32_back(i32::from(s.error.recverr6())),
            (IPPROTO_IPV6, IPV6_MULTICAST_IF) => return i32_back(s.opts.ipv6_mcast_ifindex.load(Ordering::Acquire) as i32),
            (IPPROTO_IPV6, IPV6_RECVPKTINFO) => return i32_back(s.opts.ipv6_recvpktinfo.load(Ordering::Acquire)),
            (IPPROTO_IPV6, IPV6_RECVHOPLIMIT) => return i32_back(s.opts.ipv6_recvhoplimit.load(Ordering::Acquire)),
            (IPPROTO_IPV6, MCAST_MSFILTER) => return ipv6_group_filter_get(&s, optval, optlen_p),
            (IPPROTO_TCP, 1) => return i32_back(s.opts.tcp_nodelay.load(Ordering::Acquire)),
            (IPPROTO_TCP, TCP_CORK) => return i32_back(s.opts.tcp_cork.load(Ordering::Acquire)),
            (IPPROTO_TCP, TCP_KEEPIDLE) => return i32_back(s.opts.tcp_keepidle_s.load(Ordering::Acquire)),
            (IPPROTO_TCP, TCP_KEEPINTVL) => return i32_back(s.opts.tcp_keepintvl_s.load(Ordering::Acquire)),
            (IPPROTO_TCP, TCP_KEEPCNT) => return i32_back(s.opts.tcp_keepcnt.load(Ordering::Acquire)),
            // F188: TCP_INFO returns the Linux tcp_info struct.
            (IPPROTO_TCP, 11) => return crate::tcp_info::write_tcp_info(&s, optval, optlen_p),
            _ => return -(Errno::Enoprotoopt.as_i32() as i64),
        }
    } else {
        return -(Errno::Enotsock.as_i32() as i64);
    }
}

fn socket_path_mtu(s: &alloc::sync::Arc<net::sock::InetSocket>, ipv6: bool,
                   back: &impl Fn(i32) -> i64) -> i64 {
    use core::sync::atomic::Ordering;
    let dst = {
        let kind = s.kind.lock();
        match &*kind {
            SockKind::TcpConn(entry) => Some(entry.conn.lock().remote.ip),
            _ if ipv6 => s.peer6.lock().map(|(ip, _)| net::IpAddr::V6(ip)),
            _ => s.peer.lock().map(|(ip, _)| net::IpAddr::V4(ip)),
        }
    };
    let Some(dst) = dst else { return -(Errno::Enotconn.as_i32() as i64); };
    if ipv6 != matches!(dst, net::IpAddr::V6(_)) {
        return -(Errno::Enotconn.as_i32() as i64);
    }
    let raw = s.opts.bound_ifindex.load(Ordering::Acquire);
    let bound = if raw == 0 { None } else { Some(net::NetIfaceId::from_raw(raw)) };
    match net::sock::stack().path_mtu(dst, bound, false) {
        Ok(mtu) => back(mtu.min(i32::MAX as u32) as i32),
        Err(error) => errno_from_neterr(error),
    }
}

fn bind_to_device_name(s: &alloc::sync::Arc<net::sock::InetSocket>,
                       optval: u64, optlen_p: u64) -> i64 {
    use core::sync::atomic::Ordering;
    const IFNAMSIZ: usize = 16;
    if optval == 0 || optval >= USER_VA_END || optlen_p == 0 || optlen_p >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: optlen_p was range-checked; userspace owns the pointed u32.
    let cap = unsafe { core::ptr::read_volatile(optlen_p as *const u32) } as usize;
    let raw = s.opts.bound_ifindex.load(Ordering::Acquire);
    if raw == 0 {
        // SAFETY: validated pointers; zero-length readback for unbound sockets.
        unsafe { core::ptr::write_volatile(optlen_p as *mut u32, 0); }
        return 0;
    }
    let id = net::NetIfaceId::from_raw(raw);
    let dev = match net::sock::stack().ifaces.lookup(id) {
        Some(dev) => dev,
        None => return -(Errno::Enodev.as_i32() as i64),
    };
    let name = dev.name().as_bytes();
    let need = name.len().saturating_add(1);
    if need > IFNAMSIZ || cap < need || optval + need as u64 > USER_VA_END {
        return -(Errno::Erange.as_i32() as i64);
    }
    for (i, b) in name.iter().enumerate() {
        // SAFETY: optval + need was range-checked; byte writes are ABI-safe.
        unsafe { core::ptr::write_volatile((optval + i as u64) as *mut u8, *b); }
    }
    // SAFETY: trailing NUL lies within the validated range.
    unsafe {
        core::ptr::write_volatile((optval + name.len() as u64) as *mut u8, 0);
        core::ptr::write_volatile(optlen_p as *mut u32, need as u32);
    }
    0
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

fn ipv4_msfilter_get(s: &alloc::sync::Arc<net::sock::InetSocket>, optval: u64, optlen_p: u64) -> i64 {
    if optval == 0 || optval >= USER_VA_END || optlen_p == 0 || optlen_p >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cap = match read_u32_at(optlen_p) { Some(v) => v as u64, None => return -(Errno::Efault.as_i32() as i64) };
    if cap < 16 || optval + cap > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(group) = read_ipv4_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(ifaddr) = read_ipv4_at(optval + 4) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(requested) = read_u32_at(optval + 12) else { return -(Errno::Efault.as_i32() as i64); };
    if !group.is_multicast() { return -(Errno::Einval.as_i32() as i64); }
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

fn ipv4_group_filter_get(s: &alloc::sync::Arc<net::sock::InetSocket>, optval: u64, optlen_p: u64) -> i64 {
    if optval == 0 || optval >= USER_VA_END || optlen_p == 0 || optlen_p >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cap = match read_u32_at(optlen_p) { Some(v) => v as u64, None => return -(Errno::Efault.as_i32() as i64) };
    if cap < 144 || optval + cap > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v4(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    let Some(requested) = read_u32_at(optval + 140) else { return -(Errno::Efault.as_i32() as i64); };
    if !group.is_multicast() { return -(Errno::Einval.as_i32() as i64); }
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

fn ipv6_group_filter_get(s: &alloc::sync::Arc<net::sock::InetSocket>, optval: u64,
                         optlen_p: u64) -> i64 {
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
    if !group.is_multicast() { return -(Errno::Einval.as_i32() as i64); }
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

fn socket_type(s: &alloc::sync::Arc<net::sock::InetSocket>) -> i32 {
    use core::sync::atomic::Ordering;
    const SOCK_STREAM: i32 = 1;
    const SOCK_DGRAM: i32 = 2;
    const SOCK_RAW: i32 = 3;
    const SOCK_SEQPACKET: i32 = 5;
    // Explicit SO_TYPE override (AF_UNIX SOCK_SEQPACKET listener — see
    // sys_socket): the byte-ring SockKind can't encode the SEQPACKET shape.
    let ov = s.opts.so_type.load(Ordering::Acquire);
    if ov != 0 { return ov as i32; }
    match &*s.kind.lock() {
        SockKind::Udp | SockKind::UnixDgram(_) => SOCK_DGRAM,
        SockKind::Raw4(_) | SockKind::Raw6(_) => SOCK_RAW,
        SockKind::Packet { sock_type, .. } => sock_type.load(Ordering::Acquire) as i32,
        SockKind::UnixMsgPair(_, _) => SOCK_SEQPACKET,
        SockKind::TcpInit
        | SockKind::TcpListener(_)
        | SockKind::TcpConn(_)
        | SockKind::Unix(_, _)
        | SockKind::UnixListener(_) => SOCK_STREAM,
    }
}

fn socket_acceptconn(s: &alloc::sync::Arc<net::sock::InetSocket>) -> i32 {
    match &*s.kind.lock() {
        SockKind::TcpListener(_) | SockKind::UnixListener(_) => 1,
        _ => 0,
    }
}

fn socket_protocol(s: &alloc::sync::Arc<net::sock::InetSocket>) -> i32 {
    use core::sync::atomic::Ordering;
    const IPPROTO_TCP: i32 = 6;
    const IPPROTO_UDP: i32 = 17;
    if s.family.load(Ordering::Acquire) == net::sock::AF_UNIX {
        return 0;
    }
    match &*s.kind.lock() {
        SockKind::Packet { protocol, .. } => protocol.load(Ordering::Acquire) as i32,
        SockKind::Raw4(endpoint) => endpoint.protocol() as i32,
        SockKind::Raw6(endpoint) => endpoint.protocol() as i32,
        SockKind::Udp => IPPROTO_UDP,
        SockKind::TcpInit | SockKind::TcpListener(_) | SockKind::TcpConn(_) => IPPROTO_TCP,
        _ => 0,
    }
}
