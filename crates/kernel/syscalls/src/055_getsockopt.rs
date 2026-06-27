// 055 getsockopt — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;
use net::sock::SockKind;
use crate::net_common::{peercred_for_fd, socket_from_fd};

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
    const SO_TYPE:      u64 = 3;
    const SO_PEERCRED:  u64 = 17;
    const SO_PROTOCOL:  u64 = 38;
    const SO_DOMAIN:    u64 = 39;
    const SO_SNDBUF: u64 = 7;
    const SO_RCVBUF: u64 = 8;
    const SO_SNDBUFFORCE: u64 = 32;
    const SO_RCVBUFFORCE: u64 = 33;
    let _fd     = args.a0;
    let level   = args.a1;
    let optname = args.a2;
    let optval  = args.a3;
    let optlen_p = args.a4;
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
                .map(|c| (c.tgid.load(Ordering::Relaxed),
                          c.creds.euid.load(Ordering::Relaxed),
                          c.creds.egid.load(Ordering::Relaxed)))
                .unwrap_or((0, 0, 0))
        });
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
    const IP_PKTINFO: u64 = 8;
    const IP_MULTICAST_TTL: u64 = 33;
    const IP_MULTICAST_LOOP: u64 = 34;
    const IP_MSFILTER: u64 = 41;
    const MCAST_MSFILTER: u64 = 48;
    const IPV6_V6ONLY: u64 = 26;
    const TCP_CORK: u64 = 3;
    const TCP_KEEPIDLE: u64 = 4;
    const TCP_KEEPINTVL: u64 = 5;
    const TCP_KEEPCNT: u64 = 6;
    let fd = args.a0;
    let sock = socket_from_fd(fd);
    let i32_back = |val: i32| -> i64 {
        if optval == 0 || optval >= USER_VA_END
            || optlen_p == 0 || optlen_p >= USER_VA_END { return 0; }
        // SAFETY: optval+4 within user range; optlen_p validated; 4-byte aligned int writeback.
        unsafe {
            core::ptr::write_volatile(optval as *mut i32, val);
            core::ptr::write_volatile(optlen_p as *mut u32, 4);
        }
        0
    };
    if let Some(s) = sock {
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
            (SOL_SOCKET, 12) => return i32_back(s.opts.priority.load(Ordering::Acquire)),
            (SOL_SOCKET, 36) => return i32_back(s.opts.mark.load(Ordering::Acquire)),
            (SOL_SOCKET, SO_TYPE) => return i32_back(socket_type(&s)),
            (SOL_SOCKET, SO_DOMAIN) => return i32_back(s.family.load(Ordering::Acquire) as i32),
            (SOL_SOCKET, SO_PROTOCOL) => return i32_back(socket_protocol(&s)),
            (SOL_SOCKET, SO_BINDTODEVICE) => return bind_to_device_name(&s, optval, optlen_p),
            (IPPROTO_IP, IP_TOS) => return i32_back(s.opts.ip_tos.load(Ordering::Acquire)),
            (IPPROTO_IP, IP_TTL) => return i32_back(s.opts.ip_ttl.load(Ordering::Acquire)),
            (IPPROTO_IP, IP_PKTINFO) => return i32_back(s.opts.ip_pktinfo.load(Ordering::Acquire)),
            (IPPROTO_IP, IP_MULTICAST_TTL) => return i32_back(s.opts.ip_mcast_ttl.load(Ordering::Acquire)),
            (IPPROTO_IP, IP_MULTICAST_LOOP) => return i32_back(s.opts.ip_mcast_loop.load(Ordering::Acquire)),
            (IPPROTO_IP, IP_MSFILTER) => return ipv4_msfilter_get(&s, optval, optlen_p),
            (IPPROTO_IP, MCAST_MSFILTER) => return ipv4_group_filter_get(&s, optval, optlen_p),
            (IPPROTO_IPV6, IPV6_V6ONLY) => return i32_back(s.opts.ipv6_v6only.load(Ordering::Acquire)),
            (IPPROTO_TCP, 1) => return i32_back(s.opts.tcp_nodelay.load(Ordering::Acquire)),
            (IPPROTO_TCP, TCP_CORK) => return i32_back(s.opts.tcp_cork.load(Ordering::Acquire)),
            (IPPROTO_TCP, TCP_KEEPIDLE) => return i32_back(s.opts.tcp_keepidle_s.load(Ordering::Acquire)),
            (IPPROTO_TCP, TCP_KEEPINTVL) => return i32_back(s.opts.tcp_keepintvl_s.load(Ordering::Acquire)),
            (IPPROTO_TCP, TCP_KEEPCNT) => return i32_back(s.opts.tcp_keepcnt.load(Ordering::Acquire)),
            // F188: TCP_INFO returns the Linux tcp_info struct.
            (IPPROTO_TCP, 11) => return crate::tcp_info::write_tcp_info(&s, optval, optlen_p),
            (SOL_SOCKET, 4)  => {
                // F163/F174: SO_ERROR — read+clear per-conn (TCP) or
                // per-port (UDP, ICMP-unreach surface) error.
                let e = match &*s.kind.lock() {
                    SockKind::TcpConn(entry) => {
                        let mut c = entry.conn.lock();
                        let v = c.error_eno;
                        c.error_eno = 0;
                        v
                    }
                    SockKind::Udp => {
                        if let Some(p) = *s.local_port.lock() {
                            net::sock::stack().udp_queue_arc(p)
                                .map(|q| q.take_error()).unwrap_or(0)
                        } else { 0 }
                    }
                    _ => 0,
                };
                return i32_back(e);
            }
            _ => return -(Errno::Enoprotoopt.as_i32() as i64),
        }
    } else {
        return -(Errno::Enotsock.as_i32() as i64);
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

fn iface_for_v4_addr(addr: net::Ipv4Addr) -> Option<net::NetIfaceId> {
    net::sock::stack().routes.snapshot().into_iter()
        .find(|r| r.src_hint == Some(addr))
        .map(|r| r.iface)
}

fn default_v4_mcast_iface(s: &alloc::sync::Arc<net::sock::InetSocket>, group: net::Ipv4Addr)
    -> Option<net::NetIfaceId>
{
    use core::sync::atomic::Ordering;
    let raw = s.opts.ip_mcast_ifindex.load(Ordering::Acquire);
    if raw != 0 { return Some(net::NetIfaceId::from_raw(raw)); }
    let addr = net::Ipv4Addr::from_u32(s.opts.ip_mcast_ifaddr.load(Ordering::Acquire));
    if !addr.is_unspecified() { return iface_for_v4_addr(addr); }
    let bound = s.opts.bound_ifindex.load(Ordering::Acquire);
    if bound != 0 { return Some(net::NetIfaceId::from_raw(bound)); }
    if let Some(r) = net::sock::stack().routes.lookup(group) { return Some(r.iface); }
    let routes = net::sock::stack().routes.snapshot();
    if routes.len() == 1 { Some(routes[0].iface) } else { None }
}

fn resolve_v4_mcast_iface(
    s: &alloc::sync::Arc<net::sock::InetSocket>,
    group: net::Ipv4Addr,
    ifindex: u32,
    ifaddr: net::Ipv4Addr,
) -> Result<net::NetIfaceId, i64> {
    let iface = if ifindex != 0 {
        net::NetIfaceId::from_raw(ifindex)
    } else if !ifaddr.is_unspecified() {
        iface_for_v4_addr(ifaddr).ok_or(-(Errno::Enodev.as_i32() as i64))?
    } else {
        default_v4_mcast_iface(s, group).ok_or(-(Errno::Enodev.as_i32() as i64))?
    };
    if net::sock::stack().ifaces.lookup(iface).is_none() {
        return Err(-(Errno::Enodev.as_i32() as i64));
    }
    Ok(iface)
}

fn udp_port(s: &alloc::sync::Arc<net::sock::InetSocket>) -> Result<u16, i64> {
    match *s.local_port.lock() {
        Some(p) => Ok(p),
        None => Err(-(Errno::Einval.as_i32() as i64)),
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
    let iface = match resolve_v4_mcast_iface(s, group, 0, ifaddr) { Ok(i) => i, Err(e) => return e };
    let port = match udp_port(s) { Ok(p) => p, Err(e) => return e };
    let f = net::mcast_filter::get(port, iface, group);
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
    let iface = match resolve_v4_mcast_iface(s, group, ifindex, net::Ipv4Addr::ANY) { Ok(i) => i, Err(e) => return e };
    let port = match udp_port(s) { Ok(p) => p, Err(e) => return e };
    let f = net::mcast_filter::get(port, iface, group);
    let n = core::cmp::min(requested as usize, f.sources.len());
    if 144u64 + n as u64 * 128 > cap { return -(Errno::Erange.as_i32() as i64); }
    write_u32_at(optval + 136, f.mode.as_u32());
    write_u32_at(optval + 140, f.sources.len() as u32);
    for i in 0..n { write_sockaddr_storage_v4(optval + 144 + i as u64 * 128, f.sources[i]); }
    write_u32_at(optlen_p, (144 + n * 128) as u32);
    0
}

fn socket_type(s: &alloc::sync::Arc<net::sock::InetSocket>) -> i32 {
    use core::sync::atomic::Ordering;
    const SOCK_STREAM: i32 = 1;
    const SOCK_DGRAM: i32 = 2;
    const SOCK_SEQPACKET: i32 = 5;
    match &*s.kind.lock() {
        SockKind::Udp | SockKind::UnixDgram(_) => SOCK_DGRAM,
        SockKind::Packet { sock_type, .. } => sock_type.load(Ordering::Acquire) as i32,
        SockKind::UnixMsgPair(_, _) => SOCK_SEQPACKET,
        SockKind::TcpInit
        | SockKind::TcpListener(_)
        | SockKind::TcpConn(_)
        | SockKind::Unix(_, _)
        | SockKind::UnixListener(_) => SOCK_STREAM,
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
        SockKind::Udp => IPPROTO_UDP,
        SockKind::TcpInit | SockKind::TcpListener(_) | SockKind::TcpConn(_) => IPPROTO_TCP,
        _ => 0,
    }
}
