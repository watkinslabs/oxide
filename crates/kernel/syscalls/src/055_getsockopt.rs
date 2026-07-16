// 055 getsockopt — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;
use net::sock::SockKind;
use crate::net_common::{errno_from_neterr, fd_file, socket_from_file, vsock_from_file};

#[path = "055_getsockopt/multicast.rs"]
mod multicast;
#[path = "055_getsockopt/packet.rs"]
mod packet;
#[path = "055_getsockopt/packet_abi.rs"]
mod packet_abi;
use multicast::{ipv4_group_filter_get, ipv4_msfilter_get, ipv6_group_filter_get, scalar_get};

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
    const SO_PEERCRED:  u64 = 17;
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
    const SO_LOCK_FILTER: u64 = 44;
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
    let file = match fd_file(_fd) {
        Some(file) => file,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    if level == SOL_SOCKET && optname == SO_ERROR {
        let target = match crate::recvmsg::from_file(file.clone()) {
            Ok(target) => target,
            Err(e) => return e,
        };
        let pending = target.take_error();
        return i32_back(pending);
    }
    if level == SOL_SOCKET && optname == SO_LOCK_FILTER {
        let target = match socket::FilterFile::from_file(file.clone()) {
            Some(target) => target,
            None => return -(Errno::Enotsock.as_i32() as i64),
        };
        return i32_back(i32::from(target.is_locked()));
    }
    if let Some(target) = crate::netlink_fd::from_file(file.clone()) {
        return crate::netlink_fd::getsockopt(&target, level, optname, optval, optlen_p);
    }
    if let Some(vsock) = vsock_from_file(file.clone()) {
        return match vsock.get_socket_option(level, optname) {
            Ok(value) => i32_back(value),
            Err(e) => errno_from_neterr(e),
        };
    }
    let sock = match socket_from_file(file) {
        Some(sock) => sock,
        None => return -(Errno::Enotsock.as_i32() as i64),
    };
    if let Err(error) = net::sock_opts::check_option(&sock) {
        return errno_from_neterr(error);
    }
    if level == net::uapi::SOL_PACKET {
        return packet::packet_getsockopt(&sock, optname, optval, optlen_p);
    }
    if level == SOL_SOCKET && optname == SO_PEERCRED
       && optval != 0 && optval < USER_VA_END
       && optlen_p != 0 && optlen_p < USER_VA_END
    {
        // Real peer creds for a connected AF_UNIX fd (snapshotted at
        // socketpair/connect/accept); falls back to the caller's own
        // {pid,euid,egid} for non-unix/unconnected sockets.
        let (pid, uid, gid) = peercred_for_socket(&sock).unwrap_or_else(|| {
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
        let mut raw_len = [0u8; 4];
        if uaccess::copy_from_user(&mut raw_len, optlen_p).is_err() {
            return -(Errno::Efault.as_i32() as i64);
        }
        let requested = i32::from_ne_bytes(raw_len);
        if requested < 0 { return -(Errno::Einval.as_i32() as i64); }
        let mut value = [0u8; 12];
        value[..4].copy_from_slice(&pid.to_ne_bytes());
        value[4..8].copy_from_slice(&uid.to_ne_bytes());
        value[8..].copy_from_slice(&gid.to_ne_bytes());
        let take = core::cmp::min(requested as usize, value.len());
        if take != 0 && uaccess::copy_to_user(optval, &value[..take]).is_err() {
            return -(Errno::Efault.as_i32() as i64);
        }
        if uaccess::copy_to_user(optlen_p, &(take as u32).to_ne_bytes()).is_err() {
            return -(Errno::Efault.as_i32() as i64);
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
    {
        let s = sock;
        let bytes_back = |value: &[u8]| -> i64 {
            let mut raw_len = [0u8; 4];
            if uaccess::copy_from_user(&mut raw_len, optlen_p).is_err() { return -(Errno::Efault.as_i32() as i64); }
            let requested = i32::from_ne_bytes(raw_len);
            if requested < 0 { return -(Errno::Einval.as_i32() as i64); }
            let take = core::cmp::min(requested as usize, value.len());
            if take != 0 && uaccess::copy_to_user(optval, &value[..take]).is_err() { return -(Errno::Efault.as_i32() as i64); }
            if uaccess::copy_to_user(optlen_p, &(take as u32).to_ne_bytes()).is_err() { return -(Errno::Efault.as_i32() as i64); }
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
            (SOL_SOCKET, net::uapi::SO_TYPE) => return i32_back(socket_type(&s)),
            (SOL_SOCKET, net::uapi::SO_ACCEPTCONN) => return i32_back(socket_acceptconn(&s)),
            (SOL_SOCKET, net::uapi::SO_DOMAIN) => return i32_back(s.family.load(Ordering::Acquire) as i32),
            (SOL_SOCKET, net::uapi::SO_PROTOCOL) => return i32_back(socket_protocol(&s)),
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
            (IPPROTO_IP, IP_MULTICAST_TTL) => return scalar_get(&s, net::sock_mcast::McastScalarGet::V4Ttl, &i32_back),
            (IPPROTO_IP, IP_MULTICAST_LOOP) => return scalar_get(&s, net::sock_mcast::McastScalarGet::V4Loop, &i32_back),
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
            (IPPROTO_IPV6, IPV6_MULTICAST_HOPS) => return scalar_get(&s, net::sock_mcast::McastScalarGet::V6Hops, &i32_back),
            (IPPROTO_IPV6, IPV6_MULTICAST_LOOP) => return scalar_get(&s, net::sock_mcast::McastScalarGet::V6Loop, &i32_back),
            (IPPROTO_IPV6, IPV6_MTU) => return socket_path_mtu(&s, true, &i32_back),
            (IPPROTO_IPV6, IPV6_MTU_DISCOVER) =>
                return i32_back(s.opts.ipv6_mtu_discover.load(Ordering::Acquire)),
            (IPPROTO_IPV6, IPV6_RECVERR) => return i32_back(i32::from(s.error.recverr6())),
            (IPPROTO_IPV6, IPV6_MULTICAST_IF) => return scalar_get(&s, net::sock_mcast::McastScalarGet::V6Iface, &i32_back),
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
    }
}

fn peercred_for_socket(sock: &alloc::sync::Arc<net::sock::InetSocket>)
    -> Option<(u32, u32, u32)>
{
    match &*sock.kind.lock() {
        SockKind::Unix(pair, end) => Some(pair.peer_cred(*end)),
        SockKind::UnixMsgPair(pair, end) => Some(pair.peer_cred(*end)),
        SockKind::UnixListener(listener) => Some(listener.owner_cred()),
        _ => None,
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
