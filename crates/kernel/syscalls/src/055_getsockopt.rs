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
    const IP_TOS: u64 = 1;
    const IP_TTL: u64 = 2;
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
            (SOL_SOCKET, 7)  => return i32_back(s.opts.sndbuf.load(Ordering::Acquire)),
            (SOL_SOCKET, 8)  => return i32_back(s.opts.rcvbuf.load(Ordering::Acquire)),
            (SOL_SOCKET, SO_PASSCRED) => return i32_back(s.opts.passcred.load(Ordering::Acquire)),
            (SOL_SOCKET, 12) => return i32_back(s.opts.priority.load(Ordering::Acquire)),
            (SOL_SOCKET, 36) => return i32_back(s.opts.mark.load(Ordering::Acquire)),
            (SOL_SOCKET, SO_TYPE) => return i32_back(socket_type(&s)),
            (SOL_SOCKET, SO_DOMAIN) => return i32_back(s.family.load(Ordering::Acquire) as i32),
            (SOL_SOCKET, SO_PROTOCOL) => return i32_back(socket_protocol(&s)),
            (SOL_SOCKET, SO_BINDTODEVICE) => return bind_to_device_name(&s, optval, optlen_p),
            (IPPROTO_IP, IP_TOS) => return i32_back(s.opts.ip_tos.load(Ordering::Acquire)),
            (IPPROTO_IP, IP_TTL) => return i32_back(s.opts.ip_ttl.load(Ordering::Acquire)),
            (IPPROTO_TCP, 1) => return i32_back(s.opts.tcp_nodelay.load(Ordering::Acquire)),
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
            _ => {}
        }
    }
    if optlen_p != 0 && optlen_p < USER_VA_END {
        // SAFETY: optlen_p validated < USER_VA_END; CPL=0 write through caller's AS.
        unsafe { core::ptr::write_volatile(optlen_p as *mut u32, 0); }
    }
    0
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
