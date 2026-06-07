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
    const SO_TYPE:      u64 = 3;
    const SO_PEERCRED:  u64 = 17;
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
    if level == SOL_SOCKET && optname == SO_TYPE
       && optval != 0 && optval < USER_VA_END
       && optlen_p != 0 && optlen_p < USER_VA_END
    {
        // SAFETY: optval+optlen_p validated < USER_VA_END; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile(optval as *mut u32, 1 /* SOCK_STREAM */);
            core::ptr::write_volatile(optlen_p as *mut u32, 4);
        }
        return 0;
    }
    // Read-back of options stored via setsockopt.
    use core::sync::atomic::Ordering;
    const IPPROTO_TCP: u64 = 6;
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
            (SOL_SOCKET, 12) => return i32_back(s.opts.priority.load(Ordering::Acquire)),
            (SOL_SOCKET, 36) => return i32_back(s.opts.mark.load(Ordering::Acquire)),
            (IPPROTO_TCP, 1) => return i32_back(s.opts.tcp_nodelay.load(Ordering::Acquire)),
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
