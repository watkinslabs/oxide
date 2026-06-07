// 042 connect — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::net_trace::trace_enotsock_at;
use crate::net_sockaddr::*;
use crate::net_common::{AF_INET, AF_INET6, errno_from_neterr, socket_from_fd};

/// `connect(fd, sockaddr, addrlen)` slot 42. Parses user sockaddr →
/// `net::sock::RemoteAddr` then calls `net::sock::connect`.
/// # C: O(1) UDP/UNIX, O(SYN-ACK RTT) TCP.
pub fn sys_connect(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"connect"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    const AF_UNIX: u32 = 1;
    let family = match read_sa_family(addr_p) {
        Some(f) => f as u32, None => return -(Errno::Efault.as_i32() as i64),
    };
    let addr = if family == AF_UNIX {
        let path = match read_sockaddr_un_path(addr_p) {
            Some(p) => p, None => return -(Errno::Einval.as_i32() as i64),
        };
        net::sock::RemoteAddr::UnixPath(path)
    } else if family == AF_INET || family == AF_INET6 {
        let sock_fam = sock.family.load(core::sync::atomic::Ordering::Acquire) as u32;
        if family != sock_fam { return -(Errno::Einval.as_i32() as i64); }
        // F180b: native v6 dst routes through connect_v6 (UDP stashes
        // the v6 peer, TCP runs tcp_connect_ip). Only the v4-mapped
        // form (::ffff:a.b.c.d) falls through to the v4 path for
        // dual-stack semantics — ::1 / :: / global are genuine v6 and
        // must NOT be mis-stashed as a v4 peer.
        if family == AF_INET6 {
            if let Some((_, port, bytes, _)) = read_sockaddr_in6(addr_p) {
                let v4_mapped = ipv4_from_v6_mapped(&bytes).is_some();
                if !v4_mapped {
                    return match net::sock::connect(&sock, net::sock::RemoteAddr::Inet6 { ip: net::Ipv6Addr(bytes), port }) {
                        Ok(()) => 0,
                        Err(net::NetError::Eio) => -(Errno::Etimedout.as_i32() as i64),
                        Err(e) => errno_from_neterr(e),
                    };
                }
            }
        }
        let (_fam, ip, port) = match read_sockaddr_any(addr_p) {
            Some(t) => t, None => return -(Errno::Eafnosupport.as_i32() as i64),
        };
        net::sock::RemoteAddr::Inet { ip, port }
    } else {
        return -(Errno::Eafnosupport.as_i32() as i64);
    };
    match net::sock::connect(&sock, addr) {
        Ok(()) => 0,
        Err(net::NetError::Eio) => -(Errno::Etimedout.as_i32() as i64),
        Err(e) => errno_from_neterr(e),
    }
}
