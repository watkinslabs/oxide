// 052 getpeername — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;
use crate::net_trace::trace_enotsock_at;
use crate::net_sockaddr::*;
use crate::net_common::socket_from_fd;

/// `getpeername(fd, addr, addrlen)` slot 52.
/// # C: O(1)
pub fn sys_getpeername(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"getpeername"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    if addr_p == 0 || addr_p >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let (ip, port) = match *sock.peer.lock() {
        Some(t) => t, None => return -(Errno::Enotconn.as_i32() as i64),
    };
    write_sockaddr_for_socket(addr_p, &sock, ip, port);
    0
}
