// 051 getsockname — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::net_trace::trace_enotsock_at;
use crate::net_sockaddr::*;
use crate::net_common::socket_from_fd;
use net::sock::SockKind;

/// `getsockname(fd, addr, addrlen)` slot 51 — write local addr.
/// # C: O(1)
pub fn sys_getsockname(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let len_p  = args.a2;
    if crate::netlink_fd::is_netlink(fd) {
        return crate::netlink_fd::getsockname(fd, addr_p, len_p);
    }
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"getsockname"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    let raw = match &*sock.kind.lock() {
        SockKind::Raw4(endpoint) => {
            let state = endpoint.snapshot();
            Some(encoded_sockaddr_in(state.local.as_u32().to_be(), 0))
        }
        SockKind::Raw6(endpoint) => {
            let local = endpoint.local();
            Some(encoded_sockaddr_in6(local.addr.0, 0, local.scope_id))
        }
        _ => None,
    };
    if let Some(sa) = raw { return copy_sockaddr_to_user(addr_p, len_p, &sa); }
    let port = (*sock.local_port.lock()).unwrap_or(0);
    let ip   = *sock.local_ip.lock();
    let sa = encoded_sockaddr_for_socket(&sock, ip, port);
    copy_sockaddr_to_user(addr_p, len_p, &sa)
}
