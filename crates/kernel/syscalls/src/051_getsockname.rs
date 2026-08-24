// 051 getsockname — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::net_trace::trace_enotsock_at;
use crate::net_sockaddr::*;
use crate::net_common::{fd_file, socket_from_file, vsock_from_file};

/// `getsockname(fd, addr, addrlen)` slot 51 — write local addr.
/// # C: O(1)
pub fn sys_getsockname(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let len_p  = args.a2;
    let file = match fd_file(fd) {
        Some(file) => file,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    if let Some(target) = crate::netlink_fd::from_file(file.clone()) {
        return crate::netlink_fd::getsockname(&target, addr_p, len_p);
    }
    if let Some(vsock) = vsock_from_file(file.clone()) {
        if let Err(e) = net::sock_opts::check_vsock_name_query(&vsock) {
            return crate::net_errno::errno_from_neterr(e);
        }
        let (port, cid) = match vsock.local_addr() {
            Ok(addr) => addr,
            Err(e) => return crate::net_errno::errno_from_neterr(e),
        };
        let sa = encoded_sockaddr_vm(port, cid);
        return copy_sockaddr_to_user(addr_p, len_p, &sa);
    }
    let sock = match socket_from_file(file) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"getsockname"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    if let Err(e) = net::sock_opts::check_socket_name_query(&sock) {
        return crate::net_errno::errno_from_neterr(e);
    }
    let sa = crate::sock_name::local_sockaddr(&sock);
    copy_sockaddr_to_user(addr_p, len_p, &sa)
}
