// 052 getpeername — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::net_trace::trace_enotsock_at;
use crate::net_sockaddr::*;
use crate::net_common::{fd_file, inode_as_inet_socket, vsock_from_file};

/// `getpeername(fd, addr, addrlen)` slot 52.
/// # C: O(1)
pub fn sys_getpeername(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let len_p  = args.a2;
    let file = match fd_file(fd) {
        Some(file) => file,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    if let Some(target) = crate::netlink_fd::from_file(file.clone()) {
        return crate::netlink_fd::getpeername(&target, addr_p, len_p);
    }
    if let Some(vsock) = vsock_from_file(file.clone()) {
        if let Err(e) = net::sock_opts::check_name_query(vsock.net_ns(), net::sock::AF_VSOCK) {
            return crate::net_common::errno_from_neterr(e);
        }
        let (port, cid) = match vsock.peer_addr() {
            Ok(addr) => addr,
            Err(e) => return crate::net_common::errno_from_neterr(e),
        };
        let sa = encoded_sockaddr_vm(port, cid);
        return copy_sockaddr_to_user(addr_p, len_p, &sa);
    }
    let sock = match inode_as_inet_socket(file.inode()) {
        Some(sock) => sock,
        None => { trace_enotsock_at(fd, b"getpeername"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    if let Err(e) = net::sock_opts::check_name_query(sock.net_ns(),
        sock.family.load(core::sync::atomic::Ordering::Acquire)) {
        return crate::net_common::errno_from_neterr(e);
    }
    match crate::sock_name::peer_sockaddr(&sock) {
        Ok(sa) => copy_sockaddr_to_user(addr_p, len_p, &sa),
        Err(error) => -(error.as_i32() as i64),
    }
}
