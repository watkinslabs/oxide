// 052 getpeername — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use crate::net_sockaddr::*;
use crate::net_common::{classify, Routed};
use crate::sock_route::ControlOp;

/// `getpeername(fd, addr, addrlen)` slot 52.
/// # C: O(1)
pub fn sys_getpeername(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let len_p  = args.a2;
    // EBADF before ENOTSOCK, from the one ladder in `sock_route`.
    let target = match classify(fd, ControlOp::GetPeerName, None) {
        Ok(target) => target,
        Err(error) => return -(error.as_i32() as i64),
    };
    match target {
        Routed::Netlink(target) => crate::netlink_fd::getpeername(&target, addr_p, len_p),
        Routed::Vsock(vsock) => {
            if let Err(e) = net::sock_opts::check_name_query(vsock.net_ns(), net::sock::AF_VSOCK) {
                return crate::net_common::errno_from_neterr(e);
            }
            let (port, cid) = match vsock.peer_addr() {
                Ok(addr) => addr,
                Err(e) => return crate::net_common::errno_from_neterr(e),
            };
            let sa = encoded_sockaddr_vm(port, cid);
            copy_sockaddr_to_user(addr_p, len_p, &sa)
        }
        Routed::Inet(_, sock) => {
            if let Err(e) = net::sock_opts::check_name_query(sock.net_ns(),
                sock.family.load(core::sync::atomic::Ordering::Acquire)) {
                return crate::net_common::errno_from_neterr(e);
            }
            match crate::sock_name::peer_sockaddr(&sock) {
                Ok(sa) => copy_sockaddr_to_user(addr_p, len_p, &sa),
                Err(error) => -(error.as_i32() as i64),
            }
        }
    }
}
