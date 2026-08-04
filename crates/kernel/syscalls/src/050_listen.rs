// 050 listen — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use crate::net_common::{classify, Routed};
use crate::net_errno::errno_from_neterr;
use crate::sock_route::ControlOp;

/// `listen(fd, backlog)` slot 50. ABI shim per `docs/53§4`.
/// # C: O(1)
pub fn sys_listen(args: &SyscallArgs) -> i64 {
    let fd      = args.a0;
    let backlog = args.a1 as i32;
    // EBADF, ENOTSOCK, and netlink's "no listen operation" EOPNOTSUPP all come
    // from the one ladder in `sock_route`, which the hosted suite drives.
    let target = match classify(fd, ControlOp::Listen, None) {
        Ok(target) => target,
        Err(error) => return -(error.as_i32() as i64),
    };
    match target {
        Routed::Netlink(netlink) => match netlink.socket().listen() {
            Ok(()) => 0, Err(error) => errno_from_neterr(error),
        },
        // D3.3: AF_VSOCK listen — register the bound port in the vsock
        // connection table so inbound OP_REQUESTs are accepted + queued.
        Routed::Vsock(vs) => match vs.listen_with_backlog(backlog) {
            Ok(()) => 0, Err(error) => errno_from_neterr(error),
        },
        Routed::Inet(file, sock) => match net::sock::listen(&sock, backlog) {
            Ok(()) => { net::bind_file(&file, &sock); 0 }
            Err(e) => errno_from_neterr(e),
        },
    }
}
