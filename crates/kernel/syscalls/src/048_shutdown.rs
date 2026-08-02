// 048 shutdown — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use crate::net_common::{classify, errno_from_neterr, Routed};
use crate::sock_route::ControlOp;

/// `shutdown(fd, how)` slot 48. POSIX semantics:
///   SHUT_RD   (0) — drain queued input, then apply protocol receive shutdown
///   SHUT_WR   (1) — apply protocol send shutdown and notify the peer
///   SHUT_RDWR (2) — both
/// Protocol state and wakeup ordering are owned by `net::sock::shutdown`.
/// # C: O(1)
pub fn sys_shutdown(args: &SyscallArgs) -> i64 {
    let fd  = args.a0;
    let how = args.a1 as u32;
    // EBADF before ENOTSOCK, from the one ladder in `sock_route`.
    let target = match classify(fd, ControlOp::Shutdown, None) {
        Ok(target) => target,
        Err(error) => return -(error.as_i32() as i64),
    };
    match target {
        // The netlink socket's own shutdown operation performs security
        // admission and then reports the refusal. `how` is intentionally not
        // parsed for this unsupported protocol operation.
        Routed::Netlink(netlink) =>
            match netlink.socket().shutdown() { Ok(()) => 0, Err(e) => errno_from_neterr(e) },
        Routed::Vsock(vsock) =>
            match vsock.shutdown_raw(how) { Ok(()) => 0, Err(e) => errno_from_neterr(e) },
        Routed::Inet(_, sock) =>
            match net::sock::shutdown_raw(&sock, how) { Ok(()) => 0, Err(e) => errno_from_neterr(e) },
    }
}
