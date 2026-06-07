// 050 listen — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::net_trace::trace_enotsock_at;
use crate::net_common::{errno_from_neterr, socket_from_fd};

/// `listen(fd, backlog)` slot 50.
/// # C: O(1)
/// `listen(fd, backlog)` slot 50. Tier-3 shim per `docs/53§4`.
/// # C: O(1)
pub fn sys_listen(args: &SyscallArgs) -> i64 {
    let fd      = args.a0;
    let backlog = args.a1 as i32;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"listen"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    match net::sock::listen(&sock, backlog) {
        Ok(())  => 0,
        Err(e)  => errno_from_neterr(e),
    }
}
