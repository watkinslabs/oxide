// 048 shutdown — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::net_trace::trace_enotsock_at;
use crate::net_common::{errno_from_neterr, fd_file, inode_as_inet_socket, vsock_from_file};

/// `shutdown(fd, how)` slot 48. POSIX semantics:
///   SHUT_RD   (0) — drain queued input, then apply protocol receive shutdown
///   SHUT_WR   (1) — apply protocol send shutdown and notify the peer
///   SHUT_RDWR (2) — both
/// Protocol state and wakeup ordering are owned by `net::sock::shutdown`.
/// # C: O(1)
pub fn sys_shutdown(args: &SyscallArgs) -> i64 {
    let fd  = args.a0;
    let how = args.a1 as u32;
    let file = match fd_file(fd) {
        Some(file) => file,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // Linux `netlink_ops.shutdown = sock_no_shutdown`: classify the valid
    // AF_NETLINK socket first, then let its owner perform security admission
    // and return EOPNOTSUPP. `how` is intentionally not parsed for this
    // unsupported protocol operation.
    if let Some(netlink) = ::netlink::netlink_arc_from_inode(file.inode()) {
        return match netlink.shutdown() { Ok(()) => 0, Err(e) => errno_from_neterr(e) };
    }
    if let Some(vsock) = vsock_from_file(file.clone()) {
        return match vsock.shutdown_raw(how) { Ok(()) => 0, Err(e) => errno_from_neterr(e) };
    }
    let sock = match inode_as_inet_socket(file.inode()) {
        Some(sock) => sock,
        None => { trace_enotsock_at(fd, b"shutdown"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    match net::sock::shutdown_raw(&sock, how) { Ok(()) => 0, Err(e) => errno_from_neterr(e) }
}
