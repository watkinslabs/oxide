use net::sock::SockKind;
use syscall::errno::Errno;

use crate::recv_user::RecvUser;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Route one imported receive destination to its protocol owner. # C: O(1)
pub(crate) fn recv(fd: u64, user: &RecvUser, flags: u64) -> i64 {
    if crate::netlink_fd::is_netlink(fd) { return super::netlink::recv(fd, user, flags); }
    if crate::net_common::vsock_from_fd(fd).is_some() { return super::vsock::recv(fd, user, flags); }
    let sock = match crate::net_common::socket_from_fd(fd) {
        Some(sock) => sock,
        None => return if crate::net_common::fd_file(fd).is_some() { err(Errno::Enotsock) } else { err(Errno::Ebadf) },
    };
    if matches!(*sock.kind.lock(), SockKind::Unix(_, _) | SockKind::UnixMsgPair(_, _) | SockKind::UnixDgram(_)) {
        crate::unix_recv::recvmsg(&sock, fd, user, flags)
    } else {
        super::inet::recv(fd, &sock, user, flags)
    }
}
