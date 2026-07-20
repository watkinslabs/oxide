use alloc::sync::Arc;

use net::sock::SockKind;
use net::uapi::MSG_ERRQUEUE;
use syscall::errno::Errno;
use vfs::OpenFlags;

use crate::recv_user::RecvUser;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

enum RecvKind {
    Inet(Arc<net::sock::InetSocket>),
    Netlink(Arc<::netlink::NetlinkSocket>),
    Vsock(Arc<net::vsock_socket::VsockSocket>),
}

/// One fget-style pin and concrete socket classification reused for a receive batch.
pub(crate) struct RecvTarget {
    file: Arc<vfs::File>,
    kind: RecvKind,
}

/// Resolve and classify one socket descriptor for the syscall duration. # C: O(1)
pub(crate) fn lookup(fd: u64) -> Result<RecvTarget, i64> {
    let file = crate::net_common::fd_file(fd).ok_or_else(|| err(Errno::Ebadf))?;
    from_file(file)
}

/// Classify an already-pinned file as a receive target. # C: O(1)
pub(crate) fn from_file(file: Arc<vfs::File>) -> Result<RecvTarget, i64> {
    let inode = file.inode();
    let kind = if let Ok(sock) = inode.i_private().clone().downcast::<::netlink::NetlinkSocket>() {
        RecvKind::Netlink(sock)
    } else if let Some(sock) = crate::net_common::inode_as_vsock(&inode) {
        RecvKind::Vsock(sock)
    } else if let Some(sock) = crate::net_common::inode_as_inet_socket(&inode) {
        RecvKind::Inet(sock)
    } else {
        return Err(err(Errno::Enotsock));
    };
    Ok(RecvTarget { file, kind })
}

/// Route one imported receive destination to its protocol owner. # C: O(1)
pub(crate) fn recv(target: &RecvTarget, user: &RecvUser, flags: u64) -> i64 {
    if flags & MSG_ERRQUEUE != 0 {
        if let RecvKind::Inet(sock) = &target.kind {
            if !matches!(*sock.kind.lock(), SockKind::Unix(_, _) | SockKind::UnixMsgPair(_, _)
                | SockKind::UnixDgram(_))
            {
                if let Err(error) = net::security_admission::check(sock.net_ns(),
                    sock.family.load(core::sync::atomic::Ordering::Acquire),
                    security::network::Operation::Receive)
                { return crate::net_common::errno_from_neterr(error); }
                return super::inet::recv_error(sock, user, flags);
            }
        }
    }
    let nonblock = target.file.flags().contains(OpenFlags::O_NONBLOCK);
    match &target.kind {
        RecvKind::Netlink(_) => super::netlink::recv_pinned(&target.file, nonblock, user, flags),
        RecvKind::Vsock(sock) => super::vsock::recv_pinned(sock, nonblock, user, flags),
        RecvKind::Inet(sock) => {
            if matches!(*sock.kind.lock(), SockKind::Unix(_, _) | SockKind::UnixMsgPair(_, _) | SockKind::UnixDgram(_)) {
                crate::unix_recv::recvmsg(sock, nonblock, user, flags)
            } else {
                super::inet::recv_pinned(sock, nonblock, user, flags)
            }
        }
    }
}

impl RecvTarget {
    /// Retained namespace/family owner for generic socket-option admission. # C: O(1)
    pub(crate) fn option_context(&self) -> (u64, u16) {
        match &self.kind {
            RecvKind::Inet(sock) => (sock.net_ns(), sock.family.load(core::sync::atomic::Ordering::Acquire)),
            RecvKind::Netlink(sock) => (net::net_ns::namespace_id(&sock.net_ns), net::socket_args::AF_NETLINK_WIRE),
            RecvKind::Vsock(sock) => (sock.net_ns(), net::socket_args::AF_VSOCK as u16),
        }
    }

    /// Consume the socket's first pending receive error. # C: O(1)
    pub(crate) fn take_error(&self) -> i32 {
        match &self.kind {
            RecvKind::Inet(sock) => sock.take_pending_recv_error(),
            RecvKind::Netlink(sock) => sock.take_pending_recv_error(),
            RecvKind::Vsock(sock) => sock.take_pending_recv_error(),
        }
    }

    /// Publish the latest pending positive receive error. # C: O(1)
    pub(crate) fn set_pending_error(&self, errno: i32) {
        match &self.kind {
            RecvKind::Inet(sock) => { sock.set_pending_recv_error(errno); }
            RecvKind::Netlink(sock) => { sock.set_pending_recv_error(errno); }
            RecvKind::Vsock(sock) => { sock.set_pending_recv_error(errno); }
        }
    }
}
