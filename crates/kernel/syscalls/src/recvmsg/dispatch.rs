use alloc::sync::Arc;

use net::sock::SockKind;
use syscall::errno::Errno;
use vfs::OpenFlags;

use crate::recv_admit::{RecvFamily, RecvRoute};
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
    // The one receive-side security decision, and the only source of a route:
    // no protocol owner can be reached without it.
    let route = match crate::recv_admit::admit_and_route(target.security_sock(),
        target.family(), flags)
    { Ok(route) => route, Err(error) => return error };
    let nonblock = target.file.flags().contains(OpenFlags::O_NONBLOCK);
    match (route, &target.kind) {
        (RecvRoute::Netlink, _) =>
            super::netlink::recv_pinned(&target.file, nonblock, user, flags),
        (RecvRoute::Vsock, RecvKind::Vsock(sock)) =>
            super::vsock::recv_pinned(sock, nonblock, user, flags),
        (RecvRoute::Unix, RecvKind::Inet(sock)) =>
            crate::unix_recv::recvmsg(sock, nonblock, user, flags),
        (RecvRoute::InetErrqueue, RecvKind::Inet(sock)) =>
            super::inet::recv_error(sock, user, flags),
        (RecvRoute::Inet, RecvKind::Inet(sock)) =>
            super::inet::recv_pinned(sock, nonblock, user, flags),
        _ => err(Errno::Enotsock),
    }
}

impl RecvTarget {
    /// Describe the pinned receive target to the one message security
    /// boundary. # C: O(1)
    pub(crate) fn security_sock(&self) -> net::socket_security::MsgSock {
        match &self.kind {
            RecvKind::Inet(sock) => net::socket_security::inet(sock),
            RecvKind::Netlink(sock) => net::socket_security::other(
                net::net_ns::namespace_id(&sock.net_ns), net::socket_args::AF_NETLINK_WIRE),
            RecvKind::Vsock(sock) => net::socket_security::other(
                sock.net_ns(), net::socket_args::AF_VSOCK as u16),
        }
    }

    /// Concrete family of the pinned target, for admission and routing. # C: O(1)
    pub(crate) fn family(&self) -> RecvFamily {
        match &self.kind {
            RecvKind::Netlink(_) => RecvFamily::Netlink,
            RecvKind::Vsock(_) => RecvFamily::Vsock,
            RecvKind::Inet(sock) => RecvFamily::Inet {
                unix: matches!(*sock.kind.lock(), SockKind::Unix(_, _)
                    | SockKind::UnixMsgPair(_, _) | SockKind::UnixDgram(_)),
            },
        }
    }

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
