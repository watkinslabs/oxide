// `mq_notify(SIGEV_THREAD)`'s netlink half: resolves the registrant's netlink
// socket by fd and delivers the stamped cookie on it.
//
// The registration holds the SOCKET, not the descriptor number: delivery runs
// in the SENDING process's context, where the registrant's fd number means
// nothing, so the socket is held for the life of the
// registration. That is what lets glibc's `mq_notify` helper thread keep
// working after it closes its own copy of the fd.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

/// Linux `netlink_getsockbyfd(fd)`: `EBADF` for a closed descriptor,
/// `ENOTSOCK` when it is not a socket, `EINVAL` when it is a socket of some
/// family other than `AF_NETLINK`.
/// # C: O(1)
pub(super) fn getsockbyfd(fd: i32) -> Result<Arc<netlink::NetlinkSocket>, Errno> {
    let cur = sched::live::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let fdt = (unsafe { cur.fd_table_ref() }).map(|t| t.clone()).ok_or(Errno::Ebadf)?;
    let file = fdt.get(fd).map_err(|_| Errno::Ebadf)?;
    let inode = file.inode();
    if inode.file_type() != vfs::FileType::Socket { return Err(Errno::Enotsock); }
    netlink::netlink_arc_from_inode(&inode).ok_or(Errno::Einval)
}

/// Linux `netlink_sendskb`: drop the stamped cookie on the registered socket's
/// receive queue and wake anything polling it.
/// # C: O(cookie.len())
pub(super) fn sendskb(sock: &Arc<netlink::NetlinkSocket>, cookie: &[u8]) {
    let mut msg: Vec<u8> = Vec::new();
    if msg.try_reserve_exact(cookie.len()).is_err() { return; }
    msg.extend_from_slice(cookie);
    sock.enqueue(msg);
}
