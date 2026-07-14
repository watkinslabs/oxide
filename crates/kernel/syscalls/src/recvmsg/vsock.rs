use alloc::sync::Arc;

use net::uapi::{MSG_DONTWAIT, MSG_PEEK, MSG_WAITALL};
use syscall::errno::Errno;

use crate::net_common::file_is_nonblock;
use crate::recv_user::RecvUser;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

pub(crate) fn recv_with_copy_pinned<F>(sock: &Arc<net::vsock_socket::VsockSocket>, capacity: usize, flags: u64, file_nonblock: bool, mut copy: F) -> Result<usize, i64>
where F: FnMut(usize, &[u8]) -> Result<usize, i64>
{
    if capacity == 0 { return Ok(0); }
    if sock.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(0); }
    let conn = sock.conn().ok_or_else(|| err(Errno::Enotconn))?;
    let peek = flags & MSG_PEEK != 0;
    let waitall = flags & MSG_WAITALL != 0;
    let nonblock = flags & MSG_DONTWAIT != 0 || file_nonblock;
    let mut total = 0usize;
    loop {
        let _ = net::vsock::poll_rx_for(conn.owner);
        let offset = if peek { total } else { 0 };
        match net::vsock::recv_with_offset(&conn, capacity - total, peek, offset,
            |bytes| copy(total, bytes).map(|n| (n, n))) {
            Ok(net::vsock::RecvWith::Data(copied)) => {
                total += copied;
                if !waitall || total == capacity { return Ok(total); }
            }
            Ok(net::vsock::RecvWith::Eof) => {
                if total == 0 {
                    let pending = sock.take_pending_recv_error();
                    if pending != 0 { return Err(-(pending as i64)); }
                }
                return Ok(total);
            }
            Ok(net::vsock::RecvWith::Retry) => {
                if total == 0 {
                    let pending = sock.take_pending_recv_error();
                    if pending != 0 { return Err(-(pending as i64)); }
                } else if sock.has_pending_recv_error() { return Ok(total); }
            }
            Err(e) => return if total != 0 { Ok(total) } else { Err(e) },
        }
        if nonblock { return if total != 0 { Ok(total) } else { Err(err(Errno::Eagain)) }; }
        if sched::live::deliverable_signals_self() != 0 { return if total != 0 { Ok(total) } else { Err(err(Errno::Eintr)) }; }
        let rx = conn.rx.lock();
        if rx.len() > if peek { total } else { 0 } { continue; }
        // SAFETY: RX lock closes the enqueue-before-park lost-wake window;
        // interruptible sleep lets WAITALL return a copied prefix on signal.
        unsafe { conn.waiters.park_interruptible_with_deadline(0); }
        drop(rx);
        // SAFETY: current task is parked on this connection's wait list.
        unsafe { sched::live::schedule::schedule(); }
    }
}

pub(crate) fn recv_with_copy<F>(fd: u64, capacity: usize, flags: u64, copy: F) -> Result<usize, i64>
where F: FnMut(usize, &[u8]) -> Result<usize, i64>
{
    let sock = crate::net_common::vsock_from_fd(fd).ok_or_else(|| err(Errno::Ebadf))?;
    recv_with_copy_pinned(&sock, capacity, flags, file_is_nonblock(fd), copy)
}

/// AF_VSOCK stream recvmsg through its transactional RX queue. # C: O(payload)
pub(crate) fn recv_pinned(sock: &Arc<net::vsock_socket::VsockSocket>, file_nonblock: bool, user: &RecvUser, flags: u64) -> i64 {
    let copied = match recv_with_copy_pinned(sock, user.capacity, flags, file_nonblock, |offset, bytes| user.copy_payload_at(offset, bytes)) {
        Ok(copied) => copied,
        Err(e) => return e,
    };
    if let Err(e) = user.copy_name(&[]) { return e; }
    if let Err(e) = user.finish(0, crate::recv_control::output_flags(flags)) { return e; }
    copied as i64
}

/// AF_VSOCK recvmsg after fd resolution. # C: O(payload)
pub(crate) fn recv(fd: u64, user: &RecvUser, flags: u64) -> i64 {
    let sock = match crate::net_common::vsock_from_fd(fd) { Some(sock) => sock, None => return err(Errno::Ebadf) };
    recv_pinned(&sock, file_is_nonblock(fd), user, flags)
}
