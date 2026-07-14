use net::uapi::{MSG_DONTWAIT, MSG_PEEK};
use syscall::errno::Errno;

use crate::net_common::file_is_nonblock;
use crate::recv_user::RecvUser;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

pub(crate) fn recv_with_copy<F>(fd: u64, capacity: usize, flags: u64, mut copy: F) -> Result<usize, i64>
where F: FnMut(&[u8]) -> Result<usize, i64>
{
    if capacity == 0 { return Ok(0); }
    let sock = crate::net_common::vsock_from_fd(fd).ok_or_else(|| err(Errno::Ebadf))?;
    if sock.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(0); }
    let conn = sock.conn().ok_or_else(|| err(Errno::Enotconn))?;
    let peek = flags & MSG_PEEK != 0;
    let nonblock = flags & MSG_DONTWAIT != 0 || file_is_nonblock(fd);
    loop {
        let _ = net::vsock::poll_rx_for(conn.owner);
        match net::vsock::recv_with(&conn, capacity, peek, |bytes| copy(bytes).map(|n| (n, n))) {
            Ok(net::vsock::RecvWith::Data(copied)) => return Ok(copied),
            Ok(net::vsock::RecvWith::Eof) => return Ok(0),
            Ok(net::vsock::RecvWith::Retry) => {}
            Err(e) => return Err(e),
        }
        if nonblock { return Err(err(Errno::Eagain)); }
        if sched::live::deliverable_signals_self() != 0 { return Err(err(Errno::Eintr)); }
        let rx = conn.rx.lock();
        if !rx.is_empty() { continue; }
        // SAFETY: RX lock closes the enqueue-before-park lost-wake window.
        unsafe { conn.waiters.park(); }
        drop(rx);
        // SAFETY: current task is parked on this connection's wait list.
        unsafe { sched::live::schedule::schedule(); }
    }
}

/// AF_VSOCK stream recvmsg through its transactional RX queue. # C: O(payload)
pub(crate) fn recv(fd: u64, user: &RecvUser, flags: u64) -> i64 {
    let copied = match recv_with_copy(fd, user.capacity, flags, |bytes| user.copy_payload(bytes)) {
        Ok(copied) => copied,
        Err(e) => return e,
    };
    if let Err(e) = user.write_namelen(0) { return e; }
    if let Err(e) = user.finish(0, 0) { return e; }
    copied as i64
}
