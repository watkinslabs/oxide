use crate::sock::{drain_loopback, stack, InetSocket};
use crate::stack::TcpEntry;

/// Block until TCP receive data or a terminal receive state is visible.
/// # C: blocks until recv_buf non-empty or terminal state
/// # Lk: takes entry.conn briefly between yields; entry.rx_waiters during park
/// # Ctx: process; preempt-off; runqueue installed
pub(crate) fn read_tcp_blocking(
    sock: &InetSocket,
    entry: &alloc::sync::Arc<TcpEntry>,
    buf: &mut [u8],
    deadline_ns: u64,
) -> vfs::KResult<usize> {
    loop {
        drain_loopback();
        let got = stack().tcp_recv(entry, buf.len());
        if !got.is_empty() {
            let n = got.len();
            buf[..n].copy_from_slice(&got);
            return Ok(n);
        }
        let eno = sock.take_pending_recv_error();
        if eno != 0 { return Err(tcp_vfs_error(eno)); }
        if sock.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(0); }
        if tcp_recv_eof(entry.conn.lock().state) { return Ok(0); }
        #[cfg(target_os = "oxide-kernel")]
        if sched::live::deliverable_signals_self() != 0 { return Err(vfs::VfsError::Eintr); }
        #[cfg(target_os = "oxide-kernel")]
        if deadline_ns != 0 && super::monotonic_ns_safe() >= deadline_ns {
            return Err(vfs::VfsError::Eagain);
        }
        #[cfg(target_os = "oxide-kernel")]
        if arm_tcp_read(sock, entry, deadline_ns) {
            // SAFETY: arm_tcp_read published current under entry.conn.
            unsafe { sched::live::schedule::schedule(); }
            entry.rx_waiters.remove_current();
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        return Err(vfs::VfsError::Eagain);
    }
}

/// Map canonical TCP errno after queued data has been drained. # C: O(1)
pub(crate) fn tcp_vfs_error(errno: i32) -> vfs::VfsError {
    if errno == syscall::errno::Errno::Econnreset as i32 { vfs::VfsError::Econnreset }
    else if errno == syscall::errno::Errno::Econnrefused as i32 { vfs::VfsError::Econnrefused }
    else if errno == syscall::errno::Errno::Etimedout as i32 { vfs::VfsError::Etimedout }
    else { vfs::VfsError::Eio }
}

pub fn tcp_recv_eof(st: crate::tcp_state::TcpState) -> bool {
    st == crate::tcp_state::TcpState::Closed
        || st == crate::tcp_state::TcpState::CloseWait
        || st == crate::tcp_state::TcpState::LastAck
        || st == crate::tcp_state::TcpState::Closing
        || st == crate::tcp_state::TcpState::TimeWait
}

/// Atomically recheck TCP receive shutdown/data state and park current.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn arm_tcp_read(sock: &InetSocket, entry: &alloc::sync::Arc<TcpEntry>, deadline_ns: u64) -> bool {
    arm_tcp_read_after(sock, entry, 0, deadline_ns)
}

/// Atomically park until bytes exist beyond a non-consuming peek offset. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn arm_tcp_read_after(sock: &InetSocket, entry: &alloc::sync::Arc<TcpEntry>, offset: usize, deadline_ns: u64) -> bool {
    let c = entry.conn.lock();
    if sock.read_shut.load(core::sync::atomic::Ordering::Acquire)
        || sock.has_pending_recv_error() || c.recv_buf.len() > offset || c.has_urgent()
        || tcp_recv_eof(c.state)
    {
        return false;
    }
    // SAFETY: process context; TCP receive and shutdown mutate under conn
    // before waking rx_waiters, so publication cannot miss either transition.
    unsafe { entry.rx_waiters.park_interruptible_with_deadline(deadline_ns); }
    drop(c);
    true
}

#[cfg(test)]
mod tests {
    use super::tcp_recv_eof;
    use crate::tcp_state::TcpState;

    #[test]
    fn receive_eof_covers_passive_and_simultaneous_close() {
        for st in [TcpState::Closed, TcpState::CloseWait, TcpState::LastAck,
            TcpState::Closing, TcpState::TimeWait]
        {
            assert!(tcp_recv_eof(st));
        }
        for st in [TcpState::Established, TcpState::FinWait1, TcpState::FinWait2] {
            assert!(!tcp_recv_eof(st));
        }
    }
}
