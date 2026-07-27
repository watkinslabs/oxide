use alloc::sync::Arc;

use net::uapi::{MSG_DONTWAIT, MSG_EOR, MSG_PEEK, MSG_TRUNC, MSG_WAITALL};
use syscall::errno::Errno;

use crate::net_common::VsockFileRef;
use crate::recv_user::RecvUser;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Linux-ordered state selected before one connectible VSOCK `recvmsg`.
enum RecvmsgState {
    Empty,
    Stream(Arc<net::vsock::VsockConn>),
    Seqpacket(Arc<net::vsock::VsockConn>),
}

/// Validate AF_VSOCK receive state before touching either receive queue.
///
/// This mirrors Linux's connectible receive ordering: connection state, OOB,
/// local read shutdown, then a zero-length return.  In particular, zero-length
/// seqpacket receives must not enter the record transaction or retire credit.
fn recvmsg_preflight(sock: &Arc<net::vsock_socket::VsockSocket>, capacity: usize,
    flags: u64) -> Result<RecvmsgState, i64>
{
    sock.check_receive().map_err(|_| err(Errno::Eacces))?;
    if sock.is_datagram() { return Err(err(Errno::Eopnotsupp)); }
    let conn = sock.conn().ok_or_else(|| err(Errno::Enotconn))?;
    match *conn.st.lock() {
        net::vsock::VsockState::Connecting => return Err(err(Errno::Enotconn)),
        net::vsock::VsockState::RcvShutdown | net::vsock::VsockState::Closed => {
            return Ok(RecvmsgState::Empty);
        }
        net::vsock::VsockState::Connected => {}
    }
    if flags & net::uapi::MSG_OOB != 0 { return Err(err(Errno::Eopnotsupp)); }
    if sock.read_shut.load(core::sync::atomic::Ordering::Acquire) || capacity == 0 {
        return Ok(RecvmsgState::Empty);
    }
    Ok(match sock.socket_type() {
        net::vsock_socket::VsockSocketType::Stream => RecvmsgState::Stream(conn),
        net::vsock_socket::VsockSocketType::Seqpacket => RecvmsgState::Seqpacket(conn),
        net::vsock_socket::VsockSocketType::Datagram => unreachable!("datagram rejected above"),
    })
}

fn recv_with_copy_inner<F, R>(sock: &Arc<net::vsock_socket::VsockSocket>, capacity: usize,
    flags: u64, file_nonblock: bool, copy: F, retry: R) -> Result<usize, i64>
where F: FnMut(usize, &[u8]) -> Result<usize, i64>, R: FnMut(&Arc<net::vsock_socket::VsockSocket>)
{
    sock.check_receive().map_err(|_| err(Errno::Eacces))?;
    // Current virtio-vsock exposes the DGRAM socket but its transport
    // `dgram_dequeue` operation is explicitly unsupported.
    if sock.is_datagram() { return Err(err(Errno::Eopnotsupp)); }
    if capacity == 0 { return Ok(0); }
    if sock.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(0); }
    let conn = sock.conn().ok_or_else(|| err(Errno::Enotconn))?;
    recv_connected_with_copy(sock, &conn, capacity, flags, file_nonblock, copy, retry)
}

/// Receive from a VSOCK stream whose recvmsg preflight retained its connection.
fn recv_connected_with_copy<F, R>(sock: &Arc<net::vsock_socket::VsockSocket>,
    conn: &Arc<net::vsock::VsockConn>, capacity: usize, flags: u64, file_nonblock: bool,
    mut copy: F, mut retry: R) -> Result<usize, i64>
where F: FnMut(usize, &[u8]) -> Result<usize, i64>, R: FnMut(&Arc<net::vsock_socket::VsockSocket>)
{
    let peek = flags & MSG_PEEK != 0;
    let waitall = flags & MSG_WAITALL != 0;
    let nonblock = flags & MSG_DONTWAIT != 0 || file_nonblock;
    let mut total = 0usize;
    loop {
        if sock.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(total); }
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
                retry(sock);
                if sock.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(total); }
            }
            Err(e) => return if total != 0 { Ok(total) } else { Err(e) },
        }
        if nonblock { return if total != 0 { Ok(total) } else { Err(err(Errno::Eagain)) }; }
        #[cfg(target_os = "oxide-kernel")]
        {
            // Linux `vsock_connectible_recvmsg`'s wait loop
            // (`net/vmw_vsock/af_vsock.c:2383-2385`): `err = sock_intr_errno(timeout)`
            // off `sock_rcvtimeo`.
            if sched::live::deliverable_signals_self() != 0 {
                return crate::net_errno::recv_interrupted(sock.recv_deadline_ns(), total);
            }
            if !conn.arm_recv_wait(sock, if peek { total } else { 0 }, 0) { continue; }
            // SAFETY: current task is parked on this connection's wait list.
            unsafe { sched::live::schedule::schedule(); }
            conn.waiters.remove_current();
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        {
            if !conn.recv_wait_would_park(sock, if peek { total } else { 0 }) { continue; }
            return if total != 0 { Ok(total) } else { Err(err(Errno::Eagain)) };
        }
    }
}

/// Receive through one already-retained VSOCK endpoint. # C: O(payload)
pub(crate) fn recv_with_copy_pinned<F>(sock: &Arc<net::vsock_socket::VsockSocket>, capacity: usize, flags: u64, file_nonblock: bool, copy: F) -> Result<usize, i64>
where F: FnMut(usize, &[u8]) -> Result<usize, i64>
{
    recv_with_copy_inner(sock, capacity, flags, file_nonblock, copy, |_| {})
}

/// Receive through one classified retained VSOCK file. # C: O(payload)
pub(crate) fn recv_with_copy<F>(target: &VsockFileRef, capacity: usize, flags: u64, copy: F) -> Result<usize, i64>
where F: FnMut(usize, &[u8]) -> Result<usize, i64>
{
    recv_with_copy_pinned(target, capacity, flags, target.is_nonblock(), copy)
}

/// AF_VSOCK stream recvmsg through its transactional RX queue. # C: O(payload)
pub(crate) fn recv_pinned(sock: &Arc<net::vsock_socket::VsockSocket>, file_nonblock: bool, user: &RecvUser, flags: u64) -> i64 {
    let state = match recvmsg_preflight(sock, user.capacity, flags) {
        Ok(state) => state,
        Err(error) => return error,
    };
    if matches!(state, RecvmsgState::Empty) {
        return finish_seqpacket(user, flags, 0, false, false);
    }
    if let RecvmsgState::Seqpacket(conn) = state {
        return recv_seqpacket_pinned(sock, &conn, file_nonblock, user, flags);
    }
    let RecvmsgState::Stream(conn) = state else { unreachable!("empty state returned above"); };
    let copied = match recv_connected_with_copy(sock, &conn, user.capacity, flags, file_nonblock,
        |offset, bytes| user.copy_payload_at(offset, bytes), |_| {}) {
        Ok(copied) => copied,
        Err(e) => return e,
    };
    if let Err(e) = user.copy_name(&[]) { return e; }
    if let Err(e) = user.finish(0, crate::recv_control::output_flags(flags)) { return e; }
    copied as i64
}

/// AF_VSOCK `SOCK_SEQPACKET` recvmsg through the canonical complete-record
/// owner. # C: O(record + iov)
fn recv_seqpacket_pinned(sock: &Arc<net::vsock_socket::VsockSocket>, conn: &Arc<net::vsock::VsockConn>,
    file_nonblock: bool, user: &RecvUser, flags: u64) -> i64
{
    let peek = flags & MSG_PEEK != 0;
    let nonblock = flags & MSG_DONTWAIT != 0 || file_nonblock;
    loop {
        if sock.read_shut.load(core::sync::atomic::Ordering::Acquire) {
            return finish_seqpacket(user, flags, 0, false, false);
        }
        let _ = net::vsock::poll_rx_for(conn.owner);
        match net::vsock::recv_seqpacket_with(&conn, user.capacity, peek,
            |bytes| user.copy_payload_record(bytes)) {
            Ok(net::vsock::SeqpacketRecvWith::Data(copied, delivery)) => {
                let returned = if flags & MSG_TRUNC != 0 { delivery.message_len } else { copied };
                return finish_seqpacket(user, flags, returned, delivery.truncated,
                    delivery.end_of_record);
            }
            Ok(net::vsock::SeqpacketRecvWith::Eof) => {
                let pending = sock.take_pending_recv_error();
                if pending != 0 { return -(pending as i64); }
                return finish_seqpacket(user, flags, 0, false, false);
            }
            Ok(net::vsock::SeqpacketRecvWith::Retry) => {
                let pending = sock.take_pending_recv_error();
                if pending != 0 { return -(pending as i64); }
            }
            Err(error) => return error,
        }
        if nonblock { return err(Errno::Eagain); }
        #[cfg(target_os = "oxide-kernel")]
        {
            // Same `sock_intr_errno(timeout)` rule as the stream path above
            // (`net/vmw_vsock/af_vsock.c:2384`).
            if sched::live::deliverable_signals_self() != 0 {
                return crate::net_errno::sock_intr_errno(sock.recv_deadline_ns());
            }
            if !net::vsock::arm_seqpacket_recv_wait(&conn, sock, 0) { continue; }
            // SAFETY: current task is parked on this connection's wait list.
            unsafe { sched::live::schedule::schedule(); }
            conn.waiters.remove_current();
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        {
            if !net::vsock::seqpacket_recv_wait_would_park(&conn, sock) { continue; }
            return err(Errno::Eagain);
        }
    }
}

/// Publish seqpacket-specific receive flags after one record transaction.
/// # C: O(faults)
fn finish_seqpacket(user: &RecvUser, flags: u64, returned: usize, truncated: bool,
    end_of_record: bool) -> i64
{
    if let Err(error) = user.copy_name(&[]) { return error; }
    let mut output = crate::recv_control::output_flags(flags);
    if truncated { output |= MSG_TRUNC as u32; }
    if end_of_record { output |= MSG_EOR as u32; }
    if let Err(error) = user.finish(0, output) { return error; }
    returned as i64
}

#[cfg(test)]
#[path = "vsock_shutdown_tests.rs"]
mod shutdown_tests;
