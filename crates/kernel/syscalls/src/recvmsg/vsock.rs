use alloc::sync::Arc;

use net::uapi::{MSG_DONTWAIT, MSG_EOR, MSG_PEEK, MSG_TRUNC, MSG_WAITALL};
use syscall::errno::Errno;

use crate::net_common::VsockFileRef;
use crate::recv_user::RecvUser;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn recv_with_copy_inner<F, R>(sock: &Arc<net::vsock_socket::VsockSocket>, capacity: usize,
    flags: u64, file_nonblock: bool, mut copy: F, mut retry: R) -> Result<usize, i64>
where F: FnMut(usize, &[u8]) -> Result<usize, i64>, R: FnMut(&Arc<net::vsock_socket::VsockSocket>)
{
    sock.check_receive().map_err(|_| err(Errno::Eacces))?;
    // Current virtio-vsock exposes the DGRAM socket but its transport
    // `dgram_dequeue` operation is explicitly unsupported.
    if sock.is_datagram() { return Err(err(Errno::Eopnotsupp)); }
    if capacity == 0 { return Ok(0); }
    if sock.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(0); }
    let conn = sock.conn().ok_or_else(|| err(Errno::Enotconn))?;
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
            if sched::live::deliverable_signals_self() != 0 { return if total != 0 { Ok(total) } else { Err(err(Errno::Eintr)) }; }
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
    if flags & net::uapi::MSG_OOB != 0 { return err(Errno::Eopnotsupp); }
    if sock.socket_type() == net::vsock_socket::VsockSocketType::Seqpacket {
        return recv_seqpacket_pinned(sock, file_nonblock, user, flags);
    }
    let copied = match recv_with_copy_pinned(sock, user.capacity, flags, file_nonblock, |offset, bytes| user.copy_payload_at(offset, bytes)) {
        Ok(copied) => copied,
        Err(e) => return e,
    };
    if let Err(e) = user.copy_name(&[]) { return e; }
    if let Err(e) = user.finish(0, crate::recv_control::output_flags(flags)) { return e; }
    copied as i64
}

/// AF_VSOCK `SOCK_SEQPACKET` recvmsg through the canonical complete-record
/// owner. # C: O(record + iov)
fn recv_seqpacket_pinned(sock: &Arc<net::vsock_socket::VsockSocket>, file_nonblock: bool,
    user: &RecvUser, flags: u64) -> i64
{
    if sock.check_receive().is_err() { return err(Errno::Eacces); }
    if sock.read_shut.load(core::sync::atomic::Ordering::Acquire) {
        return finish_seqpacket(user, flags, 0, false, false);
    }
    let conn = match sock.conn() {
        Some(conn) => conn,
        None => return err(Errno::Enotconn),
    };
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
            if sched::live::deliverable_signals_self() != 0 { return err(Errno::Eintr); }
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
