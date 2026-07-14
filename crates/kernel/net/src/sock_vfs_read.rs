// VFS read(2) helpers for non-stream socket kinds.

use crate::NetError;
use crate::sock::{InetSocket, SockKind, AF_INET6};
use crate::sock_io::{monotonic_ns_safe, recvfrom_opts, RecvOptions};

/// Map socket receive errors into VFS read errors. # C: O(1)
pub(crate) fn recv_vfs_err(e: NetError) -> vfs::VfsError {
    match e {
        NetError::Eagain        => vfs::VfsError::Eagain,
        NetError::Eintr         => vfs::VfsError::Eintr,
        NetError::Einval        => vfs::VfsError::Einval,
        NetError::Enobufs       => vfs::VfsError::Enobufs,
        NetError::Enomem        => vfs::VfsError::Enomem,
        NetError::Eaddrnotavail => vfs::VfsError::Eaddrnotavail,
        NetError::Edestaddrreq  => vfs::VfsError::Edestaddrreq,
        NetError::Enetunreach   => vfs::VfsError::Enetunreach,
        NetError::Econnrefused  => vfs::VfsError::Econnrefused,
        NetError::Econnreset    => vfs::VfsError::Econnreset,
        NetError::Epipe         => vfs::VfsError::Epipe,
        NetError::Enotconn      => vfs::VfsError::Enotconn,
        _                       => vfs::VfsError::Eio,
    }
}

/// VFS `read(2)` for datagram/packet sockets: consume one message via the same
/// receive core as `recvfrom(..., src=NULL)`. # C: O(payload)
pub(crate) fn read_msg_socket_blocking(sock: &InetSocket, buf: &mut [u8], deadline_ns: u64) -> vfs::KResult<usize> {
    loop {
        match recvfrom_opts(sock, buf.len(), RecvOptions::default()) {
            Ok(r) => {
                let n = r.payload.len();
                buf[..n].copy_from_slice(&r.payload);
                return Ok(n);
            }
            Err(NetError::Eagain) => {}
            Err(e) => return Err(recv_vfs_err(e)),
        }
        if sched::live::deliverable_signals_self() != 0 { return Err(vfs::VfsError::Eintr); }
        if deadline_ns != 0 && monotonic_ns_safe() >= deadline_ns { return Err(vfs::VfsError::Eagain); }
        park_msg_socket(sock, deadline_ns);
    }
}

/// Park on the receive wait source matching `recvfrom` for the same socket kind. # C: O(1)
fn park_msg_socket(sock: &InetSocket, deadline_ns: u64) {
    let is_v6 = sock.family.load(core::sync::atomic::Ordering::Acquire) == AF_INET6;
    let is_udp = matches!(*sock.kind.lock(), SockKind::Udp);
    let v6_q = if is_udp && is_v6 {
        sock.local_port.lock().and_then(|p| crate::sock::stack().udp6_queue_arc(p))
    } else { None };
    let udp_q = if is_udp && !is_v6 {
        sock.local_port.lock().and_then(|p| crate::sock::stack().udp_queue_arc(p))
    } else { None };
    // SAFETY: process ctx; preempt-off owned by syscall stub; selected waiters
    // are woken by the same RX paths used by recvfrom, or by timer expiry.
    unsafe {
        if let Some(q) = v6_q {
            q.waiters.park_with_deadline(deadline_ns);
        } else if let Some(q) = udp_q {
            q.waiters.park_with_deadline(deadline_ns);
        } else {
            match &*sock.kind.lock() {
                SockKind::UnixDgram(q) => q.waiters.park_with_deadline(deadline_ns),
                SockKind::Packet { .. } => sock.recv_waiters.park_with_deadline(deadline_ns),
                _ => sched::live::tick_yield(),
            }
        }
        sched::live::schedule::schedule();
    }
}
