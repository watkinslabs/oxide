// VFS read(2) helpers for non-stream socket kinds.

use crate::NetError;
use crate::sock::InetSocket;
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
        NetError::Etimedout     => vfs::VfsError::Etimedout,
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
                if r.full_len != 0 || r.peer.is_some() || r.peer6.is_some() || r.packet.is_some() {
                    match r.packet.and_then(crate::sock::PacketReceive::timestamp_ns) {
                        Some(timestamp_ns) => sock.note_receive_timestamp(timestamp_ns),
                        None => sock.note_receive_now(),
                    }
                }
                return Ok(n);
            }
            Err(NetError::Eagain) => {}
            Err(e) => return Err(recv_vfs_err(e)),
        }
        // `sock_intr_errno(timeo)` — see `sock_recv::recv_blocking`.
        if sched::live::deliverable_signals_self() != 0 {
            return Err(crate::sock_intr::sock_intr_vfs(deadline_ns));
        }
        if deadline_ns != 0 && monotonic_ns_safe() >= deadline_ns { return Err(vfs::VfsError::Eagain); }
        if crate::sock_recv::wait_recv_source(sock, deadline_ns) { return Ok(0); }
    }
}
