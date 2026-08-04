use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use net::sock::{InetSocket, SockKind};
use net::uapi::{MSG_DONTWAIT, MSG_OOB, MSG_PEEK, MSG_TRUNC, MSG_WAITALL};
use syscall::errno::Errno;

use crate::net_sockaddr::encoded_sockaddr_un;
use crate::recv_control;
use crate::recv_user::RecvUser;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `recv(MSG_OOB)` on a connected AF_UNIX stream: the one byte awaiting
/// out-of-band delivery, reported with `MSG_OOB` set in the returned flags.
/// Never blocks — nothing pending, or `SO_OOBINLINE` having put the byte in the
/// in-band stream instead, is the same EINVAL. `MSG_PEEK` leaves the byte where
/// it is. # C: O(1)
fn recv_urgent(pair: &Arc<net::UnixPair>, end: net::UnixEnd, sock: &Arc<InetSocket>,
    user: &RecvUser, flags: u64, inline: bool) -> i64
{
    let Some(byte) = pair.recv_oob(end, flags & MSG_PEEK != 0, inline) else {
        return err(Errno::Einval);
    };
    let copied = match user.copy_payload_at(0, &[byte]) { Ok(n) => n, Err(e) => return e };
    let path = net::sock::unix_peer_path(sock).unwrap_or(None);
    let sa = encoded_sockaddr_un(path.as_deref());
    if let Err(e) = finish(user, alloc::vec::Vec::new(), None, flags, MSG_OOB as u32, sa.as_bytes()) {
        return e;
    }
    sock.note_receive_now();
    copied as i64
}

enum WaitOutcome { Retry, DatagramShutdown }

fn wait_nonblock(sock: &Arc<InetSocket>, nonblock: bool, flags: u64, deadline: u64,
    generation: Option<u64>) -> Result<WaitOutcome, i64> {
    wait_nonblock_after(sock, nonblock, flags, deadline, 0, generation)
}

fn wait_nonblock_after(sock: &Arc<InetSocket>, nonblock: bool, flags: u64, deadline: u64,
    offset: usize, generation: Option<u64>) -> Result<WaitOutcome, i64> {
    if flags & MSG_DONTWAIT != 0 || nonblock { return Err(err(Errno::Eagain)); }
    // An interrupted AF_UNIX receive ends on the timeout-derived interrupt
    // errno for both the stream and the datagram/seqpacket flavours, so an
    // untimed recv is RESTARTABLE and only an SO_RCVTIMEO recv reports a
    // real EINTR.
    if sched::live::deliverable_signals_self() != 0 {
        return Err(crate::net_errno::sock_intr_errno(deadline));
    }
    if net::sock_recv::deadline_expired(deadline) { return Err(err(Errno::Eagain)); }
    if net::sock_recv::wait_unix_recv_source_after(sock, deadline, offset, generation) {
        Ok(WaitOutcome::DatagramShutdown)
    } else { Ok(WaitOutcome::Retry) }
}

fn finish(user: &RecvUser, files: alloc::vec::Vec<Arc<vfs::File>>, cred: Option<(u32, u32, u32)>, flags: u64, out_flags: u32, name: &[u8]) -> Result<(), i64> {
    finish_inq(user, files, cred, None, flags, out_flags, name)
}

/// `SO_INQ` is an AF_UNIX stream option, so only the stream arm can publish a
/// remaining-bytes control message. # C: O(files + faults)
fn finish_inq(user: &RecvUser, files: alloc::vec::Vec<Arc<vfs::File>>, cred: Option<(u32, u32, u32)>,
    inq: Option<net::sock_opts::inq::InqCmsg>, flags: u64, out_flags: u32, name: &[u8])
    -> Result<(), i64> {
    let delivered = recv_control::deliver(user, files, cred, inq, None, flags)?;
    user.copy_name(name)?;
    user.finish(delivered.len, out_flags | delivered.flags)
}

/// Bytes still queued for the reader, published as `SCM_INQ` when the socket
/// asked for it. The count comes from the one memory report `SO_MEMINFO` and
/// `SIOCINQ` also answer from, so the three can never disagree.
/// # C: O(queued frames)
fn inq(sock: &Arc<InetSocket>) -> Option<net::sock_opts::inq::InqCmsg> {
    if sock.opts.generic.scalar(net::sock_opts::sol_socket::Scalar::Inq) == 0 { return None; }
    Some(net::sock_opts::inq::InqCmsg::socket(
        net::sock_opts::meminfo(sock).rmem_alloc.min(i32::MAX as u32) as i32))
}

/// Receive from one AF_UNIX socket using queue-owned copy transactions. # C: O(payload + rights + faults)
pub(crate) fn recvmsg(sock: &Arc<InetSocket>, nonblock: bool, user: &RecvUser, flags: u64) -> i64 {
    if let Err(error) = net::security_admission::check(sock.net_ns(), net::sock::AF_UNIX,
        security::network::Operation::Receive)
    { return crate::net_errno::errno_from_neterr(error); }
    enum Target {
        Stream(Arc<net::UnixPair>, net::UnixEnd),
        Msg(Arc<net::UnixMsgPair>, net::UnixEnd),
        Dgram(Arc<net::UnixDgramQueue>),
    }
    let inline = sock.opts.oobinline.load(Ordering::Acquire) != 0;
    let target = match &*sock.kind.lock() {
        SockKind::Unix(pair, end) if flags & MSG_OOB != 0 =>
            return recv_urgent(&pair.clone(), *end, sock, user, flags, inline),
        SockKind::UnixMsgPair(_, _) | SockKind::UnixDgram(_) if flags & MSG_OOB != 0 => {
            return err(Errno::Eopnotsupp);
        }
        SockKind::Unix(pair, end) => Target::Stream(pair.clone(), *end),
        SockKind::UnixMsgPair(pair, end) => Target::Msg(pair.clone(), *end),
        SockKind::UnixDgram(q) => Target::Dgram(q.clone()),
        _ => return err(Errno::Einval),
    };
    let _transfer = net::transfer_guard();
    let peek = flags & MSG_PEEK != 0;
    let passcred = sock.opts.passcred.on();
    let deadline = net::sock::compute_deadline_ns(sock.opts.rcvtimeo_ns.load(Ordering::Acquire));
    let shutdown_generation = net::sock_recv::unix_shutdown_generation(sock);
    match target {
        Target::Stream(pair, end) => {
            let path = net::sock::unix_peer_path(sock).unwrap_or(None);
            let sa = encoded_sockaddr_un(path.as_deref());
            let waitall = flags & MSG_WAITALL != 0;
            let mut total = 0usize;
            let mut all_files = alloc::vec::Vec::new();
            let mut last_cred = None; // latched once, on the first glued segment
            // The writer this receive glued its first bytes from. The latch
            // outlives the sleep a MSG_WAITALL receive does when the queue runs
            // dry, so a writer that arrives during that sleep ends the receive
            // instead of being glued onto another writer's bytes.
            let mut committed: Option<net::unix_sock::MsgCred> = None;
            loop {
                let offset = if peek { total } else { 0 };
                match pair.read_stream_with_offset(end, user.capacity - total, peek, offset, passcred, committed.as_ref(), inline, |data, _, _| {
                    let copied = user.copy_payload_at(total, data)?;
                    Ok::<_, i64>((copied, copied))
                }) {
                    Err(e) => {
                        if total == 0 { return e; }
                        if let Err(e) = finish_inq(user, all_files, last_cred.and_then(|c: (u32, u32, u32)| net::scm::recv(passcred, net::sock_opts::SenderCreds { pid: c.0, uid: c.1, gid: c.2 })), inq(sock), flags, 0, sa.as_bytes()) { return e; }
                        sock.note_receive_now();
                        return total as i64;
                    }
                    Ok(Some((copied, files, cred))) => {
                        total += copied;
                        let got_control = files.stops_waitall(passcred);
                        if committed.is_none() { committed = files.committed_sender().cloned(); }
                        all_files.extend(files);
                        if last_cred.is_none() { last_cred = cred; }
                        if !net::unix_sock::stream_recv_continues(waitall, peek, total, user.capacity, got_control) {
                            if let Err(e) = finish_inq(user, all_files, last_cred.and_then(|c: (u32, u32, u32)| net::scm::recv(passcred, net::sock_opts::SenderCreds { pid: c.0, uid: c.1, gid: c.2 })), inq(sock), flags, 0, sa.as_bytes()) { return e; }
                            sock.note_receive_now();
                            return total as i64;
                        }
                    }
                    Ok(None) => {
                        if user.capacity == 0 {
                            if let Err(e) = user.copy_name(&[]).and_then(|_| user.finish(0, recv_control::output_flags(flags))) { return e; }
                            return 0;
                        }
                        if total == 0 {
                            let pending = sock.take_pending_recv_error();
                            if pending != 0 { return -(pending as i64); }
                        } else if sock.has_pending_recv_error() {
                            if let Err(e) = finish_inq(user, all_files, last_cred.and_then(|c: (u32, u32, u32)| net::scm::recv(passcred, net::sock_opts::SenderCreds { pid: c.0, uid: c.1, gid: c.2 })), inq(sock), flags, 0, sa.as_bytes()) { return e; }
                            sock.note_receive_now();
                            return total as i64;
                        }
                        if pair.take_reset(end) {
                            if total == 0 { return err(Errno::Econnreset); }
                            if let Err(e) = finish_inq(user, all_files, last_cred.and_then(|c: (u32, u32, u32)| net::scm::recv(passcred, net::sock_opts::SenderCreds { pid: c.0, uid: c.1, gid: c.2 })), inq(sock), flags, 0, sa.as_bytes()) { return e; }
                            sock.note_receive_now();
                            return total as i64;
                        }
                        if pair.is_eof(end) {
                            if total == 0 {
                                if let Err(e) = user.copy_name(&[]).and_then(|_| user.finish(0, recv_control::output_flags(flags))) { return e; }
                                return 0;
                            }
                            if let Err(e) = finish_inq(user, all_files, last_cred.and_then(|c: (u32, u32, u32)| net::scm::recv(passcred, net::sock_opts::SenderCreds { pid: c.0, uid: c.1, gid: c.2 })), inq(sock), flags, 0, sa.as_bytes()) { return e; }
                            sock.note_receive_now();
                            return total as i64;
                        }
                    }
                }
                // A receive that already copied something and may not sleep for
                // more ends here with what it has rather than blocking.
                if total != 0 && !net::unix_sock::stream_recv_continues(waitall, peek, total, user.capacity, false) {
                    if let Err(e) = finish_inq(user, all_files, last_cred.and_then(|c: (u32, u32, u32)| net::scm::recv(passcred, net::sock_opts::SenderCreds { pid: c.0, uid: c.1, gid: c.2 })), inq(sock), flags, 0, sa.as_bytes()) { return e; }
                    sock.note_receive_now();
                    return total as i64;
                }
                if let Err(e) = wait_nonblock_after(sock, nonblock, flags, deadline,
                    if peek { total } else { 0 }, shutdown_generation) {
                    if total == 0 { return e; }
                    if let Err(e) = finish_inq(user, all_files, last_cred.and_then(|c: (u32, u32, u32)| net::scm::recv(passcred, net::sock_opts::SenderCreds { pid: c.0, uid: c.1, gid: c.2 })), inq(sock), flags, 0, sa.as_bytes()) { return e; }
                    sock.note_receive_now();
                    return total as i64;
                }
            }
        }
        Target::Msg(pair, end) => {
            let sa = encoded_sockaddr_un(None);
            loop {
            match pair.recv_msg_with(end, user.capacity, peek, |payload, _, _, _| {
                let copied = user.copy_payload(payload)?;
                Ok::<_, i64>(copied)
            }) {
                Err(e) => return e,
                Ok(Some((copied, msg, full))) => {
                    let mut out_flags = 0;
                    if full > copied { out_flags |= MSG_TRUNC as u32; }
                    if let Err(e) = finish(user, msg.fds, net::scm::recv(passcred, { let c = msg.creds.ids_for_reader(); net::sock_opts::SenderCreds { pid: c.0, uid: c.1, gid: c.2 } }), flags, out_flags, sa.as_bytes()) { return e; }
                    sock.note_receive_now();
                    return if flags & MSG_TRUNC != 0 { full as i64 } else { copied as i64 };
                }
                Ok(None) => {
                    let pending = sock.take_pending_recv_error();
                    if pending != 0 { return -(pending as i64); }
                    if pair.take_reset(end) { return err(Errno::Econnreset); }
                    if pair.is_eof(end) {
                        if let Err(e) = user.copy_name(&[]).and_then(|_| user.finish(0, recv_control::output_flags(flags))) { return e; }
                        return 0;
                    }
                }
            }
            match wait_nonblock(sock, nonblock, flags, deadline, shutdown_generation) {
                Err(e) => return e,
                Ok(WaitOutcome::DatagramShutdown) => {
                    if let Err(e) = user.copy_name(&[]).and_then(|_| user.finish(0,
                        recv_control::output_flags(flags))) { return e; }
                    return 0;
                }
                Ok(WaitOutcome::Retry) => {}
            }
        }},
        Target::Dgram(q) => loop {
            match q.recv_with(peek, |msg, sender, _| {
                let copied = user.copy_payload(&msg.payload[..core::cmp::min(user.capacity, msg.payload.len())])?;
                let _ = sender;
                Ok::<_, i64>(copied)
            }) {
                Err(e) => return e,
                Ok(Some((copied, msg, sender))) => {
                    let mut out_flags = 0;
                    if msg.payload.len() > copied { out_flags |= MSG_TRUNC as u32; }
                    let sa = encoded_sockaddr_un(sender.as_ref().map(|addr| addr.display.as_slice()));
                    if let Err(e) = finish(user, msg.fds, net::scm::recv(passcred, { let c = msg.creds.ids_for_reader(); net::sock_opts::SenderCreds { pid: c.0, uid: c.1, gid: c.2 } }), flags, out_flags, sa.as_bytes()) { return e; }
                    sock.note_receive_now();
                    return if flags & MSG_TRUNC != 0 { msg.payload.len() as i64 } else { copied as i64 };
                }
                Ok(None) => {}
            }
            let pending = sock.take_pending_recv_error();
            if pending != 0 { return -(pending as i64); }
            match wait_nonblock(sock, nonblock, flags, deadline, shutdown_generation) {
                Err(e) => return e,
                Ok(WaitOutcome::DatagramShutdown) => {
                    if let Err(e) = user.copy_name(&[]).and_then(|_| user.finish(0,
                        recv_control::output_flags(flags))) { return e; }
                    return 0;
                }
                Ok(WaitOutcome::Retry) => {}
            }
        },
    }
}
