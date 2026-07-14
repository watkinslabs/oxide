use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use net::sock::{InetSocket, SockKind};
use net::uapi::{MSG_DONTWAIT, MSG_PEEK, MSG_TRUNC, MSG_WAITALL};
use syscall::errno::Errno;

use crate::net_common::file_is_nonblock;
use crate::net_sockaddr::{copy_sockaddr_to_user, encoded_sockaddr_un};
use crate::recv_control;
use crate::recv_user::RecvUser;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn wait_nonblock(sock: &Arc<InetSocket>, nonblock: bool, flags: u64, deadline: u64) -> Result<(), i64> {
    wait_nonblock_after(sock, nonblock, flags, deadline, 0)
}

fn wait_nonblock_after(sock: &Arc<InetSocket>, nonblock: bool, flags: u64, deadline: u64, offset: usize) -> Result<(), i64> {
    if flags & MSG_DONTWAIT != 0 || nonblock { return Err(err(Errno::Eagain)); }
    if sched::live::deliverable_signals_self() != 0 { return Err(err(Errno::Eintr)); }
    if net::sock_recv::deadline_expired(deadline) { return Err(err(Errno::Eagain)); }
    let _ = net::sock_recv::wait_recv_source_after(sock, deadline, offset);
    Ok(())
}

fn wait(sock: &Arc<InetSocket>, fd: u64, flags: u64, deadline: u64) -> Result<(), i64> {
    wait_after(sock, fd, flags, deadline, 0)
}

fn wait_after(sock: &Arc<InetSocket>, fd: u64, flags: u64, deadline: u64, offset: usize) -> Result<(), i64> {
    if flags & MSG_DONTWAIT != 0 { return Err(err(Errno::Eagain)); }
    wait_nonblock_after(sock, file_is_nonblock(fd), flags, deadline, offset)
}

fn finish(user: &RecvUser, files: alloc::vec::Vec<Arc<vfs::File>>, cred: Option<(u32, u32, u32)>, flags: u64, out_flags: u32, name: &[u8]) -> Result<(), i64> {
    let delivered = recv_control::deliver(user, files, cred, flags);
    user.copy_name(name)?;
    user.finish(delivered.len, out_flags | delivered.flags)
}

/// Receive from one AF_UNIX socket using queue-owned copy transactions. # C: O(payload + rights + faults)
pub(crate) fn recvmsg(sock: &Arc<InetSocket>, nonblock: bool, user: &RecvUser, flags: u64) -> i64 {
    enum Target {
        Stream(Arc<net::UnixPair>, net::UnixEnd),
        Msg(Arc<net::UnixMsgPair>, net::UnixEnd),
        Dgram(Arc<net::UnixDgramQueue>),
    }
    let target = match &*sock.kind.lock() {
        SockKind::Unix(pair, end) => Target::Stream(pair.clone(), *end),
        SockKind::UnixMsgPair(pair, end) => Target::Msg(pair.clone(), *end),
        SockKind::UnixDgram(q) => Target::Dgram(q.clone()),
        _ => return err(Errno::Einval),
    };
    let _transfer = net::transfer_guard();
    let peek = flags & MSG_PEEK != 0;
    let passcred = sock.opts.passcred.load(Ordering::Acquire) != 0;
    let deadline = net::sock::compute_deadline_ns(sock.opts.rcvtimeo_ns.load(Ordering::Acquire));
    match target {
        Target::Stream(pair, end) => {
            let path = net::sock::unix_peer_path(sock).unwrap_or(None);
            let sa = encoded_sockaddr_un(path.as_deref());
            let waitall = flags & MSG_WAITALL != 0;
            let mut total = 0usize;
            let mut all_files = alloc::vec::Vec::new();
            let mut last_cred = None;
            loop {
                let offset = if peek { total } else { 0 };
                match pair.read_stream_with_offset(end, user.capacity - total, peek, offset, |data, _, _| {
                    let copied = user.copy_payload_at(total, data)?;
                    Ok::<_, i64>((copied, copied))
                }) {
                    Err(e) => {
                        if total == 0 { return e; }
                        if let Err(e) = finish(user, all_files, if passcred { last_cred } else { None }, flags, 0, sa.as_bytes()) { return e; }
                        return total as i64;
                    }
                    Ok(Some((copied, files, cred))) => {
                        total += copied;
                        let got_control = files.stops_waitall(passcred);
                        all_files.extend(files);
                        if cred.is_some() { last_cred = cred; }
                        if !waitall || total == user.capacity || got_control {
                            if let Err(e) = finish(user, all_files, if passcred { last_cred } else { None }, flags, 0, sa.as_bytes()) { return e; }
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
                            if let Err(e) = finish(user, all_files, if passcred { last_cred } else { None }, flags, 0, sa.as_bytes()) { return e; }
                            return total as i64;
                        }
                        if pair.take_reset(end) {
                            if total == 0 { return err(Errno::Econnreset); }
                            if let Err(e) = finish(user, all_files, if passcred { last_cred } else { None }, flags, 0, sa.as_bytes()) { return e; }
                            return total as i64;
                        }
                        if pair.is_eof(end) {
                            if total == 0 {
                                if let Err(e) = user.copy_name(&[]).and_then(|_| user.finish(0, recv_control::output_flags(flags))) { return e; }
                                return 0;
                            }
                            if let Err(e) = finish(user, all_files, if passcred { last_cred } else { None }, flags, 0, sa.as_bytes()) { return e; }
                            return total as i64;
                        }
                    }
                }
                if let Err(e) = wait_nonblock_after(sock, nonblock, flags, deadline, if peek { total } else { 0 }) {
                    if total == 0 { return e; }
                    if let Err(e) = finish(user, all_files, if passcred { last_cred } else { None }, flags, 0, sa.as_bytes()) { return e; }
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
                    if let Err(e) = finish(user, msg.fds, if passcred { Some(msg.creds) } else { None }, flags, out_flags, sa.as_bytes()) { return e; }
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
            if let Err(e) = wait_nonblock(sock, nonblock, flags, deadline) { return e; }
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
                    if let Err(e) = finish(user, msg.fds, if passcred { Some(msg.creds) } else { None }, flags, out_flags, sa.as_bytes()) { return e; }
                    return if flags & MSG_TRUNC != 0 { msg.payload.len() as i64 } else { copied as i64 };
                }
                Ok(None) => {}
            }
            let pending = sock.take_pending_recv_error();
            if pending != 0 { return -(pending as i64); }
            if let Err(e) = wait_nonblock(sock, nonblock, flags, deadline) { return e; }
        },
    }
}

fn copy_one(dst: u64, payload: &[u8]) -> Result<usize, i64> {
    // SAFETY: payload is kernel-owned; raw usercopy reports the uncopied suffix.
    let left = unsafe { uaccess::raw_copy_to_user(dst, payload.as_ptr(), payload.len()) };
    let copied = payload.len() - left;
    if copied != 0 || payload.is_empty() { Ok(copied) } else { Err(err(Errno::Efault)) }
}

fn copy_stream_source(sock: &InetSocket, src: u64, src_len: u64) -> Result<(), i64> {
    if src == 0 { return Ok(()); }
    let path = net::sock::unix_peer_path(sock).unwrap_or(None);
    let sa = encoded_sockaddr_un(path.as_deref());
    let rv = copy_sockaddr_to_user(src, src_len, &sa);
    if rv < 0 { Err(rv) } else { Ok(()) }
}

/// AF_UNIX `recvfrom` with queue-owned payload-copy commit semantics. # C: O(payload + faults)
pub(crate) fn recvfrom(sock: &Arc<InetSocket>, fd: u64, dst: u64, len: usize, flags: u64, src: u64, src_len: u64) -> i64 {
    enum Target {
        Stream(Arc<net::UnixPair>, net::UnixEnd),
        Msg(Arc<net::UnixMsgPair>, net::UnixEnd),
        Dgram(Arc<net::UnixDgramQueue>),
    }
    let target = match &*sock.kind.lock() {
        SockKind::Unix(pair, end) => Target::Stream(pair.clone(), *end),
        SockKind::UnixMsgPair(pair, end) => Target::Msg(pair.clone(), *end),
        SockKind::UnixDgram(q) => Target::Dgram(q.clone()),
        _ => return err(Errno::Einval),
    };
    let _transfer = net::transfer_guard();
    let peek = flags & MSG_PEEK != 0;
    let passcred = sock.opts.passcred.load(Ordering::Acquire) != 0;
    let deadline = net::sock::compute_deadline_ns(sock.opts.rcvtimeo_ns.load(Ordering::Acquire));
    match target {
        Target::Stream(pair, end) => {
            if len == 0 { return 0; }
            let waitall = flags & MSG_WAITALL != 0;
            let mut total = 0usize;
            loop {
                let offset = if peek { total } else { 0 };
                match pair.read_stream_with_offset(end, len - total, peek, offset,
                    |data, _, _| dst.checked_add(total as u64).ok_or_else(|| err(Errno::Efault))
                        .and_then(|at| copy_one(at, data)).map(|n| (n, n))) {
                    Err(e) => {
                        if total == 0 { return e; }
                        if let Err(e) = copy_stream_source(sock, src, src_len) { return e; }
                        return total as i64;
                    }
                    Ok(Some((copied, files, _))) => {
                        total += copied;
                        let got_control = files.stops_waitall(passcred);
                        drop(files);
                        if !waitall || total == len || got_control {
                            if let Err(e) = copy_stream_source(sock, src, src_len) { return e; }
                            return total as i64;
                        }
                    }
                    Ok(None) => {
                        if pair.take_reset(end) {
                            if total != 0 {
                                if let Err(e) = copy_stream_source(sock, src, src_len) { return e; }
                                return total as i64;
                            }
                            return err(Errno::Econnreset);
                        }
                        if pair.is_eof(end) {
                            if total != 0 {
                                if let Err(e) = copy_stream_source(sock, src, src_len) { return e; }
                            }
                            return total as i64;
                        }
                    }
                }
                if let Err(e) = wait_after(sock, fd, flags, deadline, if peek { total } else { 0 }) {
                    if total != 0 {
                        if let Err(e) = copy_stream_source(sock, src, src_len) { return e; }
                        return total as i64;
                    }
                    return e;
                }
            }
        }
        Target::Msg(pair, end) => loop {
            match pair.recv_msg_with(end, len, peek, |payload, _, _, _| copy_one(dst, payload)) {
                Err(e) => return e,
                Ok(Some((copied, msg, full))) => {
                    drop(msg);
                    if src != 0 {
                        let sa = encoded_sockaddr_un(None);
                        let rv = copy_sockaddr_to_user(src, src_len, &sa);
                        if rv < 0 { return rv; }
                    }
                    return if flags & MSG_TRUNC != 0 { full as i64 } else { copied as i64 };
                }
                Ok(None) => {
                    if pair.take_reset(end) { return err(Errno::Econnreset); }
                    if pair.is_eof(end) { return 0; }
                }
            }
            if let Err(e) = wait(sock, fd, flags, deadline) { return e; }
        },
        Target::Dgram(q) => loop {
            match q.recv_with(peek, |msg, _, _| {
                let take = core::cmp::min(len, msg.payload.len());
                copy_one(dst, &msg.payload[..take])
            }) {
                Err(e) => return e,
                Ok(Some((copied, msg, sender))) => {
                    let full = msg.payload.len();
                    drop(msg);
                    if src != 0 {
                        let sa = encoded_sockaddr_un(sender.as_ref().map(|addr| addr.display.as_slice()));
                        let rv = copy_sockaddr_to_user(src, src_len, &sa);
                        if rv < 0 { return rv; }
                    }
                    return if flags & MSG_TRUNC != 0 { full as i64 } else { copied as i64 };
                }
                Ok(None) => {}
            }
            if let Err(e) = wait(sock, fd, flags, deadline) { return e; }
        },
    }
}
