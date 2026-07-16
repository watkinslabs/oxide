// F162: sys_recvfrom + the UDP-waitlist park path. Split out of
// net.rs to keep that file under the 1000-line cap (docs/08§7).
// Shared file/socket classification helpers live in net_common.rs.

use syscall::SyscallArgs;
use syscall::errno::Errno;
use net::sock::SockKind;
use net::uapi::{MSG_DONTWAIT, MSG_OOB, MSG_PEEK, MSG_TRUNC};
use crate::net_common::{
    errno_from_neterr, fd_file, socket_from_file, vsock_from_file,
};
use crate::net_sockaddr::{copy_sockaddr_to_user, encoded_sockaddr_for_socket, encoded_sockaddr_in6};
use crate::net_trace::trace_enotsock_at;

fn copy_payload(dst: u64, payload: &[u8]) -> Result<(usize, bool), i64> {
    // SAFETY: payload is kernel-owned; raw usercopy reports the uncopied suffix.
    let left = unsafe { uaccess::raw_copy_to_user(dst, payload.as_ptr(), payload.len()) };
    let copied = payload.len() - left;
    if copied != 0 || payload.is_empty() { Ok((copied, left != 0)) }
    else { Err(-(Errno::Efault.as_i32() as i64)) }
}

/// `recvfrom(fd, buf, len, flags, src, srclen)` slot 45.
/// Blocking unless O_NONBLOCK or MSG_DONTWAIT; honors SO_RCVTIMEO.
/// # C: O(payload bytes)
pub fn sys_recvfrom(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let fd     = args.a0;
    let bufp   = args.a1;
    let len    = core::cmp::min(args.a2 as usize, uaccess::MAX_RW_COUNT);
    let flags  = args.a3;
    let src_p  = args.a4;
    let src_len = args.a5;
    let file = match fd_file(fd) {
        Some(file) => file,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    if let Some(target) = crate::netlink_fd::from_file(file.clone()) {
        return crate::netlink_fd::recvfrom(&target, bufp, len, src_p, src_len, flags);
    }
    // D3.3: AF_VSOCK recv/recvfrom → OP_RW delivery via the socket
    // inode read path (STREAM, src not filled — single peer).
    if let Some(vsock) = vsock_from_file(file.clone()) {
        if !uaccess::access_ok(bufp, len) { return -(Errno::Efault.as_i32() as i64); }
        return match crate::recvmsg::vsock::recv_with_copy(&vsock, len, flags, |offset, bytes| {
            copy_payload(bufp + offset as u64, bytes).map(|(copied, _)| copied)
        }) {
            Ok(n) => n as i64,
            Err(e) => e,
        };
    }
    let sock = match socket_from_file(file) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"recvfrom"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    let file_nonblock = sock.is_nonblock();
    if flags & MSG_OOB != 0 && matches!(*sock.kind.lock(), SockKind::Raw4(_) | SockKind::Raw6(_)) {
        return -(Errno::Eopnotsupp.as_i32() as i64);
    }
    if !uaccess::access_ok(bufp, len) { return -(Errno::Efault.as_i32() as i64); }
    if matches!(*sock.kind.lock(), SockKind::Unix(_, _) | SockKind::UnixMsgPair(_, _) | SockKind::UnixDgram(_)) {
        return crate::unix_recv::recvfrom(&sock, file_nonblock, bufp, len, flags, src_p, src_len);
    }
    if matches!(*sock.kind.lock(), SockKind::TcpConn(_)) {
        let copied = match crate::recvmsg::inet::tcp_with_copy_pinned(&sock, len, flags, file_nonblock, |offset, bytes| {
            copy_payload(bufp + offset as u64, bytes).map(|(copied, _)| copied)
        }) {
            Ok(copied) => copied,
            Err(e) => return e,
        };
        if src_p != 0 {
            let (ip, port) = (*sock.peer.lock()).unwrap_or((net::Ipv4Addr::ANY, 0));
            let sa = encoded_sockaddr_for_socket(&sock, ip, port);
            let rv = copy_sockaddr_to_user(src_p, src_len, &sa);
            if rv < 0 { return rv; }
        }
        return copied as i64;
    }
    let nonblock = (flags & MSG_DONTWAIT) != 0 || file_nonblock;
    let timeo = sock.opts.rcvtimeo_ns.load(Ordering::Acquire);
    let deadline = net::sock::compute_deadline_ns(timeo);
    let opts = net::sock::RecvOptions { peek: (flags & MSG_PEEK) != 0 };
    let rcv = if nonblock {
        match net::sock::recvfrom_opts(&sock, len, opts) {
            Ok(r) => r,
            Err(e) => return errno_from_neterr(e),
        }
    } else {
        match net::sock_recv::recv_blocking(&sock, len, opts, deadline) {
            Ok(r) => r,
            Err(e) => return errno_from_neterr(e),
        }
    };
    let (take, faulted) = match copy_payload(bufp, &rcv.payload) { Ok(result) => result, Err(e) => return e };
    if src_p != 0 {
        if matches!(*sock.kind.lock(), SockKind::Packet { .. }) {
            let Some(meta) = rcv.packet else { return -(Errno::Einval.as_i32() as i64); };
            let rv = crate::af_packet::copy_sockaddr_ll_to_user(src_p, src_len, meta.addr);
            if rv < 0 { return rv; }
        } else if let Some((ip6, port, scope_id)) = rcv.peer6 {
            let port = if matches!(*sock.kind.lock(), SockKind::Raw6(_)) { 0 } else { port };
            let sa = encoded_sockaddr_in6(ip6.0, port.to_be(), scope_id);
            let rv = copy_sockaddr_to_user(src_p, src_len, &sa);
            if rv < 0 { return rv; }
        } else if let Some((ip, port)) = rcv.peer {
            let port = if matches!(*sock.kind.lock(), SockKind::Raw4(_)) { 0 } else { port };
            let sa = encoded_sockaddr_for_socket(&sock, ip, port);
            let rv = copy_sockaddr_to_user(src_p, src_len, &sa);
            if rv < 0 { return rv; }
        } else if matches!(*sock.kind.lock(), SockKind::TcpConn(_)) {
            let (ip, port) = (*sock.peer.lock()).unwrap_or((net::Ipv4Addr::ANY, 0));
            let sa = encoded_sockaddr_for_socket(&sock, ip, port);
            let rv = copy_sockaddr_to_user(src_p, src_len, &sa);
            if rv < 0 { return rv; }
        }
    }
    if !faulted && (flags & MSG_TRUNC) != 0 { rcv.full_len as i64 } else { take as i64 }
}
