// F162: sys_recvfrom + the UDP-waitlist park path. Split out of
// net.rs to keep that file under the 1000-line cap (docs/08§7).
// All helper fns (socket_from_fd, file_is_nonblock, etc.) live in
// net.rs and are imported here.

use alloc::sync::Arc;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;
use net::sock::SockKind;
use net::uapi::{MSG_DONTWAIT, MSG_PEEK, MSG_TRUNC};
use crate::net_common::{
    errno_from_neterr, file_is_nonblock, socket_from_fd,
};
use crate::net_sockaddr::{write_sockaddr_for_socket, write_sockaddr_in6_peer};
use crate::net_trace::trace_enotsock_at;

/// `recvfrom(fd, buf, len, flags, src, srclen)` slot 45.
/// Blocking unless O_NONBLOCK or MSG_DONTWAIT; honors SO_RCVTIMEO.
/// # C: O(payload bytes)
pub fn sys_recvfrom(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let fd     = args.a0;
    let bufp   = args.a1;
    let len    = args.a2 as usize;
    let flags  = args.a3;
    let src_p  = args.a4;
    if crate::netlink_fd::is_netlink(fd) {
        return crate::netlink_fd::recvfrom(fd, bufp, len, src_p, flags);
    }
    // D3.3: AF_VSOCK recv/recvfrom → OP_RW delivery via the socket
    // inode read path (STREAM, src not filled — single peer).
    if crate::net_common::vsock_from_fd(fd).is_some() {
        if bufp == 0 || bufp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        let nb = (flags & MSG_DONTWAIT) != 0 || file_is_nonblock(fd);
        // SAFETY: bufp validated; user page mapped under caller's AS.
        let dst = unsafe { core::slice::from_raw_parts_mut(bufp as *mut u8, len) };
        // Post-KEYSTONE: the data path is the inode's `i_fop` (vsock FileOps).
        let file = match crate::net_common::fd_file(fd) {
            Some(f) => f, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let r = if nb { file.inode().read_nonblock(0, dst) } else { file.inode().read(0, dst) };
        return match r { Ok(n) => n as i64, Err(e) => -(e as i64) };
    }
    let sock: Arc<net::sock::InetSocket> = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"recvfrom"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    if bufp == 0 || bufp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let nonblock = (flags & MSG_DONTWAIT) != 0 || file_is_nonblock(fd);
    let timeo = sock.opts.rcvtimeo_ns.load(Ordering::Acquire);
    let deadline = net::sock::compute_deadline_ns(timeo);
    let opts = net::sock::RecvOptions { peek: (flags & MSG_PEEK) != 0 };
    let rcv = if nonblock {
        match net::sock::recvfrom_opts(&sock, len, opts) {
            Ok(r) => r,
            Err(e) => return errno_from_neterr(e),
        }
    } else {
        let is_v6 = sock.family.load(Ordering::Acquire) == net::sock::AF_INET6;
        if matches!(*sock.kind.lock(), SockKind::Udp) && !is_v6 {
            if let Some(p) = *sock.local_port.lock() {
                if let Some(q) = net::sock::stack().udp_queue_arc(p) {
                    let e = q.take_error();
                    if e != 0 { return -(e as i64); }
                }
            }
        }
        match net::sock_recv::recv_blocking(&sock, len, opts, deadline) {
            Ok(r) => r,
            Err(e) => return errno_from_neterr(e),
        }
    };
    let take = rcv.payload.len();
    // SAFETY: bufp+take validated < USER_VA_END; user page mapped under caller's AS.
    unsafe { core::ptr::copy_nonoverlapping(rcv.payload.as_ptr(), bufp as *mut u8, take); }
    if src_p != 0 {
        if matches!(*sock.kind.lock(), SockKind::Packet { .. }) {
            crate::af_packet::write_sockaddr_ll(src_p, &sock, &rcv.payload);
        } else if let Some((ip6, port)) = rcv.peer6 {
            write_sockaddr_in6_peer(src_p, ip6, port);
        } else if let Some((ip, port)) = rcv.peer {
            write_sockaddr_for_socket(src_p, &sock, ip, port);
        } else if matches!(*sock.kind.lock(), SockKind::TcpConn(_)) {
            let (ip, port) = (*sock.peer.lock()).unwrap_or((net::Ipv4Addr::ANY, 0));
            write_sockaddr_for_socket(src_p, &sock, ip, port);
        }
    }
    if (flags & MSG_TRUNC) != 0 { rcv.full_len as i64 } else { take as i64 }
}
