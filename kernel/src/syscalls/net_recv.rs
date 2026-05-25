// F162: sys_recvfrom + the UDP-waitlist park path. Split out of
// net.rs to keep that file under the 1000-line cap (docs/08§7).
// All helper fns (socket_from_fd, file_is_nonblock, etc.) live in
// net.rs and are imported here.

use alloc::sync::Arc;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;
use net::sock::SockKind;
use crate::syscalls::net::{
    errno_from_neterr, file_is_nonblock, socket_from_fd, write_sockaddr_for_socket,
};
use crate::syscalls::net_trace::trace_enotsock_at;

/// `recvfrom(fd, buf, len, flags, src, srclen)` slot 45.
/// Blocking unless O_NONBLOCK or MSG_DONTWAIT; honors SO_RCVTIMEO.
/// # C: O(payload bytes)
pub fn sys_recvfrom(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    use core::sync::atomic::Ordering;
    let fd     = args.a0;
    let bufp   = args.a1;
    let len    = args.a2 as usize;
    let flags  = args.a3;
    let src_p  = args.a4;
    const MSG_DONTWAIT: u64 = 0x40;
    if crate::syscalls::netlink_fd::is_netlink(fd) {
        return crate::syscalls::netlink_fd::recvfrom(fd, bufp, len, src_p);
    }
    let sock: Arc<net::sock::InetSocket> = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"recvfrom"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    if bufp == 0 || bufp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let nonblock = (flags & MSG_DONTWAIT) != 0 || file_is_nonblock(fd);
    let timeo = sock.opts.rcvtimeo_ns.load(Ordering::Acquire);
    #[cfg(target_arch = "x86_64")]
    let now = || hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let now = || hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let deadline = if timeo > 0 { Some(now().saturating_add(timeo as u64)) } else { None };
    let rcv = loop {
        match net::sock::recvfrom(&sock, len) {
            Ok(r)  => break r,
            Err(net::NetError::Eagain) => {
                if nonblock { return -(Errno::Eagain.as_i32() as i64); }
                if let Some(dl) = deadline { if now() >= dl { return -(Errno::Eagain.as_i32() as i64); } }
                // F162: park on UDP queue's waitlist; tick_yield for AF_PACKET / AF_UNIX (separate PRs).
                let udp_q = if matches!(*sock.kind.lock(), SockKind::Udp) {
                    sock.local_port.lock().and_then(|p| net::sock::stack().udp_queue_arc(p))
                } else { None };
                let dl = deadline.unwrap_or(0);
                if let Some(q) = udp_q {
                    // F169: park with SO_RCVTIMEO deadline; timer
                    // scanner wakes us on expiry → next iter exits via
                    // the deadline check above.
                    // SAFETY: process ctx (sys_recvfrom UDP); runqueue installed; preempt-off owned by syscall stub; deliver_rx wakes after push; timer scanner wakes on deadline.
                    unsafe { q.waiters.park_with_deadline(dl); sched::live::schedule::schedule(); }
                } else if matches!(*sock.kind.lock(), SockKind::Packet { .. }) {
                    // F172: per-socket waitq for AF_PACKET; deliver_packet_rx wakes.
                    // SAFETY: process ctx (sys_recvfrom AF_PACKET); runqueue installed; preempt-off; deliver_packet_rx wakes after rx push; timer scanner wakes on deadline.
                    unsafe { sock.recv_waiters.park_with_deadline(dl); sched::live::schedule::schedule(); }
                } else {
                    // SAFETY: process ctx; preempt-off; tick_yield reschedules.
                    unsafe { sched::live::tick_yield(); }
                }
                continue;
            }
            Err(e) => return errno_from_neterr(e),
        }
    };
    let take = rcv.payload.len();
    // SAFETY: bufp+take validated < USER_VA_END; user page mapped under caller's AS.
    unsafe { core::ptr::copy_nonoverlapping(rcv.payload.as_ptr(), bufp as *mut u8, take); }
    if src_p != 0 {
        if matches!(*sock.kind.lock(), SockKind::Packet { .. }) {
            crate::syscalls::af_packet::write_sockaddr_ll(src_p, &sock, &rcv.payload);
        } else if let Some((ip, port)) = rcv.peer {
            write_sockaddr_for_socket(src_p, &sock, ip, port);
        } else if matches!(*sock.kind.lock(), SockKind::TcpConn(_)) {
            let (ip, port) = (*sock.peer.lock()).unwrap_or((net::Ipv4Addr::ANY, 0));
            write_sockaddr_for_socket(src_p, &sock, ip, port);
        }
    }
    take as i64
}
