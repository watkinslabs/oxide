// 047 recvmsg — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;
use net::sock::SockKind;
use crate::net_common::{errno_from_neterr, file_is_nonblock, socket_from_fd};
use crate::net_sockaddr::{write_sockaddr_for_socket, write_sockaddr_in6_peer};

/// `recvmsg(fd, msghdr, flags)` slot 47. # C: O(iov)
pub fn sys_recvmsg(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let msgp   = args.a1;
    let _flags = args.a2;
    // netlink: real netlink_recvmsg (fills the returned msghdr) — explicit,
    // not relying on the recvfrom fall-through which left msghdr unset.
    // MSG_PEEK (a2) must be honoured: sd-netlink peeks to size its buffer
    // before the consuming read.
    if crate::netlink_fd::is_netlink(fd) {
        return crate::netlink_fd::recvmsg(fd, msgp, args.a2 as u32);
    }
    if msgp == 0 || msgp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    // F122/F213: route to DGRAM/STREAM cmsg handlers (lock dropped before recurse).
    let sock = socket_from_fd(fd);
    if let Some(s) = &sock {
        if matches!(*s.kind.lock(), SockKind::UnixDgram(_)) { return net::unix_cmsg::recvmsg_unix_dgram(s, msgp); }
        if matches!(*s.kind.lock(), SockKind::Unix(_, _))   {
            // MSG_DONTWAIT (0x40) or O_NONBLOCK on the fd → non-blocking recvmsg:
            // return EAGAIN on an empty ring instead of spinning. dbus-broker
            // drains edge-triggered epoll fds until EAGAIN; a spinning recvmsg
            // never yields EAGAIN, stalling its read loop → it tears the
            // connection down ("Connection terminated" on systemd's AddMatch).
            let nonblock = (args.a2 & 0x40) != 0 || crate::net_common::file_is_nonblock(fd);
            return crate::cmsg_parse::recvmsg_unix_stream(s, msgp, nonblock);
        }
        // SOCK_DGRAM/SOCK_SEQPACKET socketpair: deliver SCM_CREDENTIALS
        // (systemd handoff-timestamp pair). Generic path below dropped creds.
        if matches!(*s.kind.lock(), SockKind::UnixMsgPair(_, _)) { return crate::cmsg_parse::recvmsg_unix_msgpair(s, fd, msgp, args); }
    }
    // SAFETY: msgp range validated; user page mapped under caller's AS.
    let (name, _namelen, iov, iovlen, control, controllen) = unsafe {
        let name      = core::ptr::read_volatile(msgp as *const u64);
        let namelen   = core::ptr::read_volatile((msgp + 8) as *const u32);
        let iov       = core::ptr::read_volatile((msgp + 16) as *const u64);
        let iovlen    = core::ptr::read_volatile((msgp + 24) as *const u64);
        let control   = core::ptr::read_volatile((msgp + 32) as *const u64);
        let controllen= core::ptr::read_volatile((msgp + 40) as *const u64);
        (name, namelen, iov, iovlen, control, controllen)
    };
    if iovlen > 1024 { return -(Errno::Einval.as_i32() as i64); }
    let Some(sock) = sock else {
        let mut total: i64 = 0;
        for i in 0..iovlen {
            let iov_i = iov + i * 16;
            if iov_i >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
            // SAFETY: iovec header is in validated user VA; volatile read copies metadata only.
            let base = unsafe { core::ptr::read_volatile(iov_i as *const u64) };
            // SAFETY: iovec length slot is adjacent to the validated iovec header.
            let len  = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) };
            if len == 0 { continue; }
            let mut sa = *args;
            sa.a0 = fd; sa.a1 = base; sa.a2 = len; sa.a3 = 0; sa.a4 = name; sa.a5 = 0;
            let r = crate::net_recv::sys_recvfrom(&sa);
            if r < 0 { return if total > 0 { total } else { r }; }
            if r == 0 { break; }
            total += r;
            if (r as u64) < len { break; }
        }
        return total;
    };
    let mut cap = 0usize;
    for i in 0..iovlen {
        let iov_i = iov + i * 16;
        if iov_i >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: iovec header is in validated user VA; only length metadata is read.
        let len  = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) };
        cap = cap.saturating_add(len as usize);
    }
    let flags = args.a2;
    let rcv = recvmsg_blocking(fd, &sock, cap, flags);
    let rcv = match rcv { Ok(r) => r, Err(e) => return e };
    let mut off = 0usize;
    for i in 0..iovlen {
        if off >= rcv.payload.len() { break; }
        let iov_i = iov + i * 16;
        // SAFETY: iovec header address was bounded by iovlen and validated before use.
        let base = unsafe { core::ptr::read_volatile(iov_i as *const u64) };
        // SAFETY: iovec length slot is adjacent to the validated iovec header.
        let len  = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) };
        if len == 0 { continue; }
        if base == 0 || base.saturating_add(len) > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        let n = core::cmp::min(len as usize, rcv.payload.len() - off);
        // SAFETY: destination user buffer range is validated and source is an owned Vec.
        unsafe { core::ptr::copy_nonoverlapping(rcv.payload[off..].as_ptr(), base as *mut u8, n); }
        off += n;
    }
    if name != 0 {
        if let Some((ip6, port)) = rcv.peer6 {
            write_sockaddr_in6_peer(name, ip6, port);
        } else if let Some((ip, port)) = rcv.peer {
            write_sockaddr_for_socket(name, &sock, ip, port);
        } else if matches!(*sock.kind.lock(), SockKind::TcpConn(_)) {
            let (ip, port) = (*sock.peer.lock()).unwrap_or((net::Ipv4Addr::ANY, 0));
            write_sockaddr_for_socket(name, &sock, ip, port);
        }
    }
    let mut msg_flags: u32 = if rcv.full_len > off { MSG_TRUNC as u32 } else { 0 };
    let ctrl = write_ip_pktinfo(&sock, &rcv, control, controllen, &mut msg_flags);
    // SAFETY: msghdr pointer was validated and these fields are fixed offsets in msghdr.
    unsafe {
        core::ptr::write_volatile((msgp + 40) as *mut u64, ctrl);
        core::ptr::write_volatile((msgp + 48) as *mut u32, msg_flags);
    }
    if (flags & MSG_TRUNC) != 0 { rcv.full_len as i64 } else { off as i64 }
}

const MSG_PEEK: u64 = 0x02;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;

fn recvmsg_blocking(
    fd: u64,
    sock: &alloc::sync::Arc<net::sock::InetSocket>,
    len: usize,
    flags: u64,
) -> Result<net::sock::Received, i64> {
    use core::sync::atomic::Ordering;
    use hal::TimerOps;
    let nonblock = (flags & MSG_DONTWAIT) != 0 || file_is_nonblock(fd);
    let timeo = sock.opts.rcvtimeo_ns.load(Ordering::Acquire);
    #[cfg(target_arch = "x86_64")]
    let now = || hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let now = || hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let deadline = if timeo > 0 { Some(now().saturating_add(timeo as u64)) } else { None };
    loop {
        if matches!(*sock.kind.lock(), SockKind::Udp)
            && sock.family.load(Ordering::Acquire) != net::sock::AF_INET6
        {
            if let Some(p) = *sock.local_port.lock() {
                if let Some(q) = net::sock::stack().udp_queue_arc(p) {
                    let e = q.take_error();
                    if e != 0 { return Err(-(e as i64)); }
                }
            }
        }
        match net::sock::recvfrom_opts(sock, len, net::sock::RecvOptions { peek: (flags & MSG_PEEK) != 0 }) {
            Ok(r) => return Ok(r),
            Err(net::NetError::Eagain) => {
                if nonblock { return Err(-(Errno::Eagain.as_i32() as i64)); }
                if let Some(dl) = deadline { if now() >= dl { return Err(-(Errno::Eagain.as_i32() as i64)); } }
                let dl = deadline.unwrap_or(0);
                let is_udp = matches!(*sock.kind.lock(), SockKind::Udp);
                let is_v6 = sock.family.load(Ordering::Acquire) == net::sock::AF_INET6;
                let v6_q = if is_udp && is_v6 { sock.local_port.lock().and_then(|p| net::sock::stack().udp6_queue_arc(p)) } else { None };
                let udp_q = if is_udp && !is_v6 { sock.local_port.lock().and_then(|p| net::sock::stack().udp_queue_arc(p)) } else { None };
                #[cfg(target_os = "oxide-kernel")]
                if let Some(q) = v6_q {
                    // SAFETY: wait list parking is scheduler-local and immediately followed by schedule.
                    unsafe { q.waiters.park_with_deadline(dl); sched::live::schedule::schedule(); }
                } else if let Some(q) = udp_q {
                    // SAFETY: wait list parking is scheduler-local and immediately followed by schedule.
                    unsafe { q.waiters.park_with_deadline(dl); sched::live::schedule::schedule(); }
                } else {
                    // SAFETY: cooperative yield is scheduler-local on oxide-kernel targets.
                    unsafe { sched::live::tick_yield(); }
                }
                #[cfg(not(target_os = "oxide-kernel"))]
                return Err(-(Errno::Eagain.as_i32() as i64));
            }
            Err(e) => return Err(errno_from_neterr(e)),
        }
    }
}

fn write_ip_pktinfo(
    sock: &alloc::sync::Arc<net::sock::InetSocket>,
    rcv: &net::sock::Received,
    control: u64,
    controllen: u64,
    msg_flags: &mut u32,
) -> u64 {
    use core::sync::atomic::Ordering;
    const IPPROTO_IP: i32 = 0;
    const IP_PKTINFO: i32 = 8;
    const MSG_CTRUNC: u32 = 0x08;
    if sock.opts.ip_pktinfo.load(Ordering::Acquire) == 0 { return 0; }
    let Some((dst, iface)) = rcv.pktinfo else { return 0; };
    if control == 0 || controllen < 28 || control.saturating_add(28) > USER_VA_END {
        *msg_flags |= MSG_CTRUNC;
        return 0;
    }
    // SAFETY: control buffer has space for cmsghdr plus in_pktinfo and is user VA bounded.
    unsafe {
        core::ptr::write_volatile(control as *mut u64, 28);
        core::ptr::write_volatile((control + 8) as *mut i32, IPPROTO_IP);
        core::ptr::write_volatile((control + 12) as *mut i32, IP_PKTINFO);
        core::ptr::write_volatile((control + 16) as *mut i32, iface.raw() as i32);
        let oct = dst.octets();
        core::ptr::copy_nonoverlapping(oct.as_ptr(), (control + 20) as *mut u8, 4);
        core::ptr::copy_nonoverlapping(oct.as_ptr(), (control + 24) as *mut u8, 4);
    }
    32
}
