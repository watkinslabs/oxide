// 047 recvmsg — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;
use net::sock::SockKind;
use crate::net_common::socket_from_fd;

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
        if matches!(*s.kind.lock(), SockKind::Unix(_, _))   { return crate::cmsg_parse::recvmsg_unix_stream(s, msgp); }
        // SOCK_DGRAM/SOCK_SEQPACKET socketpair: deliver SCM_CREDENTIALS
        // (systemd handoff-timestamp pair). Generic path below dropped creds.
        if matches!(*s.kind.lock(), SockKind::UnixMsgPair(_, _)) { return crate::cmsg_parse::recvmsg_unix_msgpair(s, fd, msgp, args); }
    }
    // SAFETY: msgp range validated; user page mapped under caller's AS.
    let (name, _namelen, iov, iovlen) = unsafe {
        let name      = core::ptr::read_volatile(msgp as *const u64);
        let namelen   = core::ptr::read_volatile((msgp + 8) as *const u32);
        let iov       = core::ptr::read_volatile((msgp + 16) as *const u64);
        let iovlen    = core::ptr::read_volatile((msgp + 24) as *const u64);
        (name, namelen, iov, iovlen)
    };
    if iovlen > 1024 { return -(Errno::Einval.as_i32() as i64); }
    let mut total: i64 = 0;
    for i in 0..iovlen {
        let iov_i = iov + i * 16;
        if iov_i >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: iov_i lies in user range; 8-byte aligned per Linux ABI; recvmsg path.
        let base = unsafe { core::ptr::read_volatile(iov_i as *const u64) };
        // SAFETY: iov_i + 8 still inside the iovec entry; len field is 8-byte aligned.
        let len  = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) };
        if len == 0 { continue; }
        let mut sa = *args;
        sa.a0 = fd; sa.a1 = base; sa.a2 = len; sa.a3 = 0; sa.a4 = name; sa.a5 = 0;
        let r = crate::net_recv::sys_recvfrom(&sa);
        if r < 0 { return if total > 0 { total } else { r }; }
        if r == 0 { break; }
        total += r;
        if (r as u64) < len { break; }  // short read -> stop
    }
    total
}
