// 046 sendmsg — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

/// `sendmsg(fd, msghdr, flags)` slot 46. F189 honors SCM_RIGHTS
/// for AF_UNIX DGRAM/STREAM/message-pair sockets (captures Arc<File>
/// from current fd_table; receiver dup's on recvmsg).
/// # C: O(iov + nfds)
pub fn sys_sendmsg(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let msgp   = args.a1;
    let flags  = args.a2;
    if msgp == 0 || msgp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    // SAFETY: msgp range validated; user page mapped under caller's AS.
    let (name, namelen, iov, iovlen, control, controllen) = unsafe {
        let name      = core::ptr::read_volatile(msgp as *const u64);
        let namelen   = core::ptr::read_volatile((msgp + 8) as *const u32);
        let iov       = core::ptr::read_volatile((msgp + 16) as *const u64);
        let iovlen    = core::ptr::read_volatile((msgp + 24) as *const u64);
        let control   = core::ptr::read_volatile((msgp + 32) as *const u64);
        let controllen= core::ptr::read_volatile((msgp + 40) as *const u64);
        (name, namelen, iov, iovlen, control, controllen)
    };
    if crate::netlink_fd::is_netlink(fd) {
        return crate::netlink_fd::sendmsg(fd, name, namelen as u64, iov, iovlen);
    }
    // F189: SCM_RIGHTS short-circuit for AF_UNIX sockets.
    if let Some(r) = crate::cmsg_parse::try_sendmsg_with_fds(
        fd, name, namelen as u64, iov, iovlen, control, controllen, flags,
    ) { return r; }
    if iovlen > 1024 { return -(Errno::Einval.as_i32() as i64); }
    // Netlink is DATAGRAM: a sendmsg with N iovecs is ONE datagram = the
    // concatenation of all iovecs, NOT N separate datagrams. systemd's
    // sd-device-monitor sends each cooked uevent as a `libudev` header iovec +
    // a properties iovec; sending them as two datagrams gave logind a
    // header-only then a properties-only message it can't parse (card0 add lost
    // → seat0 never CanGraphical → no greeter). Coalesce, then send once.
    if crate::netlink_fd::is_netlink(fd) {
        let mut msg: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        for i in 0..iovlen {
            let iov_i = iov + i * 16;
            if iov_i >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
            // SAFETY: iov_i in user range; {base@0,len@8} per LP64 iovec ABI.
            let base = unsafe { core::ptr::read_volatile(iov_i as *const u64) };
            let len  = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) } as usize;
            if len == 0 { continue; }
            if base == 0 || base.saturating_add(len as u64) >= USER_VA_END {
                return -(Errno::Efault.as_i32() as i64);
            }
            // SAFETY: base..base+len validated < USER_VA_END; CPL=0 read of caller AS.
            let src = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
            msg.extend_from_slice(src);
        }
        return crate::netlink_fd::send_coalesced(fd, &msg, name, namelen as u64);
    }
    // Linux `sendmsg(2)`: the iovec array forms ONE message — the datagram is the
    // concatenation of every iovec. For a message-boundary socket (inet UDP or
    // AF_UNIX SOCK_DGRAM / SOCK_SEQPACKET), emitting one datagram per iovec (the
    // stream loop below) fragments a single message into N. systemd userdb sends
    // a header iovec + body iovec over a message socket, so the reader saw only
    // iovec[0] ("Received too short user lookup message, ignoring"). Coalesce the
    // iovecs into one buffer and send once. Stream sockets (TCP / AF_UNIX STREAM)
    // fall through — the resulting byte stream is identical either way.
    if let Some(sock) = crate::net_common::socket_from_fd(fd) {
        let msg_boundary = matches!(
            &*sock.kind.lock(),
            net::sock::SockKind::Udp
                | net::sock::SockKind::UnixDgram(_)
                | net::sock::SockKind::UnixMsgPair(_, _)
        );
        if msg_boundary {
            let mut msg: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
            for i in 0..iovlen {
                let iov_i = iov + i * 16;
                if iov_i >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
                // SAFETY: iov_i in user range; {base@0,len@8} per LP64 iovec ABI.
                let base = unsafe { core::ptr::read_volatile(iov_i as *const u64) };
                let len  = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) } as usize;
                if len == 0 { continue; }
                if base == 0 || base.saturating_add(len as u64) >= USER_VA_END {
                    return -(Errno::Efault.as_i32() as i64);
                }
                // SAFETY: base..base+len validated < USER_VA_END; CPL=0 read of caller AS.
                let src = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
                msg.extend_from_slice(src);
            }
            let dest = match crate::s044_sendto::parse_send_dest(&sock, name, namelen as u64) {
                Ok((d, _)) => d,
                Err(e) => return e,
            };
            return crate::s044_sendto::send_over_socket(&sock, &msg, dest, flags, fd);
        }
    }
    let mut total: i64 = 0;
    for i in 0..iovlen {
        let iov_i = iov + i * 16;
        if iov_i >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: iov_i lies in user range; 8-byte aligned per Linux ABI; sendmsg path.
        let base = unsafe { core::ptr::read_volatile(iov_i as *const u64) };
        // SAFETY: iov_i + 8 still inside the iovec entry; len field is 8-byte aligned.
        let len  = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) };
        if len == 0 { continue; }
        let mut sa = *args;
        sa.a0 = fd; sa.a1 = base; sa.a2 = len;
        sa.a3 = if total > 0 { flags | net::uapi::MSG_NOSIGNAL } else { flags };
        sa.a4 = name; sa.a5 = namelen as u64;
        let r = crate::s044_sendto::sys_sendto(&sa);
        if r < 0 { return if total > 0 { total } else { r }; }
        total += r;
    }
    total
}
