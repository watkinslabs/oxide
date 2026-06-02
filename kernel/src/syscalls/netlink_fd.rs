// F132: netlink-fd shims for socket-shaped syscalls. The socket
// syscall layer otherwise routes through InetSocket only — netlink
// inodes (tag `NLSK` in the high bits of `ino()`) need special
// handling for bind / getsockname / setsockopt / sendto / recvfrom.
// Split out of net.rs to keep that file under the 1000-line cap.
//
// All helpers return Some(rv) when the fd is a netlink socket and
// they've handled the call; None to fall through to the InetSocket
// path.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use hal::USER_VA_END;
use syscall::errno::Errno;

const NL_TAG: u64 = 0x4E4C_534B_0000_0000;

/// Look up the File behind `fd` from the current task's table.
fn fd_file_local(fd: u64) -> Option<Arc<vfs::File>> {
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    fdt.get(fd as i32).ok()
}

/// True if `fd` resolves to a NetlinkSocket inode.
/// # C: O(1) — fd-table lookup + ino tag check.
pub fn is_netlink(fd: u64) -> bool {
    fd_file_local(fd)
        .map(|f| (f.inode().ino() & 0xFFFF_FFFF_0000_0000) == NL_TAG)
        .unwrap_or(false)
}

/// `bind(fd, sockaddr_nl, ...)` for netlink. dhcpcd's if_linksocket
/// passes nl_pid + nl_groups; v1 ignores them (no multicast wiring),
/// just returns 0.
/// # C: O(1)
pub fn bind() -> i64 { 0 }

/// `setsockopt(fd, ...)` for netlink. Tuning knobs (NETLINK_BROADCAST_ERROR,
/// NETLINK_NO_ENOBUFS) accepted as no-op.
/// # C: O(1)
pub fn setsockopt() -> i64 { 0 }

/// `getsockopt(fd, level, optname, optval, optlen)` for netlink.
/// sd_netlink_open REQUIRES getsockopt(SOL_SOCKET, SO_PROTOCOL) — it stores
/// the result as the socket's protocol. SO_TYPE → SOCK_RAW. The
/// NETLINK_LIST_MEMBERSHIPS size-query passes optval=NULL (report 0 groups).
/// # C: O(1)
pub fn getsockopt(_fd: u64, level: u64, optname: u64, optval: u64, optlen_p: u64) -> i64 {
    const SOL_SOCKET: u64 = 1;
    const SO_TYPE: u64 = 3;
    const SO_PROTOCOL: u64 = 38;
    const SOL_NETLINK: u64 = 270;
    const NETLINK_LIST_MEMBERSHIPS: u64 = 9;
    if level == SOL_NETLINK && optname == NETLINK_LIST_MEMBERSHIPS {
        if optlen_p != 0 && optlen_p < USER_VA_END {
            // SAFETY: optlen_p validated < USER_VA_END; 4-byte store at CPL=0.
            unsafe { core::ptr::write_volatile(optlen_p as *mut u32, 0); }
        }
        return 0;
    }
    // DEFERRED (netlink rtnl async completion): our rtnl delivers acks
    // correctly (timing-proven: SETLINK ack arrives 2 ms after send) but
    // sd_netlink's `process_reply` does not match the SETLINK reply to its
    // async callback — so `loopback_setup` (and every other sd_netlink
    // user, e.g. the systemd manager rtnl) blocks to its timeout and the
    // boot wedges. Until that reply-matching is root-caused (needs
    // gdb-on-systemd, not kernel-side inspection), report SO_PROTOCOL as
    // unsupported: `sd_netlink_open` then fails gracefully and systemd
    // skips rtnl entirely (the Linux-defined degradation — exactly what
    // pre-netlink boots did), reaching login. The real-state netlink
    // infrastructure stays in place for that follow-up. See state.md.
    if level == SOL_SOCKET && optname == SO_PROTOCOL {
        return -(Errno::Enoprotoopt.as_i32() as i64);
    }
    if optval == 0 || optval >= USER_VA_END || optlen_p == 0 || optlen_p >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let val: u32 = if level == SOL_SOCKET && optname == SO_TYPE { 3 /* SOCK_RAW */ }
                   else { 0 };
    // SAFETY: optval+optlen_p validated < USER_VA_END; 4-byte stores at CPL=0.
    unsafe {
        core::ptr::write_volatile(optval as *mut u32, val);
        core::ptr::write_volatile(optlen_p as *mut u32, 4);
    }
    0
}

/// `read(fd, buf, len)` for netlink — same as recvfrom with no peer addr.
/// Linux lets you read() a netlink socket. # C: O(len)
pub fn read(fd: u64, bufp: u64, len: usize) -> i64 {
    recvfrom(fd, bufp, len, 0)
}

/// `recvmsg(fd, msghdr, flags)` for netlink. Copies ONE reply datagram
/// into the msghdr's iovec(s) and fills the RETURNED msghdr fields —
/// msg_namelen (sockaddr_nl, 12), msg_controllen=0, msg_flags (MSG_TRUNC
/// when the datagram exceeds the iov space).
///
/// MSG_PEEK (libsystemd's sd-netlink sizes its buffer with
/// `recvmsg(MSG_PEEK|MSG_TRUNC)` first) leaves the datagram QUEUED so the
/// following consuming read still sees it — without this, the peek ate
/// the ack, the real read got nothing, and sd_netlink timed out waiting
/// ("Failed to bring loopback interface up: Operation timed out").
/// Per Linux netlink_recvmsg, the returned length is the FULL datagram
/// length when MSG_TRUNC is requested (so the caller sizes correctly),
/// else the number of bytes copied. # C: O(iov + len)
pub fn recvmsg(fd: u64, msgp: u64, flags: u32) -> i64 {
    const MSG_PEEK:  u32 = 0x2;
    const MSG_TRUNC: u32 = 0x20;
    if msgp == 0 || msgp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    // struct msghdr: name@0, namelen@8, iov@16, iovlen@24, control@32,
    // controllen@40, flags@48 (x86_64/aarch64 LP64 layout).
    // SAFETY: msgp validated < USER_VA_END; LP64 msghdr field offsets.
    let (name, iov, iovlen) = unsafe {
        (core::ptr::read_volatile(msgp as *const u64),
         core::ptr::read_volatile((msgp + 16) as *const u64),
         core::ptr::read_volatile((msgp + 24) as *const u64))
    };
    if iovlen > 1024 { return -(Errno::Einval.as_i32() as i64); }
    let file = match fd_file_local(fd) { Some(f) => f, None => return -(Errno::Ebadf.as_i32() as i64) };
    // Pull the datagram via PEEK (leave queued) or consume, per MSG_PEEK.
    let sock = match file.inode().as_any().and_then(|a| a.downcast_ref::<::netlink::NetlinkSocket>()) {
        Some(s) => s, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dgram = if (flags & MSG_PEEK) != 0 { sock.peek_front() } else { sock.dequeue() };
    let dgram = match dgram { Some(d) if !d.is_empty() => d, _ => return -(Errno::Eagain.as_i32() as i64) };

    // Scatter the one datagram across the iovecs (sd-netlink uses a single
    // buffer; tools may use several). Track copied vs total datagram len.
    let mut copied = 0usize;
    for i in 0..iovlen {
        if copied >= dgram.len() { break; }
        let iov_i = iov + i * 16;
        if iov_i == 0 || iov_i >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: iov_i validated in user range; iovec is {base@0,len@8}
        // per the LP64 ABI; two aligned 8-byte reads through caller AS.
        let (base, blen) = unsafe {
            (core::ptr::read_volatile(iov_i as *const u64),
             core::ptr::read_volatile((iov_i + 8) as *const u64) as usize)
        };
        if blen == 0 { continue; }
        if base == 0 || base.saturating_add(blen as u64) >= USER_VA_END {
            return -(Errno::Efault.as_i32() as i64);
        }
        let take = core::cmp::min(blen, dgram.len() - copied);
        // SAFETY: base..base+take validated < USER_VA_END (take ≤ blen); CPL=0 writes.
        let dst = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, take) };
        dst.copy_from_slice(&dgram[copied..copied + take]);
        copied += take;
    }
    let truncated = copied < dgram.len();

    // Fill the returned msghdr: sockaddr_nl source (kernel = pid 0),
    // namelen=12, controllen=0, msg_flags=MSG_TRUNC iff truncated.
    if name != 0 && name < USER_VA_END {
        // SAFETY: name validated < USER_VA_END; sockaddr_nl is 12 bytes.
        unsafe {
            core::ptr::write_volatile( name        as *mut u16, 16); // AF_NETLINK
            core::ptr::write_volatile((name +  2)  as *mut u16, 0);
            core::ptr::write_volatile((name +  4)  as *mut u32, 0);  // nl_pid = kernel
            core::ptr::write_volatile((name +  8)  as *mut u32, 0);  // nl_groups
        }
    }
    // SAFETY: msgp validated; write back namelen/controllen/flags.
    unsafe {
        core::ptr::write_volatile((msgp +  8) as *mut u32, if name != 0 { 12 } else { 0 });
        core::ptr::write_volatile((msgp + 40) as *mut u64, 0);
        core::ptr::write_volatile((msgp + 48) as *mut u32, if truncated { MSG_TRUNC } else { 0 });
    }
    // MSG_TRUNC semantics: report the real datagram length so the caller
    // can size its buffer; otherwise report bytes actually copied.
    if (flags & MSG_TRUNC) != 0 { dgram.len() as i64 } else { copied as i64 }
}

/// `getsockname(fd, addr, addrlen)` for netlink. Writes a sockaddr_nl
/// with `nl_pid = current.tid` (the bind-implied pid musl + dhcpcd
/// expect to see back).
/// # C: O(1)
pub fn getsockname(addr_p: u64) -> i64 {
    if addr_p == 0 || addr_p >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let pid = sched::live::current().map(|c| c.tid).unwrap_or(1);
    // SAFETY: addr_p validated < USER_VA_END; sockaddr_nl is 12 bytes (u16 family, u16 pad, u32 pid, u32 groups).
    unsafe {
        core::ptr::write_volatile( addr_p        as *mut u16, 16); // AF_NETLINK
        core::ptr::write_volatile((addr_p +  2)  as *mut u16, 0);
        core::ptr::write_volatile((addr_p +  4)  as *mut u32, pid as u32);
        core::ptr::write_volatile((addr_p +  8)  as *mut u32, 0);
    }
    0
}

/// `sendto(fd, buf, len, ...)` for netlink — routes the message
/// through `NetlinkSocket::write`, which parses the netlink header
/// and enqueues a reply for the matching `recvfrom`.
/// # SAFETY: caller asserts bufp..bufp+len ⊂ USER_VA_END.
/// # C: O(len) — single copy into NetlinkSocket::write.
pub fn sendto(fd: u64, bufp: u64, len: usize) -> i64 {
    let file = match fd_file_local(fd) { Some(f) => f, None => return -(Errno::Ebadf.as_i32() as i64) };
    if bufp == 0 || bufp.saturating_add(len as u64) >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: caller's range check + the bounds-add above.
    let buf = unsafe { core::slice::from_raw_parts(bufp as *const u8, len) };
    match file.inode().write(0, buf) {
        Ok(n) => n as i64,
        Err(_) => -(Errno::Eio.as_i32() as i64),
    }
}

/// `recvfrom(fd, buf, len, flags, src, ...)` for netlink — pops one
/// reply via `NetlinkSocket::read`. Returns EAGAIN if the queue is
/// empty so callers can poll/retry without spinning the kernel.
/// # SAFETY: caller asserts bufp..bufp+len ⊂ USER_VA_END; src_p
/// validated if non-zero.
/// # C: O(len) — single copy out of NetlinkSocket::read.
pub fn recvfrom(fd: u64, bufp: u64, len: usize, src_p: u64) -> i64 {
    let file = match fd_file_local(fd) { Some(f) => f, None => return -(Errno::Ebadf.as_i32() as i64) };
    if bufp == 0 || bufp.saturating_add(len as u64) >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: bufp range validated; CPL=0 writes through caller's AS.
    let buf = unsafe { core::slice::from_raw_parts_mut(bufp as *mut u8, len) };
    let n = match file.inode().read(0, buf) {
        Ok(n) => n,
        Err(_) => return -(Errno::Eio.as_i32() as i64),
    };
    if src_p != 0 && src_p < USER_VA_END {
        // SAFETY: src_p validated < USER_VA_END; sockaddr_nl is 12 bytes.
        unsafe {
            core::ptr::write_volatile( src_p        as *mut u16, 16);
            core::ptr::write_volatile((src_p +  2)  as *mut u16, 0);
            core::ptr::write_volatile((src_p +  4)  as *mut u32, 0);  // kernel = pid 0
            core::ptr::write_volatile((src_p +  8)  as *mut u32, 0);
        }
    }
    if n == 0 { -(Errno::Eagain.as_i32() as i64) } else { n as i64 }
}
