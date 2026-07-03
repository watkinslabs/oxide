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

use alloc::vec::Vec;
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

/// Resolve `fd` to its concrete `NetlinkSocket`, if it is one.
/// # C: O(1)
fn netlink_sock(fd: u64) -> Option<Arc<vfs::File>> {
    let f = fd_file_local(fd)?;
    if (f.inode().ino() & 0xFFFF_FFFF_0000_0000) == NL_TAG { Some(f) } else { None }
}

/// `bind(fd, sockaddr_nl, addrlen)` for netlink. `nl_groups` (offset 8)
/// is the multicast subscription bitmask (legacy RTMGRP_* layout); set
/// it on the socket so rtnl_multicast delivers RTM_NEW*/DEL* notifications
/// (`ip monitor`, systemd-networkd). `nl_pid` autobind is unchanged (the
/// socket keeps its allocated port_id, which getsockname reports).
/// # C: O(1)
pub fn bind(fd: u64, addr_p: u64) -> i64 {
    let file = match netlink_sock(fd) { Some(f) => f, None => return -(Errno::Ebadf.as_i32() as i64) };
    if addr_p == 0 || addr_p + 12 >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    // SAFETY: addr_p+12 validated < USER_VA_END; sockaddr_nl.nl_groups @ +8.
    let nl_groups = unsafe { core::ptr::read_volatile((addr_p + 8) as *const u32) };
    if let Some(s) = file.inode().private::<::netlink::NetlinkSocket>() {
        s.set_group_mask(nl_groups);
    }
    0
}

/// `setsockopt(fd, level, optname, optval, optlen)` for netlink. At
/// SOL_NETLINK, NETLINK_ADD_MEMBERSHIP / NETLINK_DROP_MEMBERSHIP take a
/// group NUMBER (RTNLGRP_*) in optval and (un)subscribe the socket so
/// rtnl_multicast reaches it (`ip monitor`, networkd). Other tuning knobs
/// (NETLINK_BROADCAST_ERROR, NETLINK_NO_ENOBUFS, NETLINK_PKTINFO) no-op.
/// # C: O(1)
pub fn setsockopt(fd: u64, level: u64, optname: u64, optval: u64, optlen: u64) -> i64 {
    const SOL_NETLINK: u64 = 270;
    const NETLINK_ADD_MEMBERSHIP:  u64 = 1;
    const NETLINK_DROP_MEMBERSHIP: u64 = 2;
    if level == SOL_NETLINK
        && (optname == NETLINK_ADD_MEMBERSHIP || optname == NETLINK_DROP_MEMBERSHIP)
    {
        if optval == 0 || optval + 4 > USER_VA_END || optlen < 4 {
            return -(Errno::Einval.as_i32() as i64);
        }
        let file = match netlink_sock(fd) { Some(f) => f, None => return -(Errno::Ebadf.as_i32() as i64) };
        // SAFETY: optval+4 validated < USER_VA_END; group is a 4-byte int.
        let group = unsafe { core::ptr::read_volatile(optval as *const u32) };
        if let Some(s) = file.inode().private::<::netlink::NetlinkSocket>() {
            if optname == NETLINK_ADD_MEMBERSHIP { s.add_membership(group); }
            else { s.drop_membership(group); }
        }
    }
    0
}

/// `getsockopt(fd, level, optname, optval, optlen)` for netlink.
/// sd_netlink_open REQUIRES getsockopt(SOL_SOCKET, SO_PROTOCOL) — it stores
/// the result as the socket's protocol. SO_TYPE → SOCK_RAW. The
/// NETLINK_LIST_MEMBERSHIPS size-query passes optval=NULL (report 0 groups).
/// # C: O(1)
pub fn getsockopt(fd: u64, level: u64, optname: u64, optval: u64, optlen_p: u64) -> i64 {
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
    if optval == 0 || optval >= USER_VA_END || optlen_p == 0 || optlen_p >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // sd_netlink_open REQUIRES getsockopt(SOL_SOCKET, SO_PROTOCOL) — it
    // stores the result as the socket's protocol. The reply-pid fix
    // (handle_one stamps nlmsg_pid = port_id; getsockname returns the
    // same) makes sd_netlink accept our rtnl replies, so open + rtnl now
    // work and lo comes up.
    let proto = fd_file_local(fd)
        .and_then(|f| f.inode().private::<::netlink::NetlinkSocket>().map(|s| s.protocol))
        .unwrap_or(0);
    let val: u32 = if level == SOL_SOCKET && optname == SO_PROTOCOL { proto as u32 }
                   else if level == SOL_SOCKET && optname == SO_TYPE { 3 /* SOCK_RAW */ }
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
    recvfrom(fd, bufp, len, 0, 0)
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
    let (name, iov, iovlen, ctrl, ctrllen) = unsafe {
        (core::ptr::read_volatile(msgp as *const u64),
         core::ptr::read_volatile((msgp + 16) as *const u64),
         core::ptr::read_volatile((msgp + 24) as *const u64),
         core::ptr::read_volatile((msgp + 32) as *const u64),
         core::ptr::read_volatile((msgp + 40) as *const u64))
    };
    if iovlen > 1024 { return -(Errno::Einval.as_i32() as i64); }
    let file = match fd_file_local(fd) { Some(f) => f, None => return -(Errno::Ebadf.as_i32() as i64) };
    // Pull the datagram via PEEK (leave queued) or consume, per MSG_PEEK.
    let sock = match file.inode().private::<::netlink::NetlinkSocket>() {
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
    // nl_groups MUST identify the multicast group the message came on, NOT 0.
    // libudev's `device_monitor_receive_device` treats nl_groups==0 as a
    // UNICAST message and drops it unless from a trusted sender — so a uevent
    // with nl_groups=0 was silently ignored (udevd read it, never processed it,
    // no /run/udev/data, no seat, no greeter). Raw kernel uevents ride group 1
    // (UDEV_MONITOR_KERNEL); cooked "libudev" messages ride group 2 (…_UDEV).
    if name != 0 && name < USER_VA_END {
        let nl_groups: u32 = if dgram.starts_with(b"libudev\0") { 2 } else { 1 };
        // SAFETY: name validated < USER_VA_END; sockaddr_nl is 12 bytes.
        unsafe {
            core::ptr::write_volatile( name        as *mut u16, 16); // AF_NETLINK
            core::ptr::write_volatile((name +  2)  as *mut u16, 0);
            core::ptr::write_volatile((name +  4)  as *mut u32, 0);  // nl_pid = kernel
            core::ptr::write_volatile((name +  8)  as *mut u32, nl_groups);
        }
    }
    // SCM_CREDENTIALS ancillary: modern systemd-udevd's `sd-device-monitor`
    // reads SO_PASSCRED creds off each uevent and DROPS any message that lacks
    // an SCM_CREDENTIALS record or whose uid != 0 ("No sender credentials
    // received, ignoring message"). Kernel-originated uevents carry ucred
    // {pid:0,uid:0,gid:0}. Without this every uevent was silently ignored:
    // udevd drained the socket but processed no device (empty /run/udev/data,
    // no master-of-seat tag, seat0 non-graphical, gdm greeter never launched).
    // cmsghdr (LP64) = {len:u64@0, level:i32@8, type:i32@12}; SCM_CREDENTIALS
    // (SOL_SOCKET=1, type=2) data = struct ucred {pid:i32,uid:u32,gid:u32}.
    // CMSG_LEN(12)=28, CMSG_SPACE(12)=32. Only emit for the uevent monitor
    // (proto 15) when the caller supplied a control buffer with room.
    const CMSG_LEN_UCRED: u64 = 28;
    let wrote_cmsg = sock.protocol == 15 && ctrl != 0 && ctrl < USER_VA_END
        && ctrllen >= CMSG_LEN_UCRED && ctrl.saturating_add(CMSG_LEN_UCRED) < USER_VA_END;
    if wrote_cmsg {
        // SAFETY: ctrl..ctrl+28 validated in user range; LP64 cmsghdr+ucred layout.
        unsafe {
            core::ptr::write_volatile( ctrl        as *mut u64, CMSG_LEN_UCRED); // cmsg_len
            core::ptr::write_volatile((ctrl +  8)  as *mut i32, 1);  // SOL_SOCKET
            core::ptr::write_volatile((ctrl + 12)  as *mut i32, 2);  // SCM_CREDENTIALS
            core::ptr::write_volatile((ctrl + 16)  as *mut i32, 0);  // ucred.pid = kernel
            core::ptr::write_volatile((ctrl + 20)  as *mut u32, 0);  // ucred.uid = root
            core::ptr::write_volatile((ctrl + 24)  as *mut u32, 0);  // ucred.gid = root
        }
    }
    // SAFETY: msgp validated; write back namelen/controllen/flags.
    unsafe {
        core::ptr::write_volatile((msgp +  8) as *mut u32, if name != 0 { 12 } else { 0 });
        core::ptr::write_volatile((msgp + 40) as *mut u64, if wrote_cmsg { CMSG_LEN_UCRED } else { 0 });
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
pub fn getsockname(fd: u64, addr_p: u64) -> i64 {
    if addr_p == 0 || addr_p >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    // nl_pid MUST be the socket's port_id — the same value its replies
    // carry in nlmsg_pid. sd_netlink learns this via getsockname and then
    // drops any reply whose nlmsg_pid differs. Returning current.tid here
    // (≠ the port_id replies use) made every reply mismatch and get
    // dropped. Fall back to the task tid only if the fd isn't netlink.
    use core::sync::atomic::Ordering;
    let pid = fd_file_local(fd)
        .and_then(|f| f.inode().private::<::netlink::NetlinkSocket>()
            .map(|s| s.port_id.load(Ordering::Acquire)))
        .unwrap_or_else(|| sched::live::current().map(|c| c.tid).unwrap_or(1));
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
pub fn sendto(fd: u64, bufp: u64, len: usize, dest_p: u64, dest_len: u64) -> i64 {
    let file = match fd_file_local(fd) { Some(f) => f, None => return -(Errno::Ebadf.as_i32() as i64) };
    if bufp == 0 || bufp.saturating_add(len as u64) >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: caller's range check + the bounds-add above.
    let buf = unsafe { core::slice::from_raw_parts(bufp as *const u8, len) };
    send_slice(&file, buf, dest_nl_groups(dest_p, dest_len))
}

/// Read the destination multicast group from a user `sockaddr_nl` (nl_groups @
/// +8), or 0 when absent. # C: O(1)
fn dest_nl_groups(dest_p: u64, dest_len: u64) -> u32 {
    if dest_p != 0 && dest_len >= 12 && dest_p + 12 <= USER_VA_END {
        // SAFETY: dest_p+12 validated in-range; nl_groups is a 4-byte field @ +8.
        unsafe { core::ptr::read_volatile((dest_p + 8) as *const u32) }
    } else { 0 }
}

/// Send one ALREADY-COALESCED netlink message (a single datagram) — the slice
/// may be a kernel buffer assembled from a `sendmsg` iovec vector.
/// # C: O(len)
pub fn send_coalesced(fd: u64, buf: &[u8], name: u64, namelen: u64) -> i64 {
    let file = match fd_file_local(fd) { Some(f) => f, None => return -(Errno::Ebadf.as_i32() as i64) };
    send_slice(&file, buf, dest_nl_groups(name, namelen))
}

/// Core netlink send over a byte slice. A KOBJECT_UEVENT socket carrying a
/// COOKED libudev message (magic "libudev\0" prefix) or a multicast destination
/// re-broadcasts to the monitor group so systemd PID1 / logind receive processed
/// device events (a cooked message is NOT an nlmsghdr). The cooked datagram is
/// header+properties across MULTIPLE `sendmsg` iovecs — it must be coalesced
/// (see `sys_sendmsg`) so the whole libudev message reaches the monitor as one
/// datagram, not split into a header-only + properties-only pair that logind
/// can't parse (card0 add lost → seat0 never CanGraphical → no greeter).
/// # C: O(len)
fn send_slice(file: &alloc::sync::Arc<vfs::File>, buf: &[u8], dest_groups: u32) -> i64 {
    if let Some(s) = file.inode().private::<::netlink::NetlinkSocket>() {
        let is_uevent = s.protocol == ::netlink::proto::NETLINK_KOBJECT_UEVENT;
        let is_cooked = buf.len() >= 8 && &buf[..8] == b"libudev\0";
        if is_uevent && (is_cooked || dest_groups != 0) {
            ::netlink::rebroadcast_cooked_uevent(buf, dest_groups, s);
            return buf.len() as i64;
        }
    }
    match file.inode().write(0, buf) {
        Ok(n) => n as i64,
        Err(_) => -(Errno::Eio.as_i32() as i64),
    }
}

/// `sendmsg(fd, msghdr)` for netlink. Unlike the generic sendmsg fallback,
/// this preserves datagram boundaries across iovecs and passes
/// sockaddr_nl.nl_groups into the netlink layer so userspace-originated
/// multicast, especially systemd-udevd's cooked kobject uevents, reaches
/// monitor subscribers.
/// # C: O(iov + payload bytes)
pub fn sendmsg(fd: u64, name: u64, namelen: u64, iov: u64, iovlen: u64) -> i64 {
    let file = match fd_file_local(fd) { Some(f) => f, None => return -(Errno::Ebadf.as_i32() as i64) };
    let sock = match file.inode().private::<::netlink::NetlinkSocket>() {
        Some(s) => s,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    if iovlen > 1024 { return -(Errno::Einval.as_i32() as i64); }
    let groups = if name != 0 {
        if name >= USER_VA_END || namelen < 12 { return -(Errno::Einval.as_i32() as i64); }
        // SAFETY: name validated in user range and namelen covers sockaddr_nl.nl_groups @ +8.
        unsafe { core::ptr::read_volatile((name + 8) as *const u32) }
    } else {
        0
    };

    let mut payload = Vec::new();
    for i in 0..iovlen {
        let iov_i = iov + i * 16;
        if iov_i == 0 || iov_i >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: iov_i validated in user range; iovec is {base@0,len@8}.
        let (base, len) = unsafe {
            (core::ptr::read_volatile(iov_i as *const u64),
             core::ptr::read_volatile((iov_i + 8) as *const u64) as usize)
        };
        if len == 0 { continue; }
        if base == 0 || base.saturating_add(len as u64) >= USER_VA_END {
            return -(Errno::Efault.as_i32() as i64);
        }
        if payload.len().saturating_add(len) > 65507 {
            return -(Errno::Emsgsize.as_i32() as i64);
        }
        // SAFETY: base..base+len validated < USER_VA_END.
        let src = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
        payload.extend_from_slice(src);
    }
    match sock.write_to_groups(&payload, groups) {
        Ok(n) => n as i64,
        Err(_) => -(Errno::Eio.as_i32() as i64),
    }
}

/// `recvfrom(fd, buf, len, flags, src, ...)` for netlink. Honours `MSG_PEEK`
/// (leave the datagram queued) and `MSG_TRUNC` (return the FULL datagram length
/// even when the user buffer is shorter). Returns EAGAIN when the queue is
/// empty.
///
/// libudev's uevent monitor does `recvfrom(buf, len=0, MSG_PEEK|MSG_TRUNC)` to
/// SIZE the pending message before allocating, then a second consuming read.
/// If recvfrom drops the flags (as it used to) that size-probe dequeues and
/// DESTROYS the message and returns 0/EAGAIN — so udevd never actually received
/// any uevent, spun its event loop, and never processed devices (card0 was
/// never tagged → no graphical seat → no gdm greeter). MSG_PEEK must leave the
/// datagram queued and MSG_TRUNC must report its true length.
/// # SAFETY: bufp..bufp+len ⊂ USER_VA_END (checked when len>0); src_p validated.
/// # C: O(len) — single copy out of the peeked/dequeued datagram.
pub fn recvfrom(fd: u64, bufp: u64, len: usize, src_p: u64, flags: u64) -> i64 {
    const MSG_PEEK:  u64 = 0x02;
    const MSG_TRUNC: u64 = 0x20;
    let file = match fd_file_local(fd) { Some(f) => f, None => return -(Errno::Ebadf.as_i32() as i64) };
    // A zero-length size-probe (MSG_PEEK|MSG_TRUNC) legitimately passes len==0
    // (and possibly bufp==0); only range-check when there is a buffer to write.
    if len > 0 && (bufp == 0 || bufp.saturating_add(len as u64) >= USER_VA_END) {
        return -(Errno::Efault.as_i32() as i64);
    }
    let sock = match file.inode().private::<::netlink::NetlinkSocket>() {
        Some(s) => s, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // PEEK leaves the datagram queued (the following consuming read still sees
    // it); otherwise consume it. Empty/zero-length front → EAGAIN.
    let dgram = if (flags & MSG_PEEK) != 0 { sock.peek_front() } else { sock.dequeue() };
    let dgram = match dgram { Some(d) if !d.is_empty() => d, _ => return -(Errno::Eagain.as_i32() as i64) };
    let copy = dgram.len().min(len);
    if copy > 0 {
        // SAFETY: bufp..bufp+copy validated above (len>0 ⇒ range checked); CPL=0 write through caller AS.
        unsafe { core::ptr::copy_nonoverlapping(dgram.as_ptr(), bufp as *mut u8, copy); }
    }
    if src_p != 0 && src_p < USER_VA_END {
        // nl_groups identifies the multicast group (1=UDEV_MONITOR_KERNEL raw,
        // 2=UDEV_MONITOR_UDEV cooked) — NOT 0, or libudev drops it as untrusted
        // unicast (see recvmsg). SAFETY: src_p validated < USER_VA_END; 12 bytes.
        let nl_groups: u32 = if dgram.starts_with(b"libudev\0") { 2 } else { 1 };
        unsafe {
            core::ptr::write_volatile( src_p        as *mut u16, 16);
            core::ptr::write_volatile((src_p +  2)  as *mut u16, 0);
            core::ptr::write_volatile((src_p +  4)  as *mut u32, 0);  // kernel = pid 0
            core::ptr::write_volatile((src_p +  8)  as *mut u32, nl_groups);
        }
    }
    // MSG_TRUNC: report the FULL datagram length (Linux netlink_recvmsg) so the
    // caller sizes its buffer correctly; else the number of bytes copied.
    if (flags & MSG_TRUNC) != 0 { dgram.len() as i64 } else { copy as i64 }
}
