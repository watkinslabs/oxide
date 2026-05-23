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
