use alloc::vec::Vec;
use hal::USER_VA_END;
use syscall::errno::Errno;
use vfs::OpenFlags;

use super::fd_file_local;

const MSG_PEEK_U32: u32 = 0x02;
const MSG_TRUNC_U32: u32 = 0x20;
const MSG_DONTWAIT_U32: u32 = 0x40;
const MSG_PEEK_U64: u64 = 0x02;
const MSG_TRUNC_U64: u64 = 0x20;
const MSG_DONTWAIT_U64: u64 = 0x40;
const CMSG_LEN_UCRED: u64 = 28;

/// `read(fd, buf, len)` for netlink — same as recvfrom with no peer addr.
/// Linux lets read block on netlink sockets. # C: O(len) or blocks
pub fn read(fd: u64, bufp: u64, len: usize) -> i64 {
    recvfrom(fd, bufp, len, 0, 0)
}

/// `recvmsg(fd, msghdr, flags)` for netlink. # C: O(iov + len) or blocks
pub fn recvmsg(fd: u64, msgp: u64, flags: u32) -> i64 {
    if msgp == 0 || msgp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
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
    let sock = match file.inode().private::<::netlink::NetlinkSocket>() {
        Some(s) => s, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let nonblock = (flags & MSG_DONTWAIT_U32) != 0 || file.flags().contains(OpenFlags::O_NONBLOCK);
    let (dgram, src_pid) = match recv_dgram(&sock, (flags & MSG_PEEK_U32) != 0, nonblock) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut copied = 0usize;
    for i in 0..iovlen {
        if copied >= dgram.len() { break; }
        let iov_i = iov + i * 16;
        if iov_i == 0 || iov_i >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: iov_i validated in user range; iovec is {base@0,len@8}.
        let (base, blen) = unsafe {
            (core::ptr::read_volatile(iov_i as *const u64),
             core::ptr::read_volatile((iov_i + 8) as *const u64) as usize)
        };
        if blen == 0 { continue; }
        if base == 0 || base.saturating_add(blen as u64) >= USER_VA_END {
            return -(Errno::Efault.as_i32() as i64);
        }
        let take = core::cmp::min(blen, dgram.len() - copied);
        // SAFETY: base..base+take validated < USER_VA_END; CPL=0 writes.
        let dst = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, take) };
        dst.copy_from_slice(&dgram[copied..copied + take]);
        copied += take;
    }
    let truncated = copied < dgram.len();
    if name != 0 && name < USER_VA_END { write_sockaddr_nl(name, src_pid, &dgram); }
    let wrote_cmsg = sock.protocol == 15 && ctrl != 0 && ctrl < USER_VA_END
        && ctrllen >= CMSG_LEN_UCRED && ctrl.saturating_add(CMSG_LEN_UCRED) < USER_VA_END;
    if wrote_cmsg { write_ucred_cmsg(ctrl); }
    // SAFETY: msgp validated; write back returned msghdr fields.
    unsafe {
        core::ptr::write_volatile((msgp +  8) as *mut u32, if name != 0 { 12 } else { 0 });
        core::ptr::write_volatile((msgp + 40) as *mut u64, if wrote_cmsg { CMSG_LEN_UCRED } else { 0 });
        core::ptr::write_volatile((msgp + 48) as *mut u32, if truncated { MSG_TRUNC_U32 } else { 0 });
    }
    if (flags & MSG_TRUNC_U32) != 0 { dgram.len() as i64 } else { copied as i64 }
}

/// `recvfrom(fd, buf, len, flags, src, ...)` for netlink. # C: O(len) or blocks
pub fn recvfrom(fd: u64, bufp: u64, len: usize, src_p: u64, flags: u64) -> i64 {
    let file = match fd_file_local(fd) { Some(f) => f, None => return -(Errno::Ebadf.as_i32() as i64) };
    if len > 0 && (bufp == 0 || bufp.saturating_add(len as u64) >= USER_VA_END) {
        return -(Errno::Efault.as_i32() as i64);
    }
    let sock = match file.inode().private::<::netlink::NetlinkSocket>() {
        Some(s) => s, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let nonblock = (flags & MSG_DONTWAIT_U64) != 0 || file.flags().contains(OpenFlags::O_NONBLOCK);
    let (dgram, src_pid) = match recv_dgram(&sock, (flags & MSG_PEEK_U64) != 0, nonblock) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let copy = dgram.len().min(len);
    if copy > 0 {
        // SAFETY: bufp..bufp+copy validated above; CPL=0 writes through caller AS.
        unsafe { core::ptr::copy_nonoverlapping(dgram.as_ptr(), bufp as *mut u8, copy); }
    }
    if src_p != 0 && src_p < USER_VA_END { write_sockaddr_nl(src_p, src_pid, &dgram); }
    if (flags & MSG_TRUNC_U64) != 0 { dgram.len() as i64 } else { copy as i64 }
}

fn recv_dgram(sock: &::netlink::NetlinkSocket, peek: bool, nonblock: bool) -> Result<(Vec<u8>, u32), i64> {
    loop {
        let dgram = if peek { sock.peek_front() } else { sock.dequeue() };
        if let Some((d, p)) = dgram {
            if !d.is_empty() { return Ok((d, p)); }
        }
        if nonblock { return Err(-(Errno::Eagain.as_i32() as i64)); }
        if sched::live::deliverable_signals_self() != 0 {
            return Err(-(Errno::Eintr.as_i32() as i64));
        }
        let q = sock.rx_queue.lock();
        if !q.is_empty() { continue; }
        // SAFETY: process ctx; rx_queue lock closes enqueue-before-park lost wake.
        unsafe { sock.waiters.park(); }
        drop(q);
        // SAFETY: process ctx; current task is parked on the netlink read wait list.
        unsafe { sched::live::schedule::schedule(); }
    }
}

fn write_sockaddr_nl(dst: u64, src_pid: u32, dgram: &[u8]) {
    let nl_groups: u32 = if dgram.starts_with(b"libudev\0") { 2 } else { 1 };
    // SAFETY: caller validated dst < USER_VA_END; sockaddr_nl is 12 bytes.
    unsafe {
        core::ptr::write_volatile( dst       as *mut u16, 16);
        core::ptr::write_volatile((dst + 2)  as *mut u16, 0);
        core::ptr::write_volatile((dst + 4)  as *mut u32, src_pid);
        core::ptr::write_volatile((dst + 8)  as *mut u32, nl_groups);
    }
}

fn write_ucred_cmsg(ctrl: u64) {
    // SAFETY: caller validated ctrl..ctrl+28 in user range; LP64 cmsghdr+ucred layout.
    unsafe {
        core::ptr::write_volatile( ctrl        as *mut u64, CMSG_LEN_UCRED);
        core::ptr::write_volatile((ctrl +  8)  as *mut i32, 1);
        core::ptr::write_volatile((ctrl + 12)  as *mut i32, 2);
        core::ptr::write_volatile((ctrl + 16)  as *mut i32, 0);
        core::ptr::write_volatile((ctrl + 20)  as *mut u32, 0);
        core::ptr::write_volatile((ctrl + 24)  as *mut u32, 0);
    }
}
