use alloc::vec::Vec;

use net::uapi::{MSG_DONTWAIT, MSG_PEEK, MSG_TRUNC};
use syscall::errno::Errno;
use vfs::OpenFlags;

use crate::net_sockaddr::{copy_sockaddr_to_user, encoded_sockaddr_nl};

use super::fd_file_local;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }
const NETLINK_KOBJECT_UEVENT: u16 = 15;

fn groups(protocol: u16, dgram: &[u8]) -> u32 {
    if protocol != NETLINK_KOBJECT_UEVENT { 0 }
    else if dgram.starts_with(b"libudev\0") { 2 }
    else { 1 }
}

/// `read(fd, buf, len)` for a netlink record. # C: O(len) or blocks
pub fn read(fd: u64, bufp: u64, len: usize) -> i64 { recvfrom(fd, bufp, len, 0, 0, 0) }

fn wait(sock: &::netlink::NetlinkSocket) {
    let queue = sock.rx_queue.lock();
    if !queue.is_empty() { return; }
    // SAFETY: queue lock closes enqueue-before-park lost wake window.
    unsafe { sock.waiters.park(); }
    drop(queue);
    // SAFETY: current task is parked on this netlink receive wait list.
    unsafe { sched::live::schedule::schedule(); }
}

fn receive(fd: u64, bufp: u64, len: usize, flags: u64) -> Result<(Vec<u8>, u32, u16, usize, bool), i64> {
    if !uaccess::access_ok(bufp, len) { return Err(err(Errno::Efault)); }
    let file = fd_file_local(fd).ok_or_else(|| err(Errno::Ebadf))?;
    let inode = file.inode();
    let sock = inode.private::<::netlink::NetlinkSocket>().ok_or_else(|| err(Errno::Enotsock))?;
    let peek = flags & MSG_PEEK != 0;
    let nonblock = flags & MSG_DONTWAIT != 0 || file.flags().contains(OpenFlags::O_NONBLOCK);
    loop {
        let mut queue = sock.rx_queue.lock();
        if let Some((dgram, src_pid)) = queue.front() {
            let dgram = dgram.clone();
            let src_pid = *src_pid;
            let take = core::cmp::min(len, dgram.len());
            // SAFETY: datagram is kernel-owned; raw usercopy reports partial progress.
            let left = unsafe { uaccess::raw_copy_to_user(bufp, dgram.as_ptr(), take) };
            let copied = if left != take || take == 0 { Ok(take - left) } else { Err(err(Errno::Efault)) };
            if !peek { queue.pop_front(); }
            drop(queue);
            return copied.map(|copied| (dgram, src_pid, sock.protocol, copied, left != 0));
        }
        drop(queue);
        if nonblock { return Err(err(Errno::Eagain)); }
        if sched::live::deliverable_signals_self() != 0 { return Err(err(Errno::Eintr)); }
        wait(sock);
    }
}

/// `recvfrom(fd, buf, len, flags, src, srclen)` for a netlink record. # C: O(len) or blocks
pub fn recvfrom(fd: u64, bufp: u64, len: usize, src_p: u64, src_len: u64, flags: u64) -> i64 {
    let (dgram, src_pid, protocol, copied, faulted) = match receive(fd, bufp, len, flags) { Ok(got) => got, Err(e) => return e };
    if src_p != 0 {
        let sa = encoded_sockaddr_nl(src_pid, groups(protocol, &dgram));
        let rv = copy_sockaddr_to_user(src_p, src_len, &sa);
        if rv < 0 { return rv; }
    }
    if !faulted && flags & MSG_TRUNC != 0 { dgram.len() as i64 } else { copied as i64 }
}
