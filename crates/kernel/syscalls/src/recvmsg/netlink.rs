use alloc::vec::Vec;

use net::uapi::{MSG_DONTWAIT, MSG_PEEK, MSG_TRUNC};
use syscall::errno::Errno;
use vfs::OpenFlags;

use crate::net_sockaddr::encoded_sockaddr_nl;
use crate::recv_user::RecvUser;

const NETLINK_KOBJECT_UEVENT: u16 = 15;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn file(fd: u64) -> Result<alloc::sync::Arc<vfs::File>, i64> {
    let file = crate::net_common::fd_file(fd).ok_or_else(|| err(Errno::Ebadf))?;
    if file.inode().private::<::netlink::NetlinkSocket>().is_none() { return Err(err(Errno::Enotsock)); }
    Ok(file)
}

fn groups(protocol: u16, dgram: &[u8]) -> u32 {
    if protocol != NETLINK_KOBJECT_UEVENT { 0 }
    else if dgram.starts_with(b"libudev\0") { 2 }
    else { 1 }
}

fn wait(sock: &::netlink::NetlinkSocket) {
    let queue = sock.rx_queue.lock();
    if !queue.is_empty() { return; }
    // SAFETY: queue lock closes enqueue-before-park lost wake window.
    unsafe { sock.waiters.park(); }
    drop(queue);
    // SAFETY: current task is parked on the netlink receive wait list.
    unsafe { sched::live::schedule::schedule(); }
}

/// Netlink datagram recvmsg using one imported msghdr snapshot. # C: O(payload)
pub(crate) fn recv_pinned(file: &alloc::sync::Arc<vfs::File>, file_nonblock: bool, user: &RecvUser, flags: u64) -> i64 {
    let inode = file.inode();
    let sock = match inode.private::<::netlink::NetlinkSocket>() { Some(sock) => sock, None => return err(Errno::Enotsock) };
    let peek = flags & MSG_PEEK != 0;
    let nonblock = flags & MSG_DONTWAIT != 0 || file_nonblock;
    let (dgram, copied, src_pid) = loop {
        let mut queue = sock.rx_queue.lock();
        let Some((dgram, src_pid)) = queue.front() else {
            drop(queue);
            let pending = sock.take_pending_recv_error();
            if pending != 0 { return -(pending as i64); }
            if nonblock { return err(Errno::Eagain); }
            if sched::live::deliverable_signals_self() != 0 { return err(Errno::Eintr); }
            wait(&sock);
            continue;
        };
        let dgram = dgram.clone();
        let src_pid = *src_pid;
        let copied = user.copy_payload(&dgram[..core::cmp::min(user.capacity, dgram.len())]);
        if !peek { queue.pop_front(); }
        drop(queue);
        match copied {
            Ok(copied) => break (dgram, copied, src_pid),
            Err(e) => return e,
        }
    };
    let delivered = if sock.protocol == NETLINK_KOBJECT_UEVENT {
        crate::recv_control::deliver(user, Vec::new(), Some((0, 0, 0)), flags)
    } else {
        crate::recv_control::DeliveredControl { len: 0, flags: crate::recv_control::output_flags(flags) }
    };
    if let Err(e) = user.copy_name(encoded_sockaddr_nl(src_pid, groups(sock.protocol, &dgram)).as_bytes()) { return e; }
    let mut out_flags = delivered.flags;
    if copied < dgram.len() { out_flags |= MSG_TRUNC as u32; }
    if let Err(e) = user.finish(delivered.len, out_flags) { return e; }
    if flags & MSG_TRUNC != 0 { dgram.len() as i64 } else { copied as i64 }
}

/// Netlink recvmsg after resolving and pinning its file. # C: O(payload)
pub(crate) fn recv(fd: u64, user: &RecvUser, flags: u64) -> i64 {
    let file = match file(fd) { Ok(file) => file, Err(e) => return e };
    let nonblock = file.flags().contains(OpenFlags::O_NONBLOCK);
    recv_pinned(&file, nonblock, user, flags)
}
