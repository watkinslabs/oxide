use alloc::vec::Vec;

use net::uapi::{MSG_DONTWAIT, MSG_OOB, MSG_PEEK, MSG_TRUNC};
use syscall::errno::Errno;

use crate::net_sockaddr::encoded_sockaddr_nl;
use crate::recv_user::RecvUser;

const NETLINK_KOBJECT_UEVENT: u16 = 15;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn groups(protocol: u16, dgram: &[u8]) -> u32 {
    if protocol != NETLINK_KOBJECT_UEVENT { 0 }
    else if dgram.starts_with(b"libudev\0") { 2 }
    else { 1 }
}

/// Netlink datagram recvmsg using one imported msghdr snapshot. # C: O(payload)
pub(crate) fn recv_pinned(file: &alloc::sync::Arc<vfs::File>, file_nonblock: bool, user: &RecvUser, flags: u64) -> i64 {
    if flags & MSG_OOB != 0 { return err(Errno::Eopnotsupp); }
    let inode = file.inode();
    let sock = match inode.private::<::netlink::NetlinkSocket>() { Some(sock) => sock, None => return err(Errno::Enotsock) };
    let peek = flags & MSG_PEEK != 0;
    let nonblock = flags & MSG_DONTWAIT != 0 || file_nonblock;
    let (dgram, copied, src_pid) = loop {
        match sock.receive(peek) {
            ::netlink::ReceiveState::Empty => {
                if nonblock { return err(Errno::Eagain); }
                if sched::live::deliverable_signals_self() != 0 { return err(Errno::Eintr); }
                if sock.arm_receive_wait() {
                    // SAFETY: current task was parked by the canonical NETLINK receive owner.
                    unsafe { sched::live::schedule::schedule(); }
                    sock.waiters.remove_current();
                }
            }
            ::netlink::ReceiveState::Error(error) => return -(error as i64),
            ::netlink::ReceiveState::Datagram(received) => {
                let copied = user.copy_payload(
                    &received.bytes[..core::cmp::min(user.capacity, received.bytes.len())]);
                match copied {
                    Ok(copied) => break (received.bytes, copied, received.src_port),
                    Err(e) => return e,
                }
            }
        }
    };
    let delivered = if sock.protocol == NETLINK_KOBJECT_UEVENT {
        match crate::recv_control::deliver(user, Vec::new(), Some((0, 0, 0)), flags) {
            Ok(delivered) => delivered,
            Err(error) => return error,
        }
    } else {
        crate::recv_control::DeliveredControl { len: 0, flags: crate::recv_control::output_flags(flags) }
    };
    if let Err(e) = user.copy_name(encoded_sockaddr_nl(src_pid, groups(sock.protocol, &dgram)).as_bytes()) { return e; }
    let mut out_flags = delivered.flags;
    if copied < dgram.len() { out_flags |= MSG_TRUNC as u32; }
    if let Err(e) = user.finish(delivered.len, out_flags) { return e; }
    if flags & MSG_TRUNC != 0 { dgram.len() as i64 } else { copied as i64 }
}
