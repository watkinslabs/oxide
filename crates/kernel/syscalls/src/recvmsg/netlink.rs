use alloc::vec::Vec;

use net::uapi::{MSG_DONTWAIT, MSG_OOB, MSG_PEEK, MSG_TRUNC};
use syscall::errno::Errno;

use crate::net_sockaddr::encoded_sockaddr_nl;
use crate::recv_user::RecvUser;

const NETLINK_KOBJECT_UEVENT: u16 = 15;
const SOL_NETLINK: i32 = 270;
const NETLINK_PKTINFO: i32 = 3;
const NETLINK_LISTEN_ALL_NSID: i32 = 8;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn group_mask(group: u32) -> u32 {
    if group > 32 { 0 } else { group.checked_sub(1).and_then(|bit| 1u32.checked_shl(bit)).unwrap_or(0) }
}

fn source_groups(protocol: u16, dgram: &[u8], multicast_group: u32) -> u32 {
    if multicast_group != 0 { group_mask(multicast_group) }
    else if protocol != NETLINK_KOBJECT_UEVENT { 0 }
    else if dgram.starts_with(b"libudev\0") { 2 }
    else { 1 }
}

/// Netlink datagram recvmsg using one imported msghdr snapshot. # C: O(payload)
pub(crate) fn recv_pinned(file: &alloc::sync::Arc<vfs::File>, file_nonblock: bool, user: &RecvUser, flags: u64) -> i64 {
    let inode = file.inode();
    let sock = match inode.private::<::netlink::NetlinkSocket>() { Some(sock) => sock, None => return err(Errno::Enotsock) };
    if flags & MSG_OOB != 0 { return err(Errno::Eopnotsupp); }
    let peek = flags & MSG_PEEK != 0;
    let nonblock = flags & MSG_DONTWAIT != 0 || file_nonblock;
    let (dgram, copied, src_pid, multicast_group, nsid, carried, security) = loop {
        match sock.receive(peek) {
            ::netlink::ReceiveState::Empty => {
                if nonblock { return err(Errno::Eagain); }
                // Linux `netlink_recvmsg` -> `skb_recv_datagram` ->
                // `__skb_wait_for_more_packets`:
                // `error = sock_intr_errno(*timeo_p)` off `sock_rcvtimeo`.
                if sched::live::deliverable_signals_self() != 0 {
                    return crate::net_errno::sock_intr_errno(sock.recv_deadline_ns());
                }
                if sock.arm_receive_wait() {
                    // SAFETY: current task was parked by the canonical NETLINK receive owner.
                    unsafe { sched::live::schedule::schedule(); }
                    sock.waiters.remove_current();
                }
            }
            ::netlink::ReceiveState::Error(error) => return -(error as i64),
            ::netlink::ReceiveState::Datagram(received) => {
                let copied = user.copy_payload_record(
                    &received.bytes[..core::cmp::min(user.capacity, received.bytes.len())]);
                match copied {
                    Ok(copied) => break (received.bytes, copied, received.src_port,
                        received.multicast_group, received.nsid, received.creds, received.security),
                    Err(e) => return e,
                }
            }
        }
    };
    // `netlink_recvmsg` hands every datagram's carried credentials to
    // `scm_recv`, which emits SCM_CREDENTIALS when — and only when — the
    // RECEIVING socket set SO_PASSCRED. One rule for every protocol: a reader
    // that did not ask is never handed a control message, and a reader that
    // did is answered whether it is watching uevents or the link table.
    let pktinfo = multicast_group.to_ne_bytes();
    let nsid_wire = nsid.unwrap_or_default().to_ne_bytes();
    let mut protocol = Vec::new();
    if sock.flags.get(::netlink::F_RECV_PKTINFO) {
        protocol.push((SOL_NETLINK, NETLINK_PKTINFO, pktinfo.as_slice()));
    }
    if sock.flags.get(::netlink::F_LISTEN_ALL_NSID) && nsid.is_some() {
        protocol.push((SOL_NETLINK, NETLINK_LISTEN_ALL_NSID, nsid_wire.as_slice()));
    }
    let scm = crate::recv_control::ScmReceive {
        credentials: net::scm::recv(sock.scm.on(), carried),
        security: if sock.scm_security.on() { security } else { None },
        pid: None,
        want_pidfd: false,
    };
    let delivered = match crate::recv_control::deliver(user, Vec::new(), scm, None, &protocol, flags)
    {
        Ok(delivered) => delivered,
        Err(error) => return error,
    };
    if let Err(e) = user.copy_name(encoded_sockaddr_nl(src_pid,
        source_groups(sock.protocol, &dgram, multicast_group)).as_bytes()) { return e; }
    let mut out_flags = delivered.flags;
    if copied < dgram.len() { out_flags |= MSG_TRUNC as u32; }
    if let Err(e) = user.finish(delivered.len, out_flags) { return e; }
    if flags & MSG_TRUNC != 0 { dgram.len() as i64 } else { copied as i64 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_group_uses_linuxs_low_word_mask() {
        assert_eq!(source_groups(::netlink::proto::NETLINK_ROUTE, b"", 5), 1 << 4);
        assert_eq!(source_groups(::netlink::proto::NETLINK_ROUTE, b"", 33), 0);
        assert_eq!(source_groups(::netlink::proto::NETLINK_ROUTE, b"", 0), 0);
    }
}
