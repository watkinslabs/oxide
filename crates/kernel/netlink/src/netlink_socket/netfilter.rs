use core::sync::atomic::Ordering;

use crate::{invoke_netfilter, nlmsg_align, rtnetlink, Nlmsghdr};
use super::NetlinkSocket;

fn admitted(has_net_admin: bool) -> bool { has_net_admin }

/// Dispatch one complete nfnetlink datagram. Every request requires network
/// administration in the socket's network namespace before protocol parsing;
/// batch markers and queries are not exceptions. # C: O(datagram + handler)
pub(super) fn dispatch(
    sock: &NetlinkSocket,
    datagram: &[u8],
    consumed: usize,
) -> vfs::KResult<usize> {
    if !admitted(sock.may_admin_net()) {
        if let Some(header) = Nlmsghdr::parse(datagram) {
            sock.enqueue(rtnetlink::nlmsg_ack_pub(&header, -(vfs::VfsError::Eperm as i32)));
        }
        return Ok(consumed);
    }

    let mut reply = invoke_netfilter(datagram, sock.net_ns.id().as_u64());
    let port = sock.port_id.load(Ordering::Acquire);
    let mut off = 0usize;
    while off + Nlmsghdr::SIZE <= reply.len() {
        let len = u32::from_ne_bytes(
            [reply[off], reply[off + 1], reply[off + 2], reply[off + 3]],
        ) as usize;
        if len < Nlmsghdr::SIZE || off + len > reply.len() { break; }
        reply[off + 12..off + 16].copy_from_slice(&port.to_ne_bytes());
        off += nlmsg_align(len);
    }
    if !reply.is_empty() { sock.enqueue(reply); }
    Ok(consumed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_nfnetlink_datagram_requires_namespace_net_admin() {
        assert!(!admitted(false));
        assert!(admitted(true));
    }
}
