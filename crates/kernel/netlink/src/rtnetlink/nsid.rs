// Live RTM_NEWNSID / RTM_GETNSID binding to the namespace owner.

extern crate alloc;

use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::Nlmsghdr;
use super::{nlmsg_ack_pub, parse_getnsid, parse_newnsid, put_nlattr_i32, RTM_NEWNSID};

fn ack(req: &Nlmsghdr, errno: Result<(), Errno>) -> Vec<u8> {
    nlmsg_ack_pub(req, errno.map_or_else(|e| -e.as_i32(), |_| 0))
}

/// Encode the single `RTM_NEWNSID` answer returned by an ID lookup. # C: O(1)
fn get_reply(req: &Nlmsghdr, nsid: i32) -> Vec<u8> {
    let mut body = alloc::vec![0];
    put_nlattr_i32(&mut body, super::nsid_req::NETNSA_NSID, nsid);
    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32, nlmsg_type: RTM_NEWNSID, nlmsg_flags: 0,
        nlmsg_seq: req.nlmsg_seq, nlmsg_pid: req.nlmsg_pid,
    };
    let mut out = Vec::with_capacity(total);
    let mut wire = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut wire);
    out.extend_from_slice(&wire);
    out.extend_from_slice(&body);
    out
}

/// Apply `RTM_NEWNSID` with the caller's already-pinned fd table. # C: O(N peers)
pub fn new(req: &Nlmsghdr, body: &[u8], namespace: &network_namespace::NetworkNamespaceRef,
    fdt: &vfs::FdTable) -> Vec<u8>
{
    let parsed = match parse_newnsid(body) { Ok(v) => v, Err(e) => return ack(req, Err(e)) };
    let peer = match nscg::net_ns_from_fd(fdt, parsed.fd) {
        Ok(v) => v,
        Err(vfs::VfsError::Ebadf) => return ack(req, Err(Errno::Ebadf)),
        Err(_) => return ack(req, Err(Errno::Einval)),
    };
    match namespace.assign_peer_id(&peer, parsed.nsid) {
        Ok(()) => ack(req, Ok(())),
        Err(network_namespace::PeerIdError::Invalid) => ack(req, Err(Errno::Einval)),
        Err(network_namespace::PeerIdError::Exists) => ack(req, Err(Errno::Eexist)),
    }
}

/// Apply `RTM_GETNSID` for one peer nsfs descriptor. # C: O(N peers)
pub fn get(req: &Nlmsghdr, body: &[u8], namespace: &network_namespace::NetworkNamespaceRef,
    fdt: &vfs::FdTable) -> Vec<u8>
{
    let parsed = match parse_getnsid(body) { Ok(v) => v, Err(e) => return ack(req, Err(e)) };
    let peer = match nscg::net_ns_from_fd(fdt, parsed.fd) {
        Ok(v) => v,
        Err(vfs::VfsError::Ebadf) => return ack(req, Err(Errno::Ebadf)),
        Err(_) => return ack(req, Err(Errno::Einval)),
    };
    match namespace.peer_id(&peer) {
        Some(nsid) => get_reply(req, nsid),
        None => ack(req, Err(Errno::Enoent)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_reply_is_newnsid_with_one_signed_id() {
        let req = Nlmsghdr { nlmsg_len: 16, nlmsg_type: 90, nlmsg_flags: 1, nlmsg_seq: 8, nlmsg_pid: 23 };
        let reply = get_reply(&req, 41);
        assert_eq!(u16::from_ne_bytes([reply[4], reply[5]]), RTM_NEWNSID);
        assert_eq!(u32::from_ne_bytes([reply[8], reply[9], reply[10], reply[11]]), 8);
        assert_eq!(&reply[16..], &[0, 8, 0, 1, 0, 41, 0, 0, 0]);
    }
}
