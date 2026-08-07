// Live RTM_NEWNSID / RTM_GETNSID binding to the namespace owner.

extern crate alloc;

use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::{flags, Nlmsghdr};
use super::{done_multi, nlmsg_ack_bad_attr, nlmsg_ack_pub, parse_dumpnsid, parse_getnsid,
    parse_newnsid, put_nlattr_i32, ParseNsidError, PeerRef, RTM_NEWNSID};

fn ack(req: &Nlmsghdr, errno: Result<(), Errno>) -> Vec<u8> {
    nlmsg_ack_pub(req, errno.map_or_else(|e| -e.as_i32(), |_| 0))
}

fn parse_ack(req: &Nlmsghdr, err: ParseNsidError) -> Vec<u8> {
    match err.offset {
        Some(offset) => nlmsg_ack_bad_attr(req, -err.errno.as_i32(), offset),
        None => ack(req, Err(err.errno)),
    }
}

fn resolve_peer(peer: PeerRef, namespace: &network_namespace::NetworkNamespaceRef,
    fdt: &vfs::FdTable) -> Result<network_namespace::NetworkNamespaceRef, Errno>
{
    match peer {
        PeerRef::Fd(fd) => nscg::net_ns_from_fd(fdt, fd).map_err(|e| match e {
            vfs::VfsError::Ebadf => Errno::Ebadf, _ => Errno::Einval,
        }),
        PeerRef::Pid(pid) => sched::registry::resolve_user_pid(pid)
            .and_then(|task| task.network_namespace_snapshot()).ok_or(Errno::Esrch),
        PeerRef::Nsid(id) => namespace.peer_by_id(id).ok_or(Errno::Enoent),
    }
}

fn resolve_target(id: Option<i32>, namespace: &network_namespace::NetworkNamespaceRef,
    cur: &sched::Task) -> Result<network_namespace::NetworkNamespaceRef, Errno>
{
    let Some(id) = id else { return Ok(alloc::sync::Arc::clone(namespace)); };
    let target = namespace.peer_by_id(id).ok_or(Errno::Einval)?;
    if !nscg::has_net_admin_for(cur, &target) { return Err(Errno::Eacces); }
    Ok(target)
}

/// Encode the single `RTM_NEWNSID` answer returned by an ID lookup. # C: O(1)
fn get_reply(req: &Nlmsghdr, nsid: i32, multi: bool, current_nsid: Option<i32>) -> Vec<u8> {
    let mut body = alloc::vec![0];
    put_nlattr_i32(&mut body, super::nsid_req::NETNSA_NSID, nsid);
    if let Some(id) = current_nsid { put_nlattr_i32(&mut body, super::nsid_req::NETNSA_CURRENT_NSID, id); }
    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32, nlmsg_type: RTM_NEWNSID, nlmsg_flags: if multi { flags::NLM_F_MULTI } else { 0 },
        nlmsg_seq: req.nlmsg_seq, nlmsg_pid: req.nlmsg_pid,
    };
    let mut out = Vec::with_capacity(total);
    let mut wire = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut wire);
    out.extend_from_slice(&wire);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}

/// Apply `RTM_NEWNSID` with the caller's already-pinned fd table. # C: O(N peers)
pub fn new(req: &Nlmsghdr, body: &[u8], namespace: &network_namespace::NetworkNamespaceRef,
    fdt: &vfs::FdTable, _cur: &sched::Task) -> Vec<u8>
{
    let parsed = match parse_newnsid(body) { Ok(v) => v, Err(e) => return parse_ack(req, e) };
    let peer = match resolve_peer(parsed.peer, namespace, fdt) { Ok(v) => v, Err(e) => return ack(req, Err(e)) };
    match namespace.assign_peer_id(&peer, parsed.nsid) {
        Ok(()) => ack(req, Ok(())),
        Err(network_namespace::PeerIdError::Invalid) => ack(req, Err(Errno::Einval)),
        Err(network_namespace::PeerIdError::Exists) => ack(req, Err(Errno::Eexist)),
    }
}

/// Apply `RTM_GETNSID` for one peer nsfs descriptor. # C: O(N peers)
pub fn get(req: &Nlmsghdr, body: &[u8], namespace: &network_namespace::NetworkNamespaceRef,
    fdt: &vfs::FdTable, cur: &sched::Task) -> Vec<u8>
{
    let parsed = match parse_getnsid(body) { Ok(v) => v, Err(e) => return parse_ack(req, e) };
    let peer = match resolve_peer(parsed.peer, namespace, fdt) { Ok(v) => v, Err(e) => return ack(req, Err(e)) };
    let target = match resolve_target(parsed.target_nsid, namespace, cur) { Ok(v) => v, Err(e) => return ack(req, Err(e)) };
    match target.peer_id(&peer) {
        None => ack(req, Err(Errno::Enoent)),
        Some(nsid) => get_reply(req, nsid, false, parsed.target_nsid.map(|_| namespace.peer_id(&peer).unwrap_or(-1))),
    }
}

/// Build the complete immediate `RTM_GETNSID` multipart dump. # C: O(N peers)
pub fn dump(req: &Nlmsghdr, body: &[u8], namespace: &network_namespace::NetworkNamespaceRef,
    cur: &sched::Task) -> Vec<u8>
{
    let parsed = match parse_dumpnsid(body) { Ok(v) => v, Err(e) => return parse_ack(req, e) };
    let target = match resolve_target(parsed.target_nsid, namespace, cur) { Ok(v) => v, Err(e) => return ack(req, Err(e)) };
    dump_rows(req, &target, parsed.target_nsid.is_some().then_some(namespace))
}

fn dump_rows(req: &Nlmsghdr, target: &network_namespace::NetworkNamespaceRef,
    reference: Option<&network_namespace::NetworkNamespaceRef>) -> Vec<u8>
{
    let mut out = Vec::new();
    for (id, peer) in target.peer_snapshot() {
        let current = reference.map(|namespace| namespace.peer_id(&peer).unwrap_or(-1));
        out.extend_from_slice(&get_reply(req, id, true, current));
    }
    out.extend_from_slice(&done_multi(req.nlmsg_seq, req.nlmsg_pid));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_reply_is_newnsid_with_one_signed_id() {
        let req = Nlmsghdr { nlmsg_len: 16, nlmsg_type: 90, nlmsg_flags: 1, nlmsg_seq: 8, nlmsg_pid: 23 };
        let reply = get_reply(&req, 41, false, None);
        assert_eq!(u16::from_ne_bytes([reply[4], reply[5]]), RTM_NEWNSID);
        assert_eq!(u32::from_ne_bytes([reply[8], reply[9], reply[10], reply[11]]), 8);
        assert_eq!(&reply[16..25], &[0, 8, 0, 1, 0, 41, 0, 0, 0]);
    }

    #[test]
    fn dump_rows_are_multipart_and_terminated() {
        let owner = network_namespace::initial();
        let first = crate::netlink_tests::test_namespace();
        let second = crate::netlink_tests::test_namespace();
        owner.assign_peer_id(&first, 4).unwrap();
        owner.assign_peer_id(&second, 9).unwrap();
        let req = Nlmsghdr { nlmsg_len: 16, nlmsg_type: 90, nlmsg_flags: 0x301, nlmsg_seq: 8, nlmsg_pid: 23 };
        let reply = dump_rows(&req, &owner, None);
        let first = Nlmsghdr::parse(&reply).unwrap();
        assert_eq!(first.nlmsg_type, RTM_NEWNSID);
        assert_eq!(first.nlmsg_flags, flags::NLM_F_MULTI);
        let second_at = crate::nlmsg_align(first.nlmsg_len as usize);
        let second = Nlmsghdr::parse(&reply[second_at..]).unwrap();
        assert_eq!(second.nlmsg_type, RTM_NEWNSID);
        let done_at = second_at + crate::nlmsg_align(second.nlmsg_len as usize);
        assert_eq!(Nlmsghdr::parse(&reply[done_at..]).unwrap().nlmsg_type, crate::msg::NLMSG_DONE);
    }
}
