use super::*;

fn request(ty: u16) -> alloc::vec::Vec<u8> {
    let hdr = Nlmsghdr { nlmsg_len: Nlmsghdr::SIZE as u32, nlmsg_type: ty,
        nlmsg_flags: crate::flags::NLM_F_REQUEST, nlmsg_seq: 7, nlmsg_pid: 9 };
    let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut msg);
    msg
}

fn ack_errno(reply: &[u8]) -> i32 {
    i32::from_ne_bytes(reply[16..20].try_into().unwrap())
}

/// Dump-only rtnetlink operations must not turn an ordinary request into a
/// multipart dump: the dispatcher has no one-shot owner for these types.
#[test]
fn dump_only_get_requests_are_rejected_before_the_dump_builder() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let socket = crate::netlink_socket::NetlinkSocket::new(
        crate::proto::NETLINK_ROUTE, &network_namespace::initial());
    for ty in [RTM_GETRULE] {
        socket.write(&request(ty)).unwrap();
        let (reply, _) = socket.dequeue().expect("dump-only request has an error reply");
        assert_eq!(ack_errno(&reply),
            -(vfs::VfsError::Eopnotsupp as i32), "type {ty}");
    }
}
