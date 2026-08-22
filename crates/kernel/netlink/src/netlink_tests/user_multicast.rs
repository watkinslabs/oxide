use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::*;

fn socket(protocol: u16, ns: &network_namespace::NetworkNamespaceRef) -> Arc<NetlinkSocket> {
    let s = Arc::new(NetlinkSocket::new(protocol, ns));
    register_port_id(&s);
    s
}

#[test]
fn userspace_group_send_broadcasts_then_unicasts_with_linux_exclusions() {
    const GROUP: u32 = 3;
    const GROUP_MASK: u32 = 1 << (GROUP - 1);
    let ns = test_namespace();
    let sender = socket(proto::NETLINK_USERSOCK, &ns);
    let unicast = socket(proto::NETLINK_USERSOCK, &ns);
    let multicast = socket(proto::NETLINK_USERSOCK, &ns);
    let unsubscribed = socket(proto::NETLINK_USERSOCK, &ns);
    sender.add_membership(GROUP).unwrap();
    unicast.add_membership(GROUP).unwrap();
    multicast.add_membership(GROUP).unwrap();

    let unicast_port = unicast.port_id.load(Ordering::Acquire);
    let dest = NlDest { port_id: unicast_port, group: GROUP_MASK };
    assert_eq!(sender.send_to(b"group", dest, true), Ok(5));

    let ReceiveState::Datagram(direct) = unicast.receive(false) else {
        panic!("named port receives the unicast copy");
    };
    assert_eq!(direct.bytes, b"group");
    assert_eq!(direct.multicast_group, 0, "named port is excluded from broadcast");

    let ReceiveState::Datagram(group) = multicast.receive(false) else {
        panic!("subscriber receives the multicast copy");
    };
    assert_eq!(group.bytes, b"group");
    assert_eq!(group.src_port, sender.port_id.load(Ordering::Acquire));
    assert_eq!(group.multicast_group, GROUP);
    assert!(matches!(sender.receive(false), ReceiveState::Empty), "sender is excluded");
    assert!(matches!(unsubscribed.receive(false), ReceiveState::Empty));
}

#[test]
fn group_only_send_broadcasts_and_still_reaches_protocol_input() {
    const GROUP: u32 = 2;
    const GROUP_MASK: u32 = 1 << (GROUP - 1);
    let ns = test_namespace();
    let sender = socket(proto::NETLINK_USERSOCK, &ns);
    let subscriber = socket(proto::NETLINK_USERSOCK, &ns);
    subscriber.add_membership(GROUP).unwrap();
    let header = Nlmsghdr {
        nlmsg_len: Nlmsghdr::SIZE as u32,
        nlmsg_type: 0x20,
        nlmsg_flags: flags::NLM_F_REQUEST,
        nlmsg_seq: 17,
        nlmsg_pid: sender.port_id.load(Ordering::Acquire),
    };
    let mut request = [0u8; Nlmsghdr::SIZE];
    header.write_to(&mut request);

    assert_eq!(sender.send_to(&request, NlDest { port_id: 0, group: GROUP_MASK }, true),
        Ok(request.len()));
    let ReceiveState::Datagram(multicast) = subscriber.receive(false) else {
        panic!("subscriber receives the group copy");
    };
    assert_eq!(multicast.bytes, request);
    assert_eq!(multicast.multicast_group, GROUP);
    let ReceiveState::Datagram(reply) = sender.receive(false) else {
        panic!("the protocol input path still returns its reply");
    };
    assert_eq!(Nlmsghdr::parse(&reply.bytes).unwrap().nlmsg_type, msg::NLMSG_DONE);
}
