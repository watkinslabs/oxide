// `NETLINK_SELINUX` wire format and delivery rule.
//
// The consumer is `libselinux`'s userspace AVC, which decides whether to flush
// every cached access decision from these bytes. A wrong message type, a wrong
// payload width or a notification delivered to a socket that never subscribed
// is invisible to a kernel build and changes what userspace believes about the
// policy in force.

use alloc::sync::Arc;

use crate::selinux_nl::{
    encode_policyload, encode_setenforce, notify_policyload, notify_setenforce,
    register_selinux_listener, uapi,
};
use crate::{proto, NetlinkSocket, Nlmsghdr};

/// `bind` with `nl_groups = SELNL_GRP_AVC`, as the userspace AVC does.
const AVC_BIND_MASK: u32 = 1 << (uapi::SELNLGRP_AVC - 1);

fn avc_socket() -> Arc<NetlinkSocket> {
    // The kernel end of this protocol lives in the initial namespace only, so
    // a fixture namespace would subscribe to a group nothing broadcasts to.
    let sock = Arc::new(NetlinkSocket::new(proto::NETLINK_SELINUX,
        &network_namespace::initial()));
    register_selinux_listener(&sock);
    sock
}

#[test]
fn a_setenforce_notification_is_a_header_plus_one_signed_word() {
    let msg = encode_setenforce(1);
    assert_eq!(msg.len(), Nlmsghdr::SIZE + uapi::SETENFORCE_BYTES);
    let hdr = Nlmsghdr::parse(&msg).expect("header");
    assert_eq!(hdr.nlmsg_len as usize, msg.len());
    assert_eq!(hdr.nlmsg_type, uapi::SELNL_MSG_SETENFORCE);
    assert_eq!(hdr.nlmsg_type, 0x10, "SELNL_MSG_BASE");
    assert_eq!(hdr.nlmsg_flags, 0);
    assert_eq!(hdr.nlmsg_seq, 0, "a kernel notification answers no request");
    assert_eq!(hdr.nlmsg_pid, 0, "kernel-originated messages carry port 0");
    assert_eq!(i32::from_ne_bytes(msg[Nlmsghdr::SIZE..].try_into().unwrap()), 1);
    assert_eq!(i32::from_ne_bytes(
        encode_setenforce(0)[Nlmsghdr::SIZE..].try_into().unwrap()), 0);
}

#[test]
fn a_policyload_notification_carries_the_policy_sequence_number() {
    let msg = encode_policyload(7);
    assert_eq!(msg.len(), Nlmsghdr::SIZE + uapi::POLICYLOAD_BYTES);
    let hdr = Nlmsghdr::parse(&msg).expect("header");
    assert_eq!(hdr.nlmsg_len as usize, msg.len());
    assert_eq!(hdr.nlmsg_type, uapi::SELNL_MSG_POLICYLOAD);
    assert_eq!(hdr.nlmsg_type, 0x11, "SELNL_MSG_BASE + 1");
    assert_eq!(u32::from_ne_bytes(msg[Nlmsghdr::SIZE..].try_into().unwrap()), 7);
}

#[test]
fn the_two_message_types_are_distinct_and_neither_collides_with_a_control_type() {
    assert_ne!(uapi::SELNL_MSG_SETENFORCE, uapi::SELNL_MSG_POLICYLOAD);
    for control in [crate::msg::NLMSG_NOOP, crate::msg::NLMSG_ERROR, crate::msg::NLMSG_DONE,
                    crate::msg::NLMSG_OVERRUN] {
        assert_ne!(uapi::SELNL_MSG_SETENFORCE, control);
        assert_ne!(uapi::SELNL_MSG_POLICYLOAD, control);
    }
}

#[test]
fn a_subscribed_socket_receives_both_notifications_and_an_unsubscribed_one_receives_neither() {
    let _serial = crate::test_serial::selinux();
    let avc = avc_socket();
    let unsubscribed = avc_socket();
    avc.set_group_mask(AVC_BIND_MASK);

    assert_eq!(notify_setenforce(true), 1);
    assert_eq!(notify_policyload(3), 1);

    let (first, src) = avc.dequeue().expect("setenforce notification");
    assert_eq!(src, 0, "the kernel is the sender");
    assert_eq!(first, encode_setenforce(1));
    let (second, _) = avc.dequeue().expect("policyload notification");
    assert_eq!(second, encode_policyload(3));
    assert!(avc.dequeue().is_none(), "nothing else was notified");
    assert!(unsubscribed.dequeue().is_none(),
        "a socket that never bound the AVC group must receive nothing");
}

#[test]
fn a_notification_leaves_the_socket_readable_until_it_is_consumed() {
    let _serial = crate::test_serial::selinux();
    let avc = avc_socket();
    avc.set_group_mask(AVC_BIND_MASK);
    assert_eq!(avc.poll() & vfs::POLL_IN, 0, "nothing has happened yet");
    assert_eq!(notify_setenforce(false), 1);
    assert_ne!(avc.poll() & vfs::POLL_IN, 0);
    assert_eq!(avc.dequeue().expect("notification").0, encode_setenforce(0));
    assert_eq!(avc.poll() & vfs::POLL_IN, 0);
}

#[test]
fn a_socket_in_another_network_namespace_receives_nothing() {
    let _serial = crate::test_serial::selinux();
    let foreign = Arc::new(NetlinkSocket::new(proto::NETLINK_SELINUX,
        &crate::netlink_tests::test_namespace()));
    register_selinux_listener(&foreign);
    foreign.set_group_mask(AVC_BIND_MASK);
    assert_eq!(notify_policyload(1), 0);
    assert!(foreign.dequeue().is_none());
}

#[test]
fn a_closed_subscriber_stops_counting_and_drops_out_of_the_registry() {
    let _serial = crate::test_serial::selinux();
    let avc = avc_socket();
    avc.set_group_mask(AVC_BIND_MASK);
    assert_eq!(notify_setenforce(true), 1);
    drop(avc);
    assert_eq!(notify_setenforce(false), 0);
}

#[test]
fn the_protocol_is_registered_and_permits_unprivileged_subscription() {
    // The reference registers this family unconditionally when the label
    // module is built in, and every subscriber is an unprivileged process
    // linked against libselinux.
    assert!(crate::protocol_registered(proto::NETLINK_SELINUX as u32));
    assert!(crate::nonroot_recv(proto::NETLINK_SELINUX));
}

#[test]
fn the_protocol_offers_a_full_word_of_groups() {
    let sock = NetlinkSocket::new(proto::NETLINK_SELINUX, &network_namespace::initial());
    // Netlink floors every protocol at 32 subscribable groups even when its
    // kernel socket asked for one.
    assert_eq!(sock.ngroups(), crate::NETLINK_MIN_NGROUPS);
    assert!(uapi::SELNLGRP_MAX <= sock.ngroups());
    assert!(sock.add_membership(uapi::SELNLGRP_AVC).is_ok());
    assert_eq!(sock.membership_words(), alloc::vec![AVC_BIND_MASK]);
}

#[test]
fn a_datagram_sent_to_the_kernel_end_is_refused_and_answers_nothing() {
    // The family registers no receive path, so netlink's kernel-socket unicast
    // refuses the message. Answering it instead would put a reply in the
    // reader's queue, and the only consumer there reads notifications.
    let _serial = crate::test_serial::selinux();
    let avc = avc_socket();
    avc.set_group_mask(AVC_BIND_MASK);
    let mut request = alloc::vec![0u8; Nlmsghdr::SIZE];
    Nlmsghdr { nlmsg_len: Nlmsghdr::SIZE as u32, nlmsg_type: uapi::SELNL_MSG_SETENFORCE,
               nlmsg_flags: crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_ACK,
               nlmsg_seq: 1, nlmsg_pid: 0 }.write_to(&mut request);
    assert_eq!(avc.write_to_groups(&request, 0), Err(vfs::VfsError::Econnrefused));
    assert!(avc.dequeue().is_none(), "a refused send answers nothing");
}
