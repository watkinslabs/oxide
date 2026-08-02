// SO_PASSCRED on a netlink socket, and the credentials a receive surfaces.

use alloc::vec;
use core::sync::atomic::Ordering;

use crate::creds::{reported, NetlinkCreds};
use crate::{proto, NetlinkSocket, ReceiveState};

fn socket(protocol: u16) -> NetlinkSocket {
    NetlinkSocket::new(protocol, &super::test_namespace())
}

fn received(state: ReceiveState) -> (alloc::vec::Vec<u8>, NetlinkCreds) {
    match state {
        ReceiveState::Datagram(dgram) => (dgram.bytes, dgram.creds),
        _ => panic!("expected a queued datagram"),
    }
}

#[test]
fn a_new_socket_does_not_pass_credentials() {
    for protocol in [proto::NETLINK_ROUTE, proto::NETLINK_KOBJECT_UEVENT] {
        assert!(!socket(protocol).passcred.load(Ordering::Acquire));
    }
}

#[test]
fn a_kernel_reply_carries_the_kernel_credential_set() {
    let s = socket(proto::NETLINK_ROUTE);
    s.enqueue(vec![1, 2, 3]);
    let (bytes, creds) = received(s.receive(false));
    assert_eq!(bytes, vec![1, 2, 3]);
    assert_eq!(creds, NetlinkCreds::KERNEL);
}

#[test]
fn a_stamped_datagram_surfaces_its_senders_credentials() {
    let s = socket(proto::NETLINK_ROUTE);
    let sender = NetlinkCreds { pid: 900, uid: 1000, gid: 1001 };
    s.enqueue_from_creds(vec![7], 900, sender);
    let (_, creds) = received(s.receive(false));
    assert_eq!(creds, sender);
}

#[test]
fn credentials_survive_a_peek_and_the_following_receive() {
    let s = socket(proto::NETLINK_ROUTE);
    let sender = NetlinkCreds { pid: 42, uid: 7, gid: 8 };
    s.enqueue_from_creds(vec![9], 42, sender);
    assert_eq!(received(s.receive(true)).1, sender);
    assert_eq!(received(s.receive(false)).1, sender);
}

// The report is decided by the RECEIVING socket's option, never by which
// netlink protocol it opened: a route socket that asked is answered exactly
// as a uevent socket that asked is.
#[test]
fn the_report_follows_the_option_on_every_protocol() {
    for protocol in [proto::NETLINK_ROUTE, proto::NETLINK_KOBJECT_UEVENT] {
        let s = socket(protocol);
        s.enqueue(vec![0]);
        let (_, creds) = received(s.receive(false));
        assert_eq!(reported(s.passcred.load(Ordering::Acquire), creds), None);

        let s = socket(protocol);
        s.passcred.store(true, Ordering::Release);
        s.enqueue(vec![0]);
        let (_, creds) = received(s.receive(false));
        assert_eq!(reported(s.passcred.load(Ordering::Acquire), creds), Some((0, 0, 0)));
    }
}
