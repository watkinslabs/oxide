use syscall::errno::Errno;

use crate::addr::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::socket_error::{SocketError, SocketErrorEntry, SCM_TSTAMP_ACK, SCM_TSTAMP_SND,
    SO_EE_CODE_TXTIME_MISSED, SO_EE_CODE_ZEROCOPY_COPIED, SO_EE_ORIGIN_ICMP, SO_EE_ORIGIN_ICMP6,
    SO_EE_ORIGIN_LOCAL, SO_EE_ORIGIN_TIMESTAMPING, SO_EE_ORIGIN_TXSTATUS, SO_EE_ORIGIN_TXTIME,
    SO_EE_ORIGIN_ZEROCOPY};

#[test]
fn every_origin_carries_its_wire_number() {
    assert_eq!(crate::socket_error::SO_EE_ORIGIN_NONE, 0);
    assert_eq!(SO_EE_ORIGIN_LOCAL, 1);
    assert_eq!(SO_EE_ORIGIN_ICMP, 2);
    assert_eq!(SO_EE_ORIGIN_ICMP6, 3);
    assert_eq!(SO_EE_ORIGIN_TXSTATUS, 4);
    assert_eq!(SO_EE_ORIGIN_ZEROCOPY, 5);
    assert_eq!(SO_EE_ORIGIN_TXTIME, 6);
    assert_eq!(SO_EE_ORIGIN_TIMESTAMPING, SO_EE_ORIGIN_TXSTATUS);
}

#[test]
fn local_record_names_the_destination_and_reports_the_path_mtu() {
    let dest = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
    let entry = SocketErrorEntry::local(Errno::Emsgsize as i32, dest, 53, 1280);
    assert_eq!(entry.origin, SO_EE_ORIGIN_LOCAL);
    assert_eq!((entry.kind, entry.code, entry.data), (0, 0, 0));
    assert_eq!(entry.info, 1280);
    assert_eq!(entry.destination, dest);
    assert_eq!(entry.destination_port, 53);
    assert!(entry.payload.is_empty());
    assert_eq!(entry.offender, IpAddr::V4(Ipv4Addr::ANY));
}

#[test]
fn timestamping_record_selects_the_timestamp_and_carries_the_key() {
    let entry = SocketErrorEntry::timestamping(SCM_TSTAMP_ACK, 0x2211, true, 4);
    assert_eq!(entry.origin, SO_EE_ORIGIN_TIMESTAMPING);
    assert_eq!(entry.errno, Errno::Enomsg as i32);
    assert_eq!(entry.info, SCM_TSTAMP_ACK);
    assert_eq!(entry.data, 0x2211);
    assert_eq!(entry.ifindex, 4);
    assert_eq!(entry.offender, IpAddr::V6(Ipv6Addr::ANY));
}

#[test]
fn zerocopy_record_reports_the_identifier_range_and_the_copy_fallback() {
    let entry = SocketErrorEntry::zerocopy(5, 9, false, false);
    assert_eq!(entry.origin, SO_EE_ORIGIN_ZEROCOPY);
    assert_eq!(entry.errno, 0);
    assert_eq!((entry.info, entry.data), (5, 9));
    assert_eq!(entry.code, 0);
    assert_eq!(SocketErrorEntry::zerocopy(5, 9, true, false).code, SO_EE_CODE_ZEROCOPY_COPIED);
}

#[test]
fn txtime_record_splits_the_requested_transmit_time() {
    let entry = SocketErrorEntry::txtime(Errno::Einval as i32, SO_EE_CODE_TXTIME_MISSED,
        0x1234_5678_9abc_def0, false);
    assert_eq!(entry.origin, SO_EE_ORIGIN_TXTIME);
    assert_eq!(entry.code, SO_EE_CODE_TXTIME_MISSED);
    assert_eq!(entry.info, 0x9abc_def0);
    assert_eq!(entry.data, 0x1234_5678);
}

#[test]
fn local_publication_needs_the_destination_family_delivery_flag() {
    let error = SocketError::new();
    let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
    let v6 = IpAddr::V6(Ipv6Addr::LOOPBACK);
    assert!(!error.publish_local(Errno::Emsgsize as i32, v4, 53, 1280));
    assert!(!error.publish_local(Errno::Emsgsize as i32, v6, 53, 1280));
    error.set_recverr4(true);
    assert!(error.publish_local(Errno::Emsgsize as i32, v4, 53, 1280));
    assert!(!error.publish_local(Errno::Emsgsize as i32, v6, 53, 1280));
    error.set_recverr6(true);
    assert!(error.publish_local(Errno::Emsgsize as i32, v6, 53, 1280));
    assert_eq!(error.take(), 0, "a local error never becomes the pending errno");
}

#[test]
fn transmit_completions_are_independent_of_delivery_flags() {
    let error = SocketError::new();
    assert!(error.publish_timestamping(SCM_TSTAMP_SND, 1, false, 3));
    assert!(error.publish_txtime(Errno::Einval as i32, SO_EE_CODE_TXTIME_MISSED, 42, false));
    assert!(error.publish_zerocopy(0, 4, true, false));
    assert_eq!(error.take(), 0, "transmit completions never become the pending errno");
    for expect in [SO_EE_ORIGIN_TIMESTAMPING, SO_EE_ORIGIN_TXTIME, SO_EE_ORIGIN_ZEROCOPY] {
        assert_eq!(error.take_extended().map(|entry| entry.origin), Some(expect));
    }
}

#[test]
fn rfc4884_metadata_survives_only_when_the_family_asked_for_it() {
    let dest = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
    let mut entry = SocketErrorEntry::icmp(Errno::Ehostunreach as i32, false, 3, 4, 0,
        IpAddr::V4(Ipv4Addr::LOOPBACK), dest, 53, 1, alloc::vec![]);
    entry.data = 0x0004;
    let error = SocketError::new();
    error.set_recverr4(true);
    error.publish(entry.clone(), false, true);
    assert_eq!(error.take_extended().map(|queued| queued.data), Some(0));
    error.set_recverr4(true);
    error.set_recverr_rfc4884_4(true);
    error.publish(entry, false, true);
    assert_eq!(error.take_extended().map(|queued| queued.data), Some(0x0004));
}

#[test]
fn rfc4884_metadata_has_its_own_ipv6_switch() {
    let mut entry = SocketErrorEntry::icmp(Errno::Ehostunreach as i32, true, 1, 0, 0,
        IpAddr::V6(Ipv6Addr::LOOPBACK), IpAddr::V6(Ipv6Addr::LOOPBACK), 53, 1, alloc::vec![]);
    entry.data = 0x0008;
    let error = SocketError::new();
    error.set_recverr6(true);
    error.set_recverr_rfc4884_4(true);
    error.publish(entry.clone(), false, true);
    assert_eq!(error.take_extended().map(|queued| queued.data), Some(0),
        "the IPv4 switch does not enable IPv6 metadata");
    error.set_recverr6(true);
    error.set_recverr_rfc4884_6(true);
    error.publish(entry, false, true);
    assert_eq!(error.take_extended().map(|queued| queued.data), Some(0x0008));
}

// `IPV6_RECVPATHMTU` is a SECOND way to learn the rejecting MTU, and it is
// not the error queue: the announcement is stashed only when the socket asked
// for it, only for an IPv6 destination, and only for a size failure. It never
// touches the queue, so a socket with both switched on is told the same number
// twice rather than one of them being lost.
#[test]
fn the_path_mtu_announcement_is_stashed_only_when_the_socket_asked_for_it() {
    use crate::socket_error::report_send_failure_pmtu as report;
    use crate::NetError;
    let v6 = IpAddr::V6(Ipv6Addr::LOOPBACK);
    let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));

    let error = SocketError::new();
    assert_eq!(report(&error, 0, v6, 53, None, NetError::Emsgsize, false), NetError::Emsgsize);
    assert!(!error.pathmtu.pending(), "a socket that did not ask is charged nothing");

    let error = SocketError::new();
    assert_eq!(report(&error, 0, v4, 53, None, NetError::Emsgsize, true), NetError::Emsgsize);
    assert!(!error.pathmtu.pending(), "the announcement is an IPv6 mechanism");

    let error = SocketError::new();
    assert_eq!(report(&error, 0, v6, 53, None, NetError::Enetunreach, true),
        NetError::Enetunreach);
    assert!(!error.pathmtu.pending(), "only a size failure names an MTU");

    let error = SocketError::new();
    error.set_recverr6(true);
    assert_eq!(report(&error, 0, v6, 53, None, NetError::Emsgsize, true), NetError::Emsgsize);
    assert!(error.pathmtu.pending());
    assert_eq!(error.pathmtu.take().map(|r| r.dst), Some(Ipv6Addr::LOOPBACK));
    assert_eq!(error.take_extended().map(|entry| entry.origin), Some(SO_EE_ORIGIN_LOCAL),
        "reading the announcement leaves the queue record alone");
}
