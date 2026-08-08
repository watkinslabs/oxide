use syscall::errno::Errno;

use crate::socket_error::{SocketError, SO_EE_ORIGIN_TIMESTAMPING, SO_EE_ORIGIN_ZEROCOPY,
    SCM_TSTAMP_SND, SOCK_ERRQUEUE_RECORD_OVERHEAD};

use super::{icmp4, icmp6};

#[test]
fn latest_positive_error_is_canonical() {
    let error = SocketError::new();
    assert!(!error.set(0));
    assert!(!error.set(-1));
    assert!(error.set(Errno::Econnrefused as i32));
    assert!(error.set(Errno::Econnreset as i32));
    assert_eq!(error.take(), Errno::Econnreset as i32);
    assert_eq!(error.take(), 0);
}

#[test]
fn unconnected_icmp_requires_recverr_and_queues_fifo() {
    let error = SocketError::new();
    let entry = icmp4(Errno::Ehostunreach);
    assert!(!error.publish(entry.clone(), false, true));
    assert!(!error.has());
    error.set_recverr4(true);
    assert!(error.publish(entry.clone(), false, true));
    assert_eq!(error.take_extended(), Some(entry));
}

#[test]
fn connected_hard_error_publishes_pending_errno_without_recverr() {
    let error = SocketError::new();
    assert!(error.publish(icmp4(Errno::Econnrefused), true, true));
    assert!(!error.has_extended(), "no queue record without RECVERR");
    assert_eq!(error.take(), Errno::Econnrefused as i32);
}

#[test]
fn dequeue_clears_pending_errno_when_no_icmp_record_follows() {
    let error = SocketError::new();
    error.set_recverr4(true);
    error.publish(icmp4(Errno::Ehostunreach), false, true);
    // A later transport error does not survive the dequeue of the ICMP record
    // that owns the pending errno.
    error.set(Errno::Econnreset as i32);
    assert!(error.take_extended().is_some());
    assert_eq!(error.take(), 0);
}

#[test]
fn dequeue_promotes_the_next_icmp_record_to_pending_errno() {
    let error = SocketError::new();
    error.set_recverr4(true);
    error.set_recverr6(true);
    error.publish(icmp4(Errno::Ehostunreach), false, true);
    error.publish(icmp6(Errno::Econnrefused), false, true);
    assert_eq!(error.take(), Errno::Econnrefused as i32);
    assert!(error.take_extended().is_some());
    assert_eq!(error.take(), Errno::Econnrefused as i32, "next ICMP record republishes");
    assert!(error.take_extended().is_some());
    assert_eq!(error.take(), 0);
}

#[test]
fn dequeuing_a_transmit_completion_leaves_the_pending_errno_alone() {
    let error = SocketError::new();
    assert!(error.publish_zerocopy(0, 1, true, false));
    error.set(Errno::Econnreset as i32);
    assert_eq!(error.peek_extended_origin(), Some(SO_EE_ORIGIN_ZEROCOPY));
    assert!(error.take_extended().is_some());
    assert_eq!(error.take(), Errno::Econnreset as i32);
}

#[test]
fn recverr_disable_purges_every_error_origin_and_keeps_transmit_completions() {
    let error = SocketError::new();
    error.set_recverr4(true);
    error.set_recverr6(true);
    error.publish(icmp4(Errno::Ehostunreach), false, true);
    error.publish(icmp6(Errno::Econnrefused), false, true);
    assert!(error.publish_local(Errno::Emsgsize as i32,
        crate::addr::IpAddr::V4(crate::Ipv4Addr::LOOPBACK), 53, 1200));
    assert!(error.publish_timestamping(SCM_TSTAMP_SND, 7, false, 2));
    assert!(error.publish_zerocopy(0, 1, true, false));
    // Turning IPv4 delivery off drops the IPv6 and local records too.
    error.set_recverr4(false);
    assert_eq!(error.take_extended().map(|entry| entry.origin), Some(SO_EE_ORIGIN_TIMESTAMPING));
    assert_eq!(error.take_extended().map(|entry| entry.origin), Some(SO_EE_ORIGIN_ZEROCOPY));
    assert!(!error.has_extended());
}

#[test]
fn recverr_disable_leaves_the_pending_errno_alone() {
    let error = SocketError::new();
    error.set_recverr4(true);
    error.publish(icmp4(Errno::Ehostunreach), false, true);
    error.set_recverr4(false);
    assert_eq!(error.take(), Errno::Ehostunreach as i32);
}

#[test]
fn receive_memory_budget_bounds_the_queue() {
    let error = SocketError::new();
    error.set_recverr4(true);
    error.set_rmem_limit(SOCK_ERRQUEUE_RECORD_OVERHEAD * 2 + 8);
    assert!(error.publish_local(Errno::Emsgsize as i32,
        crate::addr::IpAddr::V4(crate::Ipv4Addr::LOOPBACK), 1, 1200));
    assert!(error.publish_local(Errno::Emsgsize as i32,
        crate::addr::IpAddr::V4(crate::Ipv4Addr::LOOPBACK), 2, 1200));
    assert!(!error.publish_local(Errno::Emsgsize as i32,
        crate::addr::IpAddr::V4(crate::Ipv4Addr::LOOPBACK), 3, 1200),
        "a third record exceeds the budget");
    assert!(error.take_extended().is_some());
    assert!(error.publish_local(Errno::Emsgsize as i32,
        crate::addr::IpAddr::V4(crate::Ipv4Addr::LOOPBACK), 4, 1200),
        "dequeue returns the budget");
}

#[test]
fn zerocopy_completions_coalesce_only_when_identifiers_are_contiguous() {
    let error = SocketError::new();
    assert!(error.publish_zerocopy(0, 1, true, false));
    assert!(error.publish_zerocopy(1, 2, true, false));
    let merged = error.take_extended().expect("one coalesced record");
    assert_eq!((merged.info, merged.data), (0, 2));
    assert!(!error.has_extended());

    assert!(error.publish_zerocopy(10, 1, false, false));
    assert!(error.publish_zerocopy(20, 1, false, false));
    assert_eq!(error.take_extended().map(|e| (e.info, e.data)), Some((10, 10)));
    assert_eq!(error.take_extended().map(|e| (e.info, e.data)), Some((20, 20)));
}

#[test]
fn empty_zerocopy_completion_queues_nothing() {
    let error = SocketError::new();
    assert!(!error.publish_zerocopy(0, 0, true, false));
    assert!(!error.has_extended());
}
