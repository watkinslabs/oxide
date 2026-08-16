// UDP stream promotion and ICMP admission.

use crate::proto::icmp::{self, GenericSysctl, IcmpSysctl};
use crate::proto::udp::*;
use crate::uapi::*;
use super::tuple::v4_icmp;

#[test]
fn unreplied_udp_gets_the_short_timeout() {
    let mut t = UdpTrack::default();
    let r = packet(&mut t, false, false, 100, &UdpSysctl::default());
    assert_eq!(r.timeout, UDP_TIMEOUTS[UDP_CT_UNREPLIED]);
    assert!(!r.set_assured);
}

#[test]
fn a_reply_alone_does_not_make_a_stream() {
    let mut t = UdpTrack::default();
    packet(&mut t, false, false, 100, &UdpSysctl::default());
    // The reply arrives immediately; a single exchange is a query, not a
    // stream, and must not earn the two-minute timeout.
    let r = packet(&mut t, true, false, 101, &UdpSysctl::default());
    assert_eq!(r.timeout, UDP_TIMEOUTS[UDP_CT_UNREPLIED]);
    assert!(!r.set_assured);
}

#[test]
fn traffic_past_the_grace_period_becomes_a_stream() {
    let mut t = UdpTrack::default();
    packet(&mut t, false, false, 100, &UdpSysctl::default());
    let r = packet(&mut t, true, false, 100 + UDP_STREAM_SECS as u64 + 1,
                   &UdpSysctl::default());
    assert_eq!(r.timeout, UDP_TIMEOUTS[UDP_CT_REPLIED]);
    assert!(r.set_assured);
    // Assured is set once, not on every later packet.
    let r2 = packet(&mut t, true, true, 200, &UdpSysctl::default());
    assert!(!r2.set_assured);
}

#[test]
fn udp_timeouts_are_the_documented_defaults() {
    assert_eq!(UDP_TIMEOUTS[UDP_CT_UNREPLIED], 30);
    assert_eq!(UDP_TIMEOUTS[UDP_CT_REPLIED], 120);
}

#[test]
fn only_request_types_open_an_icmp_flow() {
    let s = IcmpSysctl::default();
    let echo = v4_icmp([10, 0, 0, 1], [10, 0, 0, 2], 1, 8);
    assert_eq!(icmp::packet(&echo, false, &s), Some(30));
    // An unsolicited echo REPLY must not create state a later real request
    // would then match against.
    let reply = v4_icmp([10, 0, 0, 1], [10, 0, 0, 2], 1, 0);
    assert_eq!(icmp::packet(&reply, false, &s), None);
    // Once confirmed, the reply direction is of course tracked.
    assert_eq!(icmp::packet(&reply, true, &s), Some(30));
}

#[test]
fn icmp_error_types_are_related_not_new() {
    for ty in [3u8, 4, 5, 11, 12] { assert!(icmp::is_error(NFPROTO_IPV4, ty)); }
    assert!(!icmp::is_error(NFPROTO_IPV4, 8));
    for ty in [1u8, 2, 3, 4] { assert!(icmp::is_error(NFPROTO_IPV6, ty)); }
    assert!(!icmp::is_error(NFPROTO_IPV6, 128));
}

#[test]
fn generic_protocols_get_the_long_timeout() {
    assert_eq!(icmp::generic_packet(&GenericSysctl::default()), 600);
}
