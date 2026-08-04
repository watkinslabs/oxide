// Outbound datagram parameter selection. The mapped-destination assertions
// below are the ones `sock_v6.rs` carried inside a target-gated module, where
// they had never executed once.

use super::*;

#[test]
fn a_bound_source_wins_over_every_destination_rule() {
    let bound = Ipv4Addr::new(10, 0, 0, 5);
    assert_eq!(source_choice(bound, Ipv4Addr::new(8, 8, 8, 8)), SourceChoice::Bound(bound));
    assert_eq!(source_choice(bound, Ipv4Addr::LOOPBACK), SourceChoice::Bound(bound));
    assert_eq!(source_choice(bound, Ipv4Addr::new(224, 0, 0, 1)), SourceChoice::Bound(bound));
}

#[test]
fn a_wildcard_socket_asks_the_destination_where_its_source_comes_from() {
    assert_eq!(source_choice(Ipv4Addr::ANY, Ipv4Addr::new(224, 0, 0, 1)), SourceChoice::Multicast);
    assert_eq!(source_choice(Ipv4Addr::ANY, Ipv4Addr::LOOPBACK), SourceChoice::Loopback);
    assert_eq!(source_choice(Ipv4Addr::ANY, Ipv4Addr::new(127, 0, 0, 53)), SourceChoice::Loopback);
    // A remote peer answers the route's source, never the loopback address —
    // sending every datagram from 127.0.0.1 makes a reply unroutable.
    assert_eq!(source_choice(Ipv4Addr::ANY, Ipv4Addr::new(10, 0, 2, 3)), SourceChoice::Route);
}

#[test]
fn the_ttl_a_datagram_carries_depends_on_whether_it_is_multicast() {
    assert_eq!(ipv4_ttl(1, 64, true), 1, "multicast takes IP_MULTICAST_TTL");
    assert_eq!(ipv4_ttl(1, 64, false), 64, "unicast takes IP_TTL");
    assert_eq!(ipv4_ttl(32, 64, true), 32);
    // The unicast option's negative sentinel is resolved against route metrics
    // after the sender has selected its route.
    assert_eq!(ipv4_ttl(1, -1, false), 0);
    // A set value of zero is a real value, not "unset".
    assert_eq!(ipv4_ttl(1, 0, false), 0);
}

#[test]
fn the_hop_limit_defaults_differ_between_multicast_and_unicast() {
    assert_eq!(ipv6_hop_limit(-1, -1, true), 1, "an unset multicast hop limit stays on-link");
    assert_eq!(ipv6_hop_limit(-1, -1, false), crate::ipv6::IPV6_DEFAULT_HOP_LIMIT);
    assert_eq!(ipv6_hop_limit(8, 255, true), 8);
    assert_eq!(ipv6_hop_limit(8, 255, false), 255);
    // A set value of zero is a real value, not "unset".
    assert_eq!(ipv6_hop_limit(0, -1, true), 0);
}

#[test]
fn an_unset_traffic_class_is_zero_and_does_not_consult_the_destination() {
    assert_eq!(ipv6_tclass(-1), 0);
    assert_eq!(ipv6_tclass(0), 0);
    assert_eq!(ipv6_tclass(0x28), 0x28);
}

#[test]
fn a_multicast_send_with_loopback_off_reaches_nobody_but_still_succeeds() {
    assert!(multicast_delivers_nowhere(true, false, true));
    assert!(!multicast_delivers_nowhere(true, true, true), "loopback on delivers it");
    assert!(!multicast_delivers_nowhere(true, false, false), "a real interface carries it");
    assert!(!multicast_delivers_nowhere(false, false, true), "unicast is not affected");
}

#[test]
fn the_loopback_drain_runs_for_everything_but_a_suppressed_multicast_send() {
    assert!(drains_loopback(false, false), "a unicast send always drains");
    assert!(drains_loopback(false, true));
    assert!(drains_loopback(true, true));
    assert!(!drains_loopback(true, false), "nothing was queued to drain");
}

#[test]
fn a_v6only_socket_refuses_a_mapped_datagram_destination() {
    let mapped = Ipv6Addr::from_v4_mapped(Ipv4Addr::new(192, 0, 2, 1));
    assert_eq!(validate_udp6_mapped_destination(mapped, true), Err(NetError::Enetunreach));
    assert_eq!(validate_udp6_mapped_destination(mapped, false), Ok(()));
    assert_eq!(validate_udp6_mapped_destination(Ipv6Addr::LOOPBACK, true), Ok(()),
        "a native address is not a mapped one");
    assert_eq!(validate_udp6_mapped_destination(Ipv6Addr::LOOPBACK, false), Ok(()));
}

#[test]
fn a_mapped_stream_destination_selects_the_ipv4_stack_unless_v6only() {
    let v4 = Ipv4Addr::new(198, 51, 100, 7);
    let mapped = Ipv6Addr::from_v4_mapped(v4);
    assert_eq!(tcp6_mapped_destination(mapped, true), Err(NetError::Enetunreach));
    assert_eq!(tcp6_mapped_destination(mapped, false), Ok(Some(v4)));
    assert_eq!(tcp6_mapped_destination(Ipv6Addr::LOOPBACK, false), Ok(None), "stays native");
    assert_eq!(tcp6_mapped_destination(Ipv6Addr::LOOPBACK, true), Ok(None));
}

/// The socket-level half of the same contract. `crate::sock` is available
/// under `cfg(test)`, so these run hosted — but they may only be reached from
/// a test module, since a plain `cargo check -p net` has no socket type.
#[test]
fn a_refused_mapped_send_leaves_the_socket_unbound() {
    let mapped = Ipv6Addr::from_v4_mapped(Ipv4Addr::new(192, 0, 2, 1));
    let sock = crate::sock::InetSocket::new_udp6();
    sock.opts.ipv6_v6only.store(1, core::sync::atomic::Ordering::Release);
    assert_eq!(crate::sock_v6::sendto_v6(&sock, mapped, 53, 0, b"query"),
        Err(NetError::Enetunreach));
    // The rejection precedes the ephemeral bind, so a refused send costs the
    // socket nothing — a later send may still pick its own port.
    assert!(sock.local_port.lock().is_none());
}
