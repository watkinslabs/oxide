// `IPPROTO_IPV6` option coverage: values.

use syscall::errno::Errno;
use super::super::set::{self, Action, Ipv6Sock};
use super::super::uapi::*;
use super::*;

// ---- value windows ------------------------------------------------------

#[test]
fn hop_limits_take_the_route_sentinel_through_two_fifty_five() {
    assert_eq!(set6(IPV6_UNICAST_HOPS, -1, 4), Ok(Action::UnicastHops(-1)));
    assert_eq!(set6(IPV6_UNICAST_HOPS, 0, 4), Ok(Action::UnicastHops(0)));
    assert_eq!(set6(IPV6_UNICAST_HOPS, 255, 4), Ok(Action::UnicastHops(255)));
    assert_eq!(set6(IPV6_UNICAST_HOPS, -2, 4), Err(Errno::Einval));
    assert_eq!(set6(IPV6_UNICAST_HOPS, 256, 4), Err(Errno::Einval));
    // The multicast sentinel resolves to one at admission, not at read time.
    assert_eq!(set6(IPV6_MULTICAST_HOPS, -1, 4),
        Ok(Action::MulticastHops(IPV6_DEFAULT_MCASTHOPS)));
    assert_eq!(set::admit(IPV6_MULTICAST_HOPS, 5, 4, stream(), none()),
        Err(Errno::Enoprotoopt));
}

#[test]
fn multicast_loop_admits_exactly_zero_or_one() {
    assert_eq!(set6(IPV6_MULTICAST_LOOP, 1, 4), Ok(Action::MulticastLoop(true)));
    assert_eq!(set6(IPV6_MULTICAST_LOOP, 0, 4), Ok(Action::MulticastLoop(false)));
    assert_eq!(set6(IPV6_MULTICAST_LOOP, 2, 4), Err(Errno::Einval));
    assert_eq!(set6(IPV6_MULTICAST_LOOP, -1, 4), Err(Errno::Einval));
}

#[test]
fn the_fragmentation_size_is_zero_or_at_least_the_ipv6_minimum() {
    assert_eq!(set6(IPV6_MTU, 0, 4), Ok(Action::FragSize(0)));
    assert_eq!(set6(IPV6_MTU, IPV6_MIN_MTU, 4), Ok(Action::FragSize(IPV6_MIN_MTU)));
    assert_eq!(set6(IPV6_MTU, IPV6_MIN_MTU - 1, 4), Err(Errno::Einval));
}

#[test]
fn use_min_mtu_is_not_a_live_ipv6_socket_option() {
    assert_eq!(set6(IPV6_USE_MIN_MTU, 0, 4), Err(Errno::Enoprotoopt));
    assert_eq!(set6(IPV6_USE_MIN_MTU, 1, 4), Err(Errno::Enoprotoopt));
}

#[test]
fn the_traffic_class_sentinel_resolves_to_zero() {
    assert_eq!(set6(IPV6_TCLASS, -1, 4), Ok(Action::Tclass(0)));
    assert_eq!(set6(IPV6_TCLASS, 255, 4), Ok(Action::Tclass(255)));
    assert_eq!(set6(IPV6_TCLASS, 256, 4), Err(Errno::Einval));
    assert_eq!(set6(IPV6_TCLASS, -2, 4), Err(Errno::Einval));
    // A stream socket keeps its congestion-notification bits.
    assert_eq!(set::tclass_value(0xff, 0b10, true), 0xfe);
    assert_eq!(set::tclass_value(0xff, 0b10, false), 0xff);
}

#[test]
fn v6only_is_refused_once_the_socket_holds_a_port() {
    assert_eq!(set6(IPV6_V6ONLY, 1, 4), Ok(Action::V6Only(true)));
    let bound = Ipv6Sock { inet_num: 53, ..dgram() };
    assert_eq!(set::admit(IPV6_V6ONLY, 1, 4, bound, none()), Err(Errno::Einval));
}

#[test]
fn mtu_discovery_spans_dont_through_omit() {
    for v in IPV6_PMTUDISC_DONT..=IPV6_PMTUDISC_OMIT {
        assert_eq!(set6(IPV6_MTU_DISCOVER, v, 4), Ok(Action::MtuDiscover(v)));
    }
    assert_eq!(set6(IPV6_MTU_DISCOVER, 6, 4), Err(Errno::Einval));
}
