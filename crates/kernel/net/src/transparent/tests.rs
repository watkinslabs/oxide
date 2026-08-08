// Hosted coverage for the transparent-proxy permission beyond the bind screen:
// the shared local-input decision both families run, and the IPv4 transmit
// source screen the permission relaxes.

use super::*;
use crate::bind_screen::SockNonlocal;
use crate::Ipv4Addr;

fn none() -> SockNonlocal { SockNonlocal::default() }
fn freebind() -> SockNonlocal { SockNonlocal { freebind: true, transparent: false } }
fn transparent() -> SockNonlocal { SockNonlocal { freebind: false, transparent: true } }

#[test]
fn only_the_transparent_permission_or_a_written_header_grants_a_foreign_source() {
    assert!(!any_source(none(), false));
    // A nonlocal BIND is not a nonlocal SOURCE: freebind buys the address, not
    // the right to put it on the wire.
    assert!(!any_source(freebind(), false));
    assert!(any_source(transparent(), false));
    assert!(any_source(none(), true));
    assert!(any_source(transparent(), true));
}

#[test]
fn an_always_local_destination_consults_neither_table() {
    let mut route_asked = false;
    let mut owned_asked = false;
    assert!(delivers_locally(true, || { route_asked = true; false },
        || { owned_asked = true; false }));
    assert!(!route_asked, "an always-local destination must not need the route table");
    assert!(!owned_asked, "an always-local destination must not need the address table");
}

#[test]
fn a_local_route_delivers_an_address_no_interface_owns() {
    // The transparent-proxy delivery shape: policy routing selects local input
    // for a foreign destination, and no interface is configured with it.
    assert!(delivers_locally(false, || true, || false));
}

#[test]
fn an_owned_address_still_delivers_with_no_route_covering_it() {
    assert!(delivers_locally(false, || false, || true));
}

#[test]
fn a_foreign_destination_neither_routed_nor_owned_is_not_delivered() {
    assert!(!delivers_locally(false, || false, || false));
}

#[test]
fn the_local_route_is_asked_before_the_address_table() {
    let order = core::cell::RefCell::new(alloc::vec::Vec::new());
    assert!(delivers_locally(false, || { order.borrow_mut().push("route"); true },
        || { order.borrow_mut().push("owned"); true }));
    assert_eq!(*order.borrow(), alloc::vec!["route"], "the routing decision has the first word");
}

#[test]
fn an_unspecified_source_is_always_accepted() {
    for any in [false, true] {
        for fans_out in [false, true] {
            assert_eq!(screen_v4_source(V4Source::Unspecified, fans_out, false, any), Ok(()));
        }
    }
}

#[test]
fn a_malformed_source_is_rejected_even_with_the_permission() {
    for src in [V4Source::Multicast, V4Source::LimitedBroadcast] {
        assert_eq!(screen_v4_source(src, false, false, true), Err(crate::NetError::Einval));
        assert_eq!(screen_v4_source(src, false, false, false), Err(crate::NetError::Einval));
    }
}

#[test]
fn a_foreign_source_is_unreachable_without_the_permission_and_sent_with_it() {
    assert_eq!(screen_v4_source(V4Source::Foreign, false, false, false),
        Err(crate::NetError::Enetunreach));
    assert_eq!(screen_v4_source(V4Source::Foreign, false, false, true), Ok(()));
    assert_eq!(screen_v4_source(V4Source::Local, false, false, false), Ok(()));
}

#[test]
fn a_fanout_destination_with_no_pinned_interface_needs_an_owned_source() {
    // The send takes its interface FROM the source address, so the permission
    // cannot excuse a source no interface is configured with.
    assert_eq!(screen_v4_source(V4Source::Foreign, true, false, true),
        Err(crate::NetError::Enetunreach));
    // Pinning an interface removes the reason: the source no longer chooses it.
    assert_eq!(screen_v4_source(V4Source::Foreign, true, true, true), Ok(()));
    assert_eq!(screen_v4_source(V4Source::Foreign, true, true, false),
        Err(crate::NetError::Enetunreach));
    assert_eq!(screen_v4_source(V4Source::Local, true, false, false), Ok(()));
}

#[test]
fn source_classification_names_the_malformed_and_wildcard_cases_without_a_table() {
    assert_eq!(classify_v4_source(0, Ipv4Addr::ANY), V4Source::Unspecified);
    assert_eq!(classify_v4_source(0, Ipv4Addr::new(224, 0, 0, 1)), V4Source::Multicast);
    assert_eq!(classify_v4_source(0, Ipv4Addr::new(255, 255, 255, 255)),
        V4Source::LimitedBroadcast);
}

#[test]
fn the_screen_and_the_bind_screen_share_one_definition_of_a_local_address() {
    // An address the bind screen calls Local is a source the transmit screen
    // accepts with no permission; anything else needs one. Loopback is local
    // in every namespace through the local-table route the loopback device
    // installs, which is the same lookup the bind screen makes.
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = crate::global_stack();
    let (iface, _) = stack.register_loopback();
    let owned = Ipv4Addr::new(203, 0, 113, 9);
    crate::iface_addr::set_prefix(0, iface, owned, 24, 0);
    assert_eq!(crate::bind_screen::classify_v4(0, owned, None),
        crate::bind_screen::V4AddrType::Local);
    assert_eq!(classify_v4_source(0, owned), V4Source::Local);
    assert_eq!(screen_v4_socket_source(0, owned, Ipv4Addr::new(203, 0, 113, 20),
        false, none(), false), Ok(()));
}

#[test]
fn a_socket_bound_through_freebind_cannot_source_from_its_own_bound_address() {
    // The pair that makes the two permissions distinguishable: both bind the
    // foreign address, only one may put it on the wire.
    let _domain = crate::hosted_fixture::init_net_domain();
    let foreign = Ipv4Addr::new(198, 51, 100, 7);
    let peer = Ipv4Addr::new(203, 0, 113, 9);
    assert_eq!(crate::bind_screen::screen_v4(0, foreign, None, freebind()), Ok(()));
    assert_eq!(crate::bind_screen::screen_v4(0, foreign, None, transparent()), Ok(()));
    assert_eq!(screen_v4_socket_source(0, foreign, peer, false, freebind(), false),
        Err(crate::NetError::Enetunreach));
    assert_eq!(screen_v4_socket_source(0, foreign, peer, false, transparent(), false), Ok(()));
    // A header-including raw socket writes the source itself and is unscreened.
    assert_eq!(screen_v4_socket_source(0, foreign, peer, false, none(), true), Ok(()));
}

#[test]
fn an_ipv6_source_a_socket_selected_is_never_overwritten() {
    // IPv6 route output has no owned-source test at all: an explicit source is
    // what leaves the host, foreign or not, with no permission consulted.
    let foreign = crate::Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
    assert!(v6_source_is_verbatim(foreign));
    assert!(!v6_source_is_verbatim(crate::Ipv6Addr::ANY));
}
