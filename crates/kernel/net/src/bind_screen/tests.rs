// Hosted coverage for the nonlocal-bind screen: the pure admission table, the
// classification of a live namespace's addresses, and the two permissions that
// relax it.

use super::*;
use crate::net_ns::test_support;
use crate::sock_opts::sol_ip::flag;

const NS0: u64 = 0;

fn none() -> SockNonlocal { SockNonlocal::default() }
fn freebind() -> SockNonlocal { SockNonlocal { freebind: true, transparent: false } }
fn transparent() -> SockNonlocal { SockNonlocal { freebind: false, transparent: true } }

#[test]
fn the_v4_table_admits_every_claimable_classification() {
    for kind in [V4AddrType::Unspecified, V4AddrType::Local,
                 V4AddrType::Multicast, V4AddrType::Broadcast]
    {
        assert!(v4_admits(kind, false), "{kind:?} is claimable without a permission");
    }
    assert!(!v4_admits(V4AddrType::Other, false));
    assert!(v4_admits(V4AddrType::Other, true));
}

#[test]
fn the_v6_table_never_screens_the_wildcard_or_a_group() {
    assert!(v6_admits(V6AddrType::Unspecified, false));
    assert!(v6_admits(V6AddrType::Multicast, false));
    assert!(v6_admits(V6AddrType::Local, false));
    assert!(!v6_admits(V6AddrType::Other, false));
    assert!(v6_admits(V6AddrType::Other, true));
}

#[test]
fn either_socket_bit_or_the_namespace_knob_grants_the_permission() {
    assert!(!can_nonlocal(none(), false));
    assert!(can_nonlocal(freebind(), false));
    assert!(can_nonlocal(transparent(), false));
    assert!(can_nonlocal(none(), true));
}

#[test]
fn the_two_option_levels_share_one_permission_word() {
    // Setting the permission through either option number must be visible to
    // the screen, which reads exactly one word.
    let opts = crate::sock_opts::sol_ip::IpOpts::default();
    assert!(!opts.flag(flag::FREEBIND));
    opts.set_flag(flag::FREEBIND, true);
    let sock = SockNonlocal {
        freebind: opts.flag(flag::FREEBIND), transparent: opts.flag(flag::TRANSPARENT),
    };
    assert!(can_nonlocal(sock, false));
}

#[test]
fn a_wildcard_and_a_group_classify_without_consulting_the_tables() {
    assert_eq!(classify_v4(NS0, Ipv4Addr::ANY, None), V4AddrType::Unspecified);
    assert_eq!(classify_v4(NS0, Ipv4Addr::new(224, 0, 0, 1), None), V4AddrType::Multicast);
    assert_eq!(classify_v4(NS0, Ipv4Addr::new(255, 255, 255, 255), None), V4AddrType::Broadcast);
}

#[test]
fn an_unowned_unicast_address_is_refused_until_a_permission_relaxes_it() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let unowned = Ipv4Addr::new(198, 51, 100, 7);
    assert_eq!(classify_v4(NS0, unowned, None), V4AddrType::Other);
    assert_eq!(screen_v4(NS0, unowned, None, none()), Err(NetError::Eaddrnotavail));
    assert_eq!(screen_v4(NS0, unowned, None, freebind()), Ok(()));
    assert_eq!(screen_v4(NS0, unowned, None, transparent()), Ok(()));
    // The wildcard never needs one.
    assert_eq!(screen_v4(NS0, Ipv4Addr::ANY, None, none()), Ok(()));
}

#[test]
fn an_owned_address_classifies_local_and_a_device_binding_scopes_it() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = crate::global_stack();
    let (owner, _) = stack.register_loopback();
    let (other, _) = stack.register_loopback();
    let addr = Ipv4Addr::new(203, 0, 113, 9);
    crate::iface_addr::set_prefix(NS0, owner, addr, 24, 0);

    assert_eq!(classify_v4(NS0, addr, None), V4AddrType::Local);
    assert_eq!(classify_v4(NS0, addr, Some(owner)), V4AddrType::Local);
    // Bound to a device that does not carry the address, the claim is nonlocal.
    assert_eq!(classify_v4(NS0, addr, Some(other)), V4AddrType::Other);
    assert_eq!(screen_v4(NS0, addr, Some(other), none()), Err(NetError::Eaddrnotavail));
    assert_eq!(screen_v4(NS0, addr, Some(other), freebind()), Ok(()));
}

#[test]
fn a_directed_broadcast_address_is_claimable_without_a_permission() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = crate::global_stack();
    let (iface, _) = stack.register_loopback();
    let addr = Ipv4Addr::new(203, 0, 113, 9);
    crate::iface_addr::set_prefix(NS0, iface, addr, 24, 0);
    let cast = Ipv4Addr::new(203, 0, 113, 255);
    crate::iface_addr::insert(crate::iface_addr::Ipv4IfaceAddr {
        ns: NS0, iface, addr, peer: None, prefixlen: 24, mask: 0xffff_ff00,
        broadcast: Some(cast), scope: 0, flags: 0, proto: 0, rt_priority: 0,
        cacheinfo: crate::iface_addr::Ipv4AddrCacheInfo::PERMANENT,
    });

    assert_eq!(classify_v4(NS0, cast, None), V4AddrType::Broadcast);
    assert_eq!(screen_v4(NS0, cast, None, none()), Ok(()));
}

#[test]
fn the_namespace_knob_relaxes_the_screen_for_a_socket_holding_no_bit() {
    // A private namespace, so the knob under test is not the shared one every
    // other hosted case reads.
    let owner = test_support::allocate_namespace();
    let ns = owner.id().as_u64();
    crate::net_ns::materialize_state(&owner);
    let unowned = Ipv4Addr::new(198, 51, 100, 8);
    assert_eq!(screen_v4(ns, unowned, None, none()), Err(NetError::Eaddrnotavail));
    crate::sysctl::set_value_in(ns, NetSysctlKey::Ipv4NonlocalBind, 1).unwrap();
    assert!(v4_sysctl_nonlocal(ns));
    assert_eq!(screen_v4(ns, unowned, None, none()), Ok(()));
    crate::sysctl::set_value_in(ns, NetSysctlKey::Ipv4NonlocalBind, 0).unwrap();
    assert_eq!(screen_v4(ns, unowned, None, none()), Err(NetError::Eaddrnotavail));
}

#[test]
fn the_v6_screen_refuses_an_unowned_unicast_and_admits_every_group() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let unowned = Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(classify_v6(NS0, unowned, None), V6AddrType::Other);
    assert_eq!(screen_v6(NS0, unowned, None, none()), Err(NetError::Eaddrnotavail));
    assert_eq!(screen_v6(NS0, unowned, None, freebind()), Ok(()));
    assert_eq!(screen_v6(NS0, unowned, None, transparent()), Ok(()));

    let group = Ipv6Addr([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(classify_v6(NS0, group, None), V6AddrType::Multicast);
    assert_eq!(screen_v6(NS0, group, None, none()), Ok(()));
    assert_eq!(screen_v6(NS0, Ipv6Addr::ANY, None, none()), Ok(()));
}

#[test]
fn the_v6_namespace_knob_is_separate_from_the_v4_one() {
    let owner = test_support::allocate_namespace();
    let ns = owner.id().as_u64();
    crate::net_ns::materialize_state(&owner);
    let unowned = Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    // The IPv4 knob does not reach the IPv6 screen.
    crate::sysctl::set_value_in(ns, NetSysctlKey::Ipv4NonlocalBind, 1).unwrap();
    assert_eq!(screen_v6(ns, unowned, None, none()), Err(NetError::Eaddrnotavail));
    crate::sysctl::set_value_in(ns, NetSysctlKey::Ipv6NonlocalBind, 1).unwrap();
    assert_eq!(screen_v6(ns, unowned, None, none()), Ok(()));
}

/// Every address in the loopback prefix is bindable, not just the one the
/// loopback route carries as its preferred source.
///
/// The reference asks the local table for an address TYPE and never compares
/// the route's source annotation, which exists to pick a source address on
/// transmit. Comparing it made exactly one loopback address bindable, so the
/// stub resolver's `127.0.0.53` — the first thing it binds — was refused and
/// name resolution never started.
#[test]
fn any_loopback_address_is_local_not_only_the_routes_preferred_source() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = crate::global_stack();
    let _ = stack.register_loopback();

    for a in [Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(127, 0, 0, 53),
              Ipv4Addr::new(127, 0, 1, 1), Ipv4Addr::new(127, 255, 255, 254)] {
        assert_eq!(classify_v4(NS0, a, None), V4AddrType::Local, "{a:?} is in 127.0.0.0/8");
        assert_eq!(screen_v4(NS0, a, None, none()), Ok(()), "{a:?} binds without a permission");
    }
}

/// The screen still refuses an address no local route covers, so widening the
/// loopback case did not turn the check off.
#[test]
fn an_address_outside_every_local_route_is_still_refused() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = crate::global_stack();
    let _ = stack.register_loopback();
    let outside = Ipv4Addr::new(198, 51, 100, 7);
    assert_eq!(classify_v4(NS0, outside, None), V4AddrType::Other);
    assert_eq!(screen_v4(NS0, outside, None, none()), Err(NetError::Eaddrnotavail));
}

/// The local table answers with an address TYPE, not with "a row exists".
///
/// That table carries broadcast and anycast rows beside the local ones. A
/// broadcast row makes its address claimable — a bind may name it — but never
/// makes it an address this host owns; an anycast row makes it neither.
/// Reading the table alone classified all three as `Local`, which let an
/// address whose only local-table row is a broadcast one be used as a
/// transmit SOURCE, the other decision this classification feeds.
#[test]
fn a_local_table_row_classifies_by_route_type_not_by_the_table_it_sits_in() {
    let owner = test_support::allocate_namespace();
    let ns = owner.id().as_u64();
    crate::net_ns::materialize_state(&owner);
    let routes = &crate::global_stack().routes;
    let base = crate::route::RouteEntry {
        table: crate::policy_rule::RT_TABLE_LOCAL, dst: Ipv4Addr::ANY, prefix_len: 32,
        iface: crate::NetIfaceId::from_raw(1), gateway: None, src_hint: None,
    };
    let at = |last: u8| Ipv4Addr::new(203, 0, 113, last);
    let row = |dst, kind| {
        let mut record = crate::route::RouteRecord::kernel(crate::route::RouteEntry { dst, ..base });
        record.kind = kind;
        routes.add_record_in(ns, record);
    };

    row(at(1), crate::route::RTN_LOCAL);
    assert_eq!(classify_v4(ns, at(1), None), V4AddrType::Local);

    row(at(2), crate::route::RTN_BROADCAST);
    assert_eq!(classify_v4(ns, at(2), None), V4AddrType::Broadcast);
    // Claimable, like every broadcast classification, with no permission.
    assert_eq!(screen_v4(ns, at(2), None, none()), Ok(()));
    // Not an owned source: the transmit screen refuses it without the
    // any-source permission, which a `Local` answer would have granted.
    assert_eq!(crate::transparent::classify_v4_source(ns, at(2)),
        crate::transparent::V4Source::Foreign);

    row(at(3), crate::route::RTN_ANYCAST);
    assert_eq!(classify_v4(ns, at(3), None), V4AddrType::Other);
    assert_eq!(screen_v4(ns, at(3), None, none()), Err(NetError::Eaddrnotavail));
}
