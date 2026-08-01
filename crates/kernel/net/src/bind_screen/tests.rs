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
        broadcast: Some(cast), scope: 0, flags: 0,
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
