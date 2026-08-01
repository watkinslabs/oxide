// Hosted coverage for the local-port decisions: which window is in effect and
// whether a bind allocates from it.

use super::*;
use crate::sock_opts::sol_ip::flag;

fn ns_window() -> Range { Range::new(32_768, 60_999).unwrap() }

fn packed(lo: u16, hi: u16) -> u32 { (lo as u32) | ((hi as u32) << 16) }

#[test]
fn an_unset_socket_window_follows_the_namespace() {
    assert_eq!(effective_range(0, ns_window()), ns_window());
}

#[test]
fn a_full_socket_window_overrides_the_namespace_on_both_sides() {
    assert_eq!(effective_range(packed(40_000, 40_100), ns_window()),
        Range::new(40_000, 40_100).unwrap());
}

#[test]
fn a_half_open_socket_window_keeps_the_namespace_on_the_unnamed_side() {
    let ns = ns_window();
    assert_eq!(effective_range(packed(40_000, 0), ns), Range::new(40_000, ns.end).unwrap());
    assert_eq!(effective_range(packed(0, 40_100), ns), Range::new(ns.start, 40_100).unwrap());
}

#[test]
fn an_inverted_socket_window_falls_back_to_the_namespace() {
    // A half-open request can invert against the namespace bound it inherits;
    // the allocator must still be handed a usable window.
    let ns = ns_window();
    assert_eq!(effective_range(packed(0, 100), ns), ns);
    assert_eq!(effective_range(packed(61_000, 0), ns), ns);
}

#[test]
fn a_single_port_socket_window_is_a_window_of_one() {
    let window = effective_range(packed(40_000, 40_000), ns_window());
    assert_eq!(window.count(), 1);
    assert_eq!(window.start, 40_000);
}

#[test]
fn a_named_port_always_allocates_and_only_the_option_defers_an_unnamed_one() {
    assert!(!defers_port(0, false));
    assert!(defers_port(0, true));
    assert!(!defers_port(1024, true));
    assert!(!defers_port(1024, false));
}

#[test]
fn the_deferral_reads_the_option_the_write_table_stores() {
    let opts = crate::sock_opts::sol_ip::IpOpts::default();
    assert!(!defers_port(0, opts.flag(flag::BIND_ADDRESS_NO_PORT)));
    opts.set_flag(flag::BIND_ADDRESS_NO_PORT, true);
    assert!(defers_port(0, opts.flag(flag::BIND_ADDRESS_NO_PORT)));
}

#[test]
fn the_socket_window_reaches_a_live_namespace_lookup() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let ns = owner.id().as_u64();
    crate::net_ns::materialize_state(&owner);
    assert_eq!(range_in(ns, 0), crate::ephemeral::range_in(ns));
    assert_eq!(range_in(ns, packed(40_000, 40_100)), Range::new(40_000, 40_100));
    // A dead numeric identity has no window at all.
    assert_eq!(range_in(u64::MAX, packed(40_000, 40_100)), None);
}

#[test]
fn the_udp_allocator_draws_from_the_socket_window_not_the_namespace_one() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let owner = crate::net_ns::test_support::allocate_namespace();
    crate::net_ns::materialize_state(&owner);
    // A namespace window disjoint from the socket's, so the result names which
    // one the allocator consulted.
    let ns_window = (50_000u16, 50_009u16);
    crate::ephemeral::set_range_in(owner.id().as_u64(), ns_window.0, ns_window.1).unwrap();
    let socket_owner = crate::SocketOwner::root(owner.clone(), 0);
    let window = (40_100u16, 40_109u16);
    let (port, _endpoint) = crate::sock::alloc_ephemeral_udp4_owned(
        socket_owner, crate::Ipv4Addr::ANY, alloc::sync::Arc::new(crate::SocketError::new()),
        None, atomic_zero(), atomic_zero(), atomic_zero(), atomic_zero(),
        alloc::sync::Arc::new(sync::Spinlock::new(None)),
        alloc::sync::Arc::new(crate::bpf_filter::SocketFilter::new()),
        alloc::sync::Arc::new(crate::mcast_filter::SocketMcast::new()),
        packed(window.0, window.1),
    ).expect("a ten-port window has room for one allocation");
    assert!((window.0..=window.1).contains(&port),
        "port {port} is outside the socket's own window {window:?}");
    assert!(!(ns_window.0..=ns_window.1).contains(&port),
        "the namespace window was consulted instead of the socket's");
}

fn atomic_zero() -> alloc::sync::Arc<core::sync::atomic::AtomicI32> {
    alloc::sync::Arc::new(core::sync::atomic::AtomicI32::new(0))
}

#[test]
fn the_tcp_reservation_draws_from_the_socket_window_too() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let owner = crate::net_ns::test_support::allocate_namespace();
    crate::net_ns::materialize_state(&owner);
    let ns_window = (50_100u16, 50_109u16);
    crate::ephemeral::set_range_in(owner.id().as_u64(), ns_window.0, ns_window.1).unwrap();
    let window = (40_200u16, 40_209u16);
    let bind = crate::global_stack().tcp_reserve_owned(
        crate::SocketOwner::root(owner.clone(), 0),
        crate::addr::IpAddr::V4(crate::Ipv4Addr::ANY), 0, None, false, false, false,
        packed(window.0, window.1),
    ).expect("a ten-port window has room for one reservation");
    let port = bind.local.port;
    assert!((window.0..=window.1).contains(&port),
        "port {port} is outside the socket's own window {window:?}");
    assert!(!(ns_window.0..=ns_window.1).contains(&port));
    crate::global_stack().tcp_release_bind(&bind);
}
