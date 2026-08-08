// Source selection for an IPv6 active open.
//
// A connection's local address is settled at connect time: the route the
// destination selects names the source, and every segment the connection ever
// sends carries that address verbatim. A wildcard-bound socket that skipped
// this step put the unspecified address in the SYN's source field, which no
// peer can answer.

use super::*;
use crate::addr::Ipv6Addr;
use super::super::stack;

const REMOTE: Ipv6Addr = Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
const OWNED: Ipv6Addr = Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);

fn routed_to_remote() -> crate::NetIfaceId {
    let stack = stack();
    let (iface, _) = stack.register_loopback();
    stack.add_v6_addr_meta(iface, OWNED, 64, u32::MAX, u32::MAX);
    stack.routes6.add(crate::route6::Route6Entry {
        table: crate::policy_rule::RT_TABLE_MAIN, dst: REMOTE, prefix_len: 128, iface,
        gateway: None, src_hint: None, origin: crate::route6::Route6Origin::Static,
    });
    iface
}

#[test]
fn a_wildcard_bound_active_open_resolves_a_source_from_the_route() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let _iface = routed_to_remote();
    let sock = InetSocket::new_tcp6();

    let selected = v6_connect_source(&sock, REMOTE).unwrap();
    assert_ne!(selected, Ipv6Addr::ANY,
        "a connect must not leave the unspecified address as its source");
    assert_eq!(selected, OWNED);
}

#[test]
fn the_routes_preferred_source_outranks_address_selection() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = stack();
    let (iface, _) = stack.register_loopback();
    let preferred = Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2a]);
    stack.add_v6_addr_meta(iface, OWNED, 64, u32::MAX, u32::MAX);
    stack.add_v6_addr_meta(iface, preferred, 64, u32::MAX, u32::MAX);
    stack.routes6.add(crate::route6::Route6Entry {
        table: crate::policy_rule::RT_TABLE_MAIN, dst: REMOTE, prefix_len: 128, iface,
        gateway: None, src_hint: Some(preferred), origin: crate::route6::Route6Origin::Static,
    });
    let sock = InetSocket::new_tcp6();

    assert_eq!(v6_connect_source(&sock, REMOTE), Ok(preferred));
}

#[test]
fn a_destination_no_route_covers_is_unreachable_not_unspecified() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let sock = InetSocket::new_tcp6();
    let unrouted = Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(v6_connect_source(&sock, unrouted), Err(NetError::Enetunreach));
}
