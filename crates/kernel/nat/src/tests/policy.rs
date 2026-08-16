// Masquerade and redirect address selection, and the hook/manipulation
// pairing that decides whether a rule can work at all.

use conntrack::tuple::InetAddr;
use conntrack::uapi::{NFPROTO_IPV4, NFPROTO_IPV6};

use crate::policy::*;
use crate::range::NatRange;
use crate::uapi::*;

#[test]
fn masquerade_maps_onto_the_egress_address() {
    let src = InetAddr::v4([203, 0, 113, 5]);
    let r = masquerade_range(NF_INET_POST_ROUTING, Some(src), &NatRange::default()).unwrap();
    assert_eq!(r.min_addr, src);
    assert_eq!(r.max_addr, src);
    assert_eq!(r.flags & NF_NAT_RANGE_MAP_IPS, NF_NAT_RANGE_MAP_IPS);
}

#[test]
fn masquerade_preserves_a_requested_port_window() {
    let src = InetAddr::v4([203, 0, 113, 5]);
    let req = NatRange { flags: NF_NAT_RANGE_PROTO_SPECIFIED,
        min_proto: 20000, max_proto: 20999, ..Default::default() };
    let r = masquerade_range(NF_INET_POST_ROUTING, Some(src), &req).unwrap();
    assert_eq!((r.min_proto, r.max_proto), (20000, 20999));
    assert_eq!(r.flags & NF_NAT_RANGE_PROTO_SPECIFIED, NF_NAT_RANGE_PROTO_SPECIFIED);
}

#[test]
fn masquerade_without_an_egress_address_fails_rather_than_guessing() {
    assert_eq!(masquerade_range(NF_INET_POST_ROUTING, None, &NatRange::default()),
               Err(PolicyError::NoAddress));
}

#[test]
fn masquerade_is_refused_before_routing_has_chosen_an_interface() {
    // The address it maps onto is a property of the egress interface, which
    // does not exist yet at any earlier hook.
    let src = Some(InetAddr::v4([203, 0, 113, 5]));
    for hook in [NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_FORWARD, NF_INET_LOCAL_OUT] {
        assert_eq!(masquerade_range(hook, src, &NatRange::default()),
                   Err(PolicyError::WrongHook), "hook {hook}");
    }
}

#[test]
fn redirect_on_the_output_path_targets_loopback() {
    // The packet never leaves the host, so the socket it is handed to is local.
    let a = redirect_addr(NF_INET_LOCAL_OUT, NFPROTO_IPV4, None).unwrap();
    assert_eq!(&a.0[..4], &[127, 0, 0, 1]);
    let a = redirect_addr(NF_INET_LOCAL_OUT, NFPROTO_IPV6, None).unwrap();
    let mut want = [0u8; 16]; want[15] = 1;
    assert_eq!(a.0, want);
}

#[test]
fn redirect_on_the_input_path_targets_the_receiving_interface() {
    let iface = InetAddr::v4([192, 168, 1, 1]);
    let a = redirect_addr(NF_INET_PRE_ROUTING, NFPROTO_IPV4, Some(iface)).unwrap();
    assert_eq!(a, iface, "the client could plausibly have dialled this address");
    assert_eq!(redirect_addr(NF_INET_PRE_ROUTING, NFPROTO_IPV4, None),
               Err(PolicyError::NoAddress));
}

#[test]
fn redirect_is_refused_at_a_hook_where_the_destination_is_already_fixed() {
    for hook in [NF_INET_POST_ROUTING, NF_INET_LOCAL_IN, NF_INET_FORWARD] {
        assert_eq!(redirect_addr(hook, NFPROTO_IPV4, Some(InetAddr::v4([1, 1, 1, 1]))),
                   Err(PolicyError::WrongHook), "hook {hook}");
    }
}

#[test]
fn the_redirect_range_carries_the_requested_ports() {
    let req = NatRange { flags: NF_NAT_RANGE_PROTO_SPECIFIED,
        min_proto: 3128, max_proto: 3128, ..Default::default() };
    let r = redirect_range(NF_INET_LOCAL_OUT, NFPROTO_IPV4, None, &req).unwrap();
    assert_eq!((r.min_proto, r.max_proto), (3128, 3128));
    assert_eq!(&r.min_addr.0[..4], &[127, 0, 0, 1]);
    assert_eq!(r.flags & NF_NAT_RANGE_MAP_IPS, NF_NAT_RANGE_MAP_IPS);
}

#[test]
fn a_manipulation_is_only_allowed_where_it_can_take_effect() {
    // A source rewrite at pre-routing runs before routing reads the source;
    // a destination rewrite at post-routing runs after routing used it. Both
    // silently do nothing, so both are refused at configuration time.
    assert!(hook_allows_manip(NF_INET_POST_ROUTING, NF_NAT_MANIP_SRC));
    assert!(hook_allows_manip(NF_INET_LOCAL_IN, NF_NAT_MANIP_SRC));
    assert!(!hook_allows_manip(NF_INET_PRE_ROUTING, NF_NAT_MANIP_SRC));
    assert!(!hook_allows_manip(NF_INET_LOCAL_OUT, NF_NAT_MANIP_SRC));
    assert!(!hook_allows_manip(NF_INET_FORWARD, NF_NAT_MANIP_SRC));

    assert!(hook_allows_manip(NF_INET_PRE_ROUTING, NF_NAT_MANIP_DST));
    assert!(hook_allows_manip(NF_INET_LOCAL_OUT, NF_NAT_MANIP_DST));
    assert!(!hook_allows_manip(NF_INET_POST_ROUTING, NF_NAT_MANIP_DST));
    assert!(!hook_allows_manip(NF_INET_LOCAL_IN, NF_NAT_MANIP_DST));
}

#[test]
fn the_flag_mask_admits_every_defined_flag_and_nothing_else() {
    let all = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED
        | NF_NAT_RANGE_PROTO_RANDOM | NF_NAT_RANGE_PERSISTENT
        | NF_NAT_RANGE_PROTO_RANDOM_FULLY | NF_NAT_RANGE_PROTO_OFFSET
        | NF_NAT_RANGE_NETMAP;
    assert_eq!(NF_NAT_RANGE_MASK, all);
    assert_eq!(NF_NAT_RANGE_MASK & !all, 0);
    assert_eq!(NF_NAT_RANGE_PROTO_RANDOM_ALL,
               NF_NAT_RANGE_PROTO_RANDOM | NF_NAT_RANGE_PROTO_RANDOM_FULLY);
}
