// Range membership, port windows, and mapped-address selection.

use conntrack::tuple::{InetAddr, ProtoPart, Tuple, TupleEnd};
use conntrack::uapi::*;

use crate::range::*;
use crate::uapi::*;

pub(crate) fn tcp(s: [u8; 4], sp: u16, d: [u8; 4], dp: u16) -> Tuple {
    Tuple {
        src: TupleEnd { addr: InetAddr::v4(s), proto: ProtoPart::port(sp) },
        dst: TupleEnd { addr: InetAddr::v4(d), proto: ProtoPart::port(dp) },
        l3num: NFPROTO_IPV4, protonum: IPPROTO_TCP, zone: 0,
    }
}

pub(crate) fn icmp(s: [u8; 4], d: [u8; 4], id: u16) -> Tuple {
    Tuple {
        src: TupleEnd { addr: InetAddr::v4(s), proto: ProtoPart::icmp(id, 0, 0) },
        dst: TupleEnd { addr: InetAddr::v4(d), proto: ProtoPart::icmp(0, 8, 0) },
        l3num: NFPROTO_IPV4, protonum: IPPROTO_ICMP, zone: 0,
    }
}

#[test]
fn a_range_with_no_map_flag_constrains_no_address() {
    let t = tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    let r = NatRange { flags: 0, ..Default::default() };
    assert!(addr_in_range(&t, &r, NF_NAT_MANIP_SRC));
}

#[test]
fn address_membership_is_inclusive_at_both_ends() {
    let r = NatRange { flags: NF_NAT_RANGE_MAP_IPS,
        min_addr: InetAddr::v4([203, 0, 113, 10]),
        max_addr: InetAddr::v4([203, 0, 113, 20]), ..Default::default() };
    for (last, want) in [(9u8, false), (10, true), (15, true), (20, true), (21, false)] {
        let t = tcp([203, 0, 113, last], 1234, [10, 0, 0, 2], 80);
        assert_eq!(addr_in_range(&t, &r, NF_NAT_MANIP_SRC), want, "last octet {last}");
    }
}

#[test]
fn port_membership_uses_the_manipulated_end() {
    let r = NatRange { flags: NF_NAT_RANGE_PROTO_SPECIFIED,
        min_proto: 1000, max_proto: 2000, ..Default::default() };
    let t = tcp([10, 0, 0, 1], 1500, [10, 0, 0, 2], 80);
    assert!(port_in_range(&t, &r, NF_NAT_MANIP_SRC), "source port 1500 is in range");
    assert!(!port_in_range(&t, &r, NF_NAT_MANIP_DST), "destination port 80 is not");
}

#[test]
fn a_reversed_port_range_is_read_in_order() {
    // A rule may hand the bounds over the wrong way round; treating that as an
    // empty range would fail every allocation instead of doing the obvious.
    let r = NatRange { flags: NF_NAT_RANGE_PROTO_SPECIFIED,
        min_proto: 2000, max_proto: 1000, ..Default::default() };
    assert_eq!(r.ordered_ports(), (1000, 2000));
    let t = tcp([10, 0, 0, 1], 1500, [10, 0, 0, 2], 80);
    assert!(port_in_range(&t, &r, NF_NAT_MANIP_SRC));
}

#[test]
fn privileged_source_ports_keep_a_privileged_mapping() {
    // A service that trusts "the peer bound a reserved port" must not be
    // defeated by a NAT that maps it into the ephemeral range.
    assert_eq!(default_port_window(21),   (1, 511));
    assert_eq!(default_port_window(511),  (1, 511));
    assert_eq!(default_port_window(512),  (600, 424));
    assert_eq!(default_port_window(1023), (600, 424));
    assert_eq!(default_port_window(1024), (1024, 64512));
    assert_eq!(default_port_window(49152), (1024, 64512));
}

#[test]
fn a_destination_port_is_never_invented() {
    // The client asked for a specific service. Only an explicit range may move
    // it; otherwise there is no window to search.
    let t = tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    let none = NatRange::default();
    assert_eq!(proto_window(&t, &none, NF_NAT_MANIP_DST), None);
    assert!(proto_window(&t, &none, NF_NAT_MANIP_SRC).is_some());
    let explicit = NatRange { flags: NF_NAT_RANGE_PROTO_SPECIFIED,
        min_proto: 8080, max_proto: 8080, ..Default::default() };
    assert_eq!(proto_window(&t, &explicit, NF_NAT_MANIP_DST), Some((8080, 1)));
}

#[test]
fn icmp_allocates_from_the_whole_id_space() {
    let t = icmp([10, 0, 0, 1], [10, 0, 0, 2], 5);
    assert_eq!(proto_window(&t, &NatRange::default(), NF_NAT_MANIP_SRC), Some((0, 65536)));
    // Both manipulations act on the same id field.
    assert_eq!(manip_port(&t, NF_NAT_MANIP_SRC), 5);
    assert_eq!(manip_port(&t, NF_NAT_MANIP_DST), 5);
    let mut m = t;
    set_manip_port(&mut m, NF_NAT_MANIP_DST, 9);
    assert_eq!(m.src.proto.port, 9);
}

#[test]
fn a_protocol_with_no_port_field_has_no_window() {
    let mut t = tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    t.protonum = 47;
    assert_eq!(proto_window(&t, &NatRange::default(), NF_NAT_MANIP_SRC), None);
}

#[test]
fn a_single_address_range_always_picks_that_address() {
    let a = InetAddr::v4([203, 0, 113, 5]);
    let r = NatRange::single_addr(a, 0);
    for last in [1u8, 2, 3] {
        let t = tcp([10, 0, 0, last], 1234, [93, 184, 216, 34], 80);
        assert_eq!(pick_addr(&t, &r, NF_NAT_MANIP_SRC), a);
    }
}

#[test]
fn the_pool_choice_is_stable_for_one_client_and_lands_in_range() {
    let r = NatRange { flags: NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PERSISTENT,
        min_addr: InetAddr::v4([203, 0, 113, 0]),
        max_addr: InetAddr::v4([203, 0, 113, 255]), ..Default::default() };
    let a = tcp([10, 0, 0, 7], 1234, [93, 184, 216, 34], 80);
    let b = tcp([10, 0, 0, 7], 5678, [8, 8, 8, 8], 53);
    let pa = pick_addr(&a, &r, NF_NAT_MANIP_SRC);
    let pb = pick_addr(&b, &r, NF_NAT_MANIP_SRC);
    assert_eq!(pa, pb, "persistent mapping must not depend on the destination");
    assert!(pa.0[..4] >= [203, 0, 113, 0][..] && pa.0[..4] <= [203, 0, 113, 255][..]);
    assert_eq!(&pa.0[4..], &[0u8; 12], "an IPv4 result must not carry v6 bytes");
}

#[test]
fn without_persistent_the_destination_changes_the_choice() {
    let r = NatRange { flags: NF_NAT_RANGE_MAP_IPS,
        min_addr: InetAddr::v4([203, 0, 113, 0]),
        max_addr: InetAddr::v4([203, 0, 113, 255]), ..Default::default() };
    let a = tcp([10, 0, 0, 7], 1234, [93, 184, 216, 34], 80);
    let mut differing = alloc::vec::Vec::new();
    for last in 0..32u8 {
        let b = tcp([10, 0, 0, 7], 1234, [8, 8, 8, last], 53);
        if pick_addr(&b, &r, NF_NAT_MANIP_SRC) != pick_addr(&a, &r, NF_NAT_MANIP_SRC) {
            differing.push(last);
        }
    }
    assert!(!differing.is_empty(), "the pool must actually spread across destinations");
}

#[test]
fn every_client_lands_somewhere_in_the_pool() {
    let r = NatRange { flags: NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PERSISTENT,
        min_addr: InetAddr::v4([203, 0, 113, 16]),
        max_addr: InetAddr::v4([203, 0, 113, 31]), ..Default::default() };
    for last in 0..=255u8 {
        let t = tcp([10, 0, 0, last], 1234, [93, 184, 216, 34], 80);
        let p = pick_addr(&t, &r, NF_NAT_MANIP_SRC).0[3];
        assert!((16..=31).contains(&p), "client {last} mapped outside the pool: {p}");
    }
}

#[test]
fn netmap_keeps_the_host_part() {
    // A one-to-one prefix map: 10.0.0.0/24 onto 192.0.2.0/24 must send .7 to .7.
    let r = NatRange { flags: NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_NETMAP,
        min_addr: InetAddr::v4([192, 0, 2, 0]),
        max_addr: InetAddr::v4([192, 0, 2, 255]), ..Default::default() };
    let mapped = netmap_addr(InetAddr::v4([10, 0, 0, 7]), &r, NFPROTO_IPV4);
    assert_eq!(&mapped.0[..4], &[192, 0, 2, 7]);
}

#[test]
fn manip_accessors_touch_only_their_own_end() {
    let mut t = tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    set_manip_addr(&mut t, NF_NAT_MANIP_SRC, InetAddr::v4([203, 0, 113, 5]));
    assert_eq!(&t.src.addr.0[..4], &[203, 0, 113, 5]);
    assert_eq!(&t.dst.addr.0[..4], &[10, 0, 0, 2], "the far end must be untouched");
    set_manip_port(&mut t, NF_NAT_MANIP_DST, 8080);
    assert_eq!(t.dst.proto.port, 8080);
    assert_eq!(t.src.proto.port, 1234);
}
