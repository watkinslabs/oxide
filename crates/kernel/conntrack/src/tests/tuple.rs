// Tuple identity, inversion, and hashing. A tuple compared on the wrong
// fields is how a packet matches the wrong flow, so these assert that every
// distinguishing field actually distinguishes.

use crate::tuple::*;
use crate::uapi::*;

pub(crate) fn v4_tcp(s: [u8; 4], sp: u16, d: [u8; 4], dp: u16) -> Tuple {
    Tuple {
        src: TupleEnd { addr: InetAddr::v4(s), proto: ProtoPart::port(sp) },
        dst: TupleEnd { addr: InetAddr::v4(d), proto: ProtoPart::port(dp) },
        l3num: NFPROTO_IPV4, protonum: IPPROTO_TCP, zone: 0,
    }
}

pub(crate) fn v4_udp(s: [u8; 4], sp: u16, d: [u8; 4], dp: u16) -> Tuple {
    Tuple { protonum: IPPROTO_UDP, ..v4_tcp(s, sp, d, dp) }
}

pub(crate) fn v4_icmp(s: [u8; 4], d: [u8; 4], id: u16, ty: u8) -> Tuple {
    Tuple {
        src: TupleEnd { addr: InetAddr::v4(s), proto: ProtoPart::icmp(id, 0, 0) },
        dst: TupleEnd { addr: InetAddr::v4(d), proto: ProtoPart::icmp(0, ty, 0) },
        l3num: NFPROTO_IPV4, protonum: IPPROTO_ICMP, zone: 0,
    }
}

#[test]
fn invert_swaps_ends() {
    let t = v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    let r = t.invert().unwrap();
    assert_eq!(r.src.addr, t.dst.addr);
    assert_eq!(r.dst.addr, t.src.addr);
    assert_eq!(r.src.proto.port, 80);
    assert_eq!(r.dst.proto.port, 1234);
    assert_eq!(r.invert().unwrap(), t, "inversion is its own inverse");
}

#[test]
fn icmp_echo_inverts_to_reply_keeping_id() {
    let t = v4_icmp([10, 0, 0, 1], [10, 0, 0, 2], 0x4242, 8);
    let r = t.invert().unwrap();
    assert_eq!(r.dst.proto.icmp_type, 0, "echo request inverts to echo reply");
    assert_eq!(r.src.proto.port, 0x4242, "the id identifies the pair");
}

#[test]
fn icmp_error_type_has_no_inverse() {
    // A destination-unreachable is not half of a request/reply pair; giving it
    // one would create a trackable flow out of an error message.
    let t = v4_icmp([10, 0, 0, 1], [10, 0, 0, 2], 0, 3);
    assert!(t.invert().is_none());
    assert!(!icmp_valid_new(NFPROTO_IPV4, 3));
}

#[test]
fn icmpv6_echo_pair() {
    assert_eq!(icmp_invert_type(NFPROTO_IPV6, 128), Some(129));
    assert_eq!(icmp_invert_type(NFPROTO_IPV6, 129), Some(128));
    assert_eq!(icmp_invert_type(NFPROTO_IPV6, 1), None, "error type, no reply form");
    assert!(icmp_valid_new(NFPROTO_IPV6, 128));
    assert!(!icmp_valid_new(NFPROTO_IPV6, 129), "a reply cannot open a flow");
}

#[test]
fn every_field_changes_the_hash() {
    let base = v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    let h = base.hash(0x1234);
    let mut variants = alloc::vec::Vec::new();

    let mut t = base; t.src.addr = InetAddr::v4([10, 0, 0, 3]); variants.push(("src addr", t));
    let mut t = base; t.dst.addr = InetAddr::v4([10, 0, 0, 4]); variants.push(("dst addr", t));
    let mut t = base; t.src.proto.port = 1235;                  variants.push(("src port", t));
    let mut t = base; t.dst.proto.port = 443;                   variants.push(("dst port", t));
    let mut t = base; t.protonum = IPPROTO_UDP;                 variants.push(("protonum", t));
    let mut t = base; t.zone = 7;                               variants.push(("zone", t));

    for (what, t) in variants {
        assert_ne!(t.hash(0x1234), h, "{what} must participate in the hash");
        assert_ne!(t, base, "{what} must make the tuples unequal");
    }
}

#[test]
fn tuples_differing_only_in_zone_are_distinct() {
    // Two namespaces can legitimately run the same address pair. Merging them
    // would let one namespace's reply be delivered against the other's flow.
    let a = v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    let b = Tuple { zone: 1, ..a };
    assert_ne!(a, b);
}

#[test]
fn src_hash_ignores_destination_but_not_source() {
    let a = v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    let b = v4_tcp([10, 0, 0, 1], 1234, [192, 168, 1, 9], 443);
    assert_eq!(crate::hash::src_hash(&a, 9), crate::hash::src_hash(&b, 9),
        "same client must land in one bucket so a prior mapping is found");
    let c = v4_tcp([10, 0, 0, 1], 1235, [10, 0, 0, 2], 80);
    assert_ne!(crate::hash::src_hash(&a, 9), crate::hash::src_hash(&c, 9));
}

#[test]
fn same_src_compares_source_and_protocol_only() {
    let a = v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    let b = v4_tcp([10, 0, 0, 1], 1234, [8, 8, 8, 8], 53);
    assert!(a.same_src(&b));
    let c = v4_udp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    assert!(!a.same_src(&c), "protocol is part of source identity");
}

#[test]
fn reciprocal_scale_stays_in_range() {
    for v in [0u32, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
        for range in [1u32, 2, 3, 1024, 65535] {
            assert!(crate::hash::reciprocal_scale(v, range) < range);
        }
    }
}

#[test]
fn v6_addresses_use_all_sixteen_bytes() {
    let mut a = [0u8; 16]; a[15] = 1;
    let mut b = [0u8; 16]; b[15] = 2;
    let ta = Tuple {
        src: TupleEnd { addr: InetAddr::v6(a), proto: ProtoPart::port(1) },
        dst: TupleEnd { addr: InetAddr::v6(b), proto: ProtoPart::port(2) },
        l3num: NFPROTO_IPV6, protonum: IPPROTO_TCP, zone: 0,
    };
    let mut c = a; c[0] = 0xfe;
    let tb = Tuple { src: TupleEnd { addr: InetAddr::v6(c), ..ta.src }, ..ta };
    assert_ne!(ta.hash(1), tb.hash(1), "a high-order byte must reach the hash");
    assert_eq!(addr_len(NFPROTO_IPV6), 16);
    assert_eq!(addr_len(NFPROTO_IPV4), 4);
}
