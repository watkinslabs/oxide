// Expectation matching and admission. A mask that wildcards too much admits
// a connection nobody announced, which is the whole risk of helpers.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::entry::Conn;
use crate::expect::*;
use crate::tuple::{InetAddr, ProtoPart};
use super::tuple::{v4_tcp, v4_udp};

fn master() -> Arc<Conn> {
    let orig = v4_tcp([10, 0, 0, 1], 5000, [10, 0, 0, 2], 21);
    Arc::new(Conn::new(1, orig, orig.invert().unwrap(), 0))
}

fn exp(m: &Arc<Conn>, tuple: crate::Tuple, mask: TupleMask) -> Expectation {
    Expectation {
        tuple, mask, master: m.clone(), class: 0, flags: 0, timeout: 1000,
        helper: Some(String::from("ftp")), dir: 0,
        saved_proto: ProtoPart::port(0), saved_addr: InetAddr::default(),
    }
}

#[test]
fn a_dst_only_mask_matches_any_source_port() {
    let m = master();
    let t = ExpectTable::new(3);
    let announced = v4_tcp([10, 0, 0, 1], 0, [10, 0, 0, 2], 20);
    t.insert(exp(&m, announced, TupleMask::dst_only()), 0, 0, 0).unwrap();
    // The client's ephemeral source port cannot be predicted.
    assert!(t.find(&v4_tcp([10, 0, 0, 1], 49152, [10, 0, 0, 2], 20), 0).is_some());
    assert!(t.find(&v4_tcp([10, 0, 0, 1], 33333, [10, 0, 0, 2], 20), 0).is_some());
    // But the destination port is not wildcarded.
    assert!(t.find(&v4_tcp([10, 0, 0, 1], 49152, [10, 0, 0, 2], 21), 0).is_none());
    // Nor is the source address.
    assert!(t.find(&v4_tcp([10, 9, 9, 9], 49152, [10, 0, 0, 2], 20), 0).is_none());
}

#[test]
fn protocol_and_family_are_never_wildcarded() {
    let m = master();
    let t = ExpectTable::new(3);
    let announced = v4_tcp([10, 0, 0, 1], 0, [10, 0, 0, 2], 20);
    t.insert(exp(&m, announced, TupleMask::dst_only()), 0, 0, 0).unwrap();
    // A UDP flow to the same address pair must not satisfy a TCP expectation.
    assert!(t.find(&v4_udp([10, 0, 0, 1], 49152, [10, 0, 0, 2], 20), 0).is_none());
}

#[test]
fn zones_do_not_cross() {
    let m = master();
    let t = ExpectTable::new(3);
    let announced = v4_tcp([10, 0, 0, 1], 0, [10, 0, 0, 2], 20);
    t.insert(exp(&m, announced, TupleMask::dst_only()), 0, 0, 0).unwrap();
    let mut other = v4_tcp([10, 0, 0, 1], 49152, [10, 0, 0, 2], 20);
    other.zone = 4;
    assert!(t.find(&other, 0).is_none());
}

#[test]
fn an_expired_expectation_does_not_fire() {
    let m = master();
    let t = ExpectTable::new(3);
    let announced = v4_tcp([10, 0, 0, 1], 0, [10, 0, 0, 2], 20);
    let mut e = exp(&m, announced, TupleMask::dst_only());
    e.timeout = 100;
    t.insert(e, 0, 0, 0).unwrap();
    assert!(t.find(&v4_tcp([10, 0, 0, 1], 49152, [10, 0, 0, 2], 20), 99).is_some());
    assert!(t.find(&v4_tcp([10, 0, 0, 1], 49152, [10, 0, 0, 2], 20), 101).is_none(),
        "a stale announcement must not keep a hole open");
}

#[test]
fn an_overlapping_announcement_is_refused() {
    let a = master();
    let b = Arc::new(Conn::new(2,
        v4_tcp([10, 0, 0, 3], 5000, [10, 0, 0, 2], 21),
        v4_tcp([10, 0, 0, 2], 21, [10, 0, 0, 3], 5000), 0));
    let t = ExpectTable::new(3);
    let announced = v4_tcp([10, 0, 0, 1], 0, [10, 0, 0, 2], 20);
    t.insert(exp(&a, announced, TupleMask::dst_only()), 0, 0, 0).unwrap();
    // A second master announcing a connection indistinguishable from the
    // first: an arriving packet could not be attributed.
    let r = t.insert(exp(&b, announced, TupleMask::dst_only()), 0, 0, 0);
    assert_eq!(r, Err(ExpectError::Busy));
}

#[test]
fn re_announcing_the_same_expectation_replaces_it() {
    let m = master();
    let t = ExpectTable::new(3);
    let announced = v4_tcp([10, 0, 0, 1], 0, [10, 0, 0, 2], 20);
    t.insert(exp(&m, announced, TupleMask::dst_only()), 0, 0, 0).unwrap();
    t.insert(exp(&m, announced, TupleMask::dst_only()), 0, 0, 0).unwrap();
    assert_eq!(t.count(), 1, "a refresh must not consume a second slot");
}

#[test]
fn a_different_class_for_the_same_tuple_is_refused() {
    let m = master();
    let t = ExpectTable::new(3);
    let announced = v4_tcp([10, 0, 0, 1], 0, [10, 0, 0, 2], 20);
    t.insert(exp(&m, announced, TupleMask::dst_only()), 0, 0, 0).unwrap();
    let mut e = exp(&m, announced, TupleMask::dst_only());
    e.class = 1;
    assert_eq!(t.insert(e, 0, 0, 0), Err(ExpectError::Already));
}

#[test]
fn the_per_master_budget_is_enforced() {
    let m = master();
    let t = ExpectTable::new(3);
    let announced = v4_tcp([10, 0, 0, 1], 0, [10, 0, 0, 2], 20);
    // Budget of two, already holding two.
    let r = t.insert(exp(&m, announced, TupleMask::dst_only()), 2, 2, 0);
    assert_eq!(r, Err(ExpectError::TooMany));
    // With one held it goes in.
    assert!(t.insert(exp(&m, announced, TupleMask::dst_only()), 2, 1, 0).is_ok());
}

#[test]
fn the_global_ceiling_is_enforced() {
    let m = master();
    let t = ExpectTable::new(3);
    let mut ok = 0;
    let mut refused = 0;
    for p in 0..(t.max as u16 + 8) {
        let announced = v4_tcp([10, 0, 0, 1], 0, [10, 0, 0, 2], 1000 + p);
        match t.insert(exp(&m, announced, TupleMask::exact()), 0, 0, 0) {
            Ok(()) => ok += 1,
            Err(ExpectError::TooMany) => refused += 1,
            Err(e) => panic!("{e:?}"),
        }
    }
    assert_eq!(ok, t.max);
    assert!(refused > 0, "the ceiling must actually bite");
}

#[test]
fn losing_the_master_drops_its_announcements() {
    let m = master();
    let t = ExpectTable::new(3);
    for p in 0..4u16 {
        let announced = v4_tcp([10, 0, 0, 1], 0, [10, 0, 0, 2], 2000 + p);
        t.insert(exp(&m, announced, TupleMask::exact()), 0, 0, 0).unwrap();
    }
    assert_eq!(t.purge_master(&m), 4);
    assert_eq!(t.count(), 0);
}

#[test]
fn the_mask_compare_itself_refuses_a_foreign_zone_or_protocol() {
    // Asserted directly on the comparison rather than through the table: the
    // bucket hash also separates these, so a table-level test passes even when
    // the compare has stopped looking at them.
    let announced = v4_tcp([10, 0, 0, 1], 0, [10, 0, 0, 2], 20);
    let m = TupleMask::dst_only();
    let ok = v4_tcp([10, 0, 0, 1], 49152, [10, 0, 0, 2], 20);
    assert!(m.matches(&announced, &ok));

    let mut other_zone = ok; other_zone.zone = 3;
    assert!(!m.matches(&announced, &other_zone));

    let other_proto = v4_udp([10, 0, 0, 1], 49152, [10, 0, 0, 2], 20);
    assert!(!m.matches(&announced, &other_proto));

    let mut other_family = ok;
    other_family.l3num = crate::uapi::NFPROTO_IPV6;
    assert!(!m.matches(&announced, &other_family));
}

#[test]
fn mask_intersection_is_field_wise() {
    let a = TupleMask { src_addr: InetAddr::v4([255, 255, 255, 255]),
                        dst_addr: InetAddr::v4([255, 255, 255, 255]),
                        src_port: 0xffff, dst_port: 0xffff };
    let b = TupleMask { src_port: 0, ..a };
    let i = a.intersect(&b);
    assert_eq!(i.src_port, 0);
    assert_eq!(i.dst_port, 0xffff);
}

#[test]
fn a_fully_exact_mask_admits_only_the_announced_tuple() {
    let m = master();
    let t = ExpectTable::new(3);
    let announced = v4_tcp([10, 0, 0, 1], 49152, [10, 0, 0, 2], 20);
    t.insert(exp(&m, announced, TupleMask::exact()), 0, 0, 0).unwrap();
    assert!(t.find(&announced, 0).is_some());
    let mut off_by_one = announced;
    off_by_one.src.proto.port += 1;
    assert!(t.find(&off_by_one, 0).is_none());
}

#[test]
fn snapshot_lists_what_was_inserted() {
    let m = master();
    let t = ExpectTable::new(3);
    let announced = v4_tcp([10, 0, 0, 1], 0, [10, 0, 0, 2], 20);
    t.insert(exp(&m, announced, TupleMask::dst_only()), 0, 0, 0).unwrap();
    let s: Vec<_> = t.snapshot();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].tuple, announced);
}
