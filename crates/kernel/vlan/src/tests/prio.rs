use crate::prio::PrioMaps;
use crate::tci::{encode, qos_mask};

#[test]
fn every_code_point_maps_independently() {
    let mut m = PrioMaps::new();
    for pcp in 0u32..8 { m.set_ingress(100 + pcp, pcp); }
    for pcp in 0u32..8 {
        assert_eq!(m.ingress(pcp), 100 + pcp);
        assert_eq!(m.ingress_for_tci(encode(42, pcp as u8)), 100 + pcp);
    }
    assert_eq!(m.nr_ingress(), 8);
}

#[test]
fn unmapped_code_point_is_priority_zero() {
    let m = PrioMaps::new();
    for pcp in 0u32..8 { assert_eq!(m.ingress(pcp), 0); }
    assert_eq!(m.nr_ingress(), 0);
}

#[test]
fn code_point_index_wraps_at_eight() {
    let mut m = PrioMaps::new();
    m.set_ingress(9, 8);
    assert_eq!(m.ingress(0), 9, "code point 8 is code point 0");
}

#[test]
fn writing_zero_clears_a_code_point() {
    let mut m = PrioMaps::new();
    m.set_ingress(5, 3);
    assert_eq!(m.nr_ingress(), 1);
    m.set_ingress(0, 3);
    assert_eq!(m.ingress(3), 0);
    assert_eq!(m.nr_ingress(), 0);
}

#[test]
fn egress_returns_the_pre_shifted_value() {
    let mut m = PrioMaps::new();
    m.set_egress(1, 5);
    assert_eq!(m.egress_mask(1), qos_mask(5));
    assert_eq!(m.egress_mask(1), 0xa000);
}

#[test]
fn unmapped_priority_contributes_nothing() {
    let mut m = PrioMaps::new();
    m.set_egress(1, 5);
    for p in [0u32, 2, 17, 0xffff_ffff] { assert_eq!(m.egress_mask(p), 0, "priority {p}"); }
}

#[test]
fn priorities_sharing_a_bucket_stay_distinct() {
    let mut m = PrioMaps::new();
    // 1, 17 and 33 all select bucket 1.
    m.set_egress(1, 1);
    m.set_egress(17, 2);
    m.set_egress(33, 3);
    assert_eq!(m.egress_mask(1), qos_mask(1));
    assert_eq!(m.egress_mask(17), qos_mask(2));
    assert_eq!(m.egress_mask(33), qos_mask(3));
    assert_eq!(m.egress_mask(49), 0, "same bucket, no exact match");
    assert_eq!(m.nr_egress(), 3);
}

#[test]
fn rewriting_a_priority_replaces_it() {
    let mut m = PrioMaps::new();
    m.set_egress(7, 1);
    m.set_egress(7, 6);
    assert_eq!(m.egress_mask(7), qos_mask(6));
    assert_eq!(m.nr_egress(), 1);
}

#[test]
fn mapping_to_code_point_zero_removes_the_entry() {
    let mut m = PrioMaps::new();
    m.set_egress(7, 4);
    m.set_egress(7, 0);
    assert_eq!(m.egress_mask(7), 0);
    assert_eq!(m.nr_egress(), 0);
}

#[test]
fn mapping_an_unknown_priority_to_zero_creates_nothing() {
    let mut m = PrioMaps::new();
    m.set_egress(7, 0);
    assert_eq!(m.nr_egress(), 0);
    assert!(m.egress_mappings().is_empty());
}

#[test]
fn egress_code_point_bits_beyond_three_are_dropped() {
    let mut m = PrioMaps::new();
    m.set_egress(2, 9);
    assert_eq!(m.egress_mask(2), qos_mask(1), "code point 9 is code point 1");
}

#[test]
fn mappings_report_both_ends() {
    let mut m = PrioMaps::new();
    m.set_ingress(11, 3);
    m.set_egress(4, 6);
    assert_eq!(m.ingress_mappings(), alloc::vec![(3u32, 11u32)]);
    assert_eq!(m.egress_mappings(), alloc::vec![(4u32, 6u32)]);
}
