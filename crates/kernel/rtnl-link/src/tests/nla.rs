// Attribute walking. Every length in a blob is attacker-controlled, so the
// walk must end on a malformed one rather than read past it or spin.

extern crate alloc;
use alloc::vec::Vec;

use crate::nla::*;
use crate::uapi::*;

fn blob(attrs: &[(u16, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (ty, p) in attrs { put(&mut out, *ty, p); }
    out
}

#[test]
fn a_walk_visits_every_attribute_in_order() {
    let b = blob(&[(1, b"one\0"), (2, &[0x11, 0x22]), (3, &[1, 2, 3, 4])]);
    let mut seen = Vec::new();
    for_each(&b, |a| seen.push((a.ty, a.payload.len())));
    assert_eq!(seen, alloc::vec![(1, 4), (2, 2), (3, 4)]);
}

#[test]
fn payloads_are_padded_but_lengths_are_not() {
    // A three-byte payload occupies four bytes on the wire; reporting four
    // would hand a string parser a stray NUL and a u32 parser a bogus value.
    let b = blob(&[(1, &[1, 2, 3]), (2, &[9])]);
    let a = find(&b, 1).unwrap();
    assert_eq!(a.payload, &[1, 2, 3]);
    assert_eq!(find(&b, 2).unwrap().payload, &[9]);
    assert_eq!(b.len(), align(NLA_HDR_LEN + 3) + align(NLA_HDR_LEN + 1));
}

#[test]
fn the_nested_bit_is_not_part_of_the_number() {
    let mut b = Vec::new();
    let at = nest_start(&mut b, 18);
    put(&mut b, 1, b"vlan\0");
    nest_end(&mut b, at);
    let a = find(&b, 18).expect("the nest is found by its bare number");
    assert!(a.nested);
    assert_eq!(find(&a.payload, 1).unwrap().cstr(), Some("vlan"));
}

#[test]
fn a_length_below_the_header_ends_the_walk() {
    // Otherwise the offset never advances and the walk never returns.
    let mut b = Vec::new();
    b.extend_from_slice(&3u16.to_ne_bytes());
    b.extend_from_slice(&1u16.to_ne_bytes());
    b.extend_from_slice(&[0, 0, 0, 0]);
    let mut n = 0;
    for_each(&b, |_| n += 1);
    assert_eq!(n, 0);
}

#[test]
fn a_length_past_the_buffer_ends_the_walk() {
    let mut b = Vec::new();
    b.extend_from_slice(&64u16.to_ne_bytes());
    b.extend_from_slice(&1u16.to_ne_bytes());
    b.extend_from_slice(&[1, 2, 3, 4]);
    let mut n = 0;
    for_each(&b, |_| n += 1);
    assert_eq!(n, 0, "the declared length is a lie and must not be trusted");
}

#[test]
fn a_truncated_header_ends_the_walk() {
    let b = [1u8, 0, 0];
    let mut n = 0;
    for_each(&b, |_| n += 1);
    assert_eq!(n, 0);
}

#[test]
fn a_good_attribute_before_a_malformed_one_is_still_reported() {
    let mut b = blob(&[(1, b"ok\0")]);
    b.extend_from_slice(&2u16.to_ne_bytes());
    b.extend_from_slice(&7u16.to_ne_bytes());
    let mut seen = Vec::new();
    for_each(&b, |a| seen.push(a.ty));
    assert_eq!(seen, alloc::vec![1]);
}

#[test]
fn typed_accessors_refuse_the_wrong_width() {
    let b = blob(&[(1, &[1, 2]), (2, &[1, 2, 3, 4])]);
    assert_eq!(find(&b, 1).unwrap().u16(), Some(u16::from_ne_bytes([1, 2])));
    assert_eq!(find(&b, 1).unwrap().u32(), None, "two bytes are not a u32");
    assert_eq!(find(&b, 2).unwrap().u32(), Some(u32::from_ne_bytes([1, 2, 3, 4])));
}

#[test]
fn a_string_without_a_terminator_is_refused() {
    // The sender declared a C string; reading to the payload end instead would
    // accept a name the sender never wrote.
    let b = blob(&[(1, b"vlan")]);
    assert_eq!(find(&b, 1).unwrap().cstr(), None);
    let b = blob(&[(1, b"vlan\0")]);
    assert_eq!(find(&b, 1).unwrap().cstr(), Some("vlan"));
}

#[test]
fn a_string_stops_at_the_terminator() {
    let b = blob(&[(1, b"bond\0junk")]);
    assert_eq!(find(&b, 1).unwrap().cstr(), Some("bond"));
}

#[test]
fn find_reports_the_first_occurrence() {
    let b = blob(&[(1, b"first\0"), (1, b"second\0")]);
    assert_eq!(find(&b, 1).unwrap().cstr(), Some("first"));
}

#[test]
fn find_reports_nothing_for_an_absent_number() {
    let b = blob(&[(1, b"x\0")]);
    assert!(find(&b, 99).is_none());
    assert!(find(&[], 1).is_none());
}
