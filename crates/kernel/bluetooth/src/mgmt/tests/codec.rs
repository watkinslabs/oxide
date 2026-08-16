//! The cursor pair: bounds, exact consumption, and little-endian order.

use super::*;

#[test]
fn every_width_round_trips_little_endian() {
    let mut w = Writer::new();
    w.u8(0x12);
    w.i8(-2);
    w.u16(0x1234);
    w.u32(0x1234_5678);
    w.u64(0x0123_4567_89ab_cdef);
    let buf = w.finish();
    assert_eq!(&buf[2..4], &[0x34, 0x12], "16-bit is least significant first");
    assert_eq!(&buf[4..8], &[0x78, 0x56, 0x34, 0x12]);
    let mut r = Reader::new(&buf);
    assert_eq!(r.u8(), Some(0x12));
    assert_eq!(r.i8(), Some(-2));
    assert_eq!(r.u16(), Some(0x1234));
    assert_eq!(r.u32(), Some(0x1234_5678));
    assert_eq!(r.u64(), Some(0x0123_4567_89ab_cdef));
    assert!(r.done());
}

#[test]
fn a_read_past_the_end_yields_nothing_and_not_a_partial_value() {
    let buf = [0x01, 0x02, 0x03];
    let mut r = Reader::new(&buf);
    assert_eq!(r.u16(), Some(0x0201));
    assert_eq!(r.remaining(), 1);
    assert_eq!(r.u16(), None, "a 2-byte read with 1 byte left must fail");
    assert_eq!(r.u32(), None);
    assert_eq!(r.u64(), None);
    assert_eq!(r.take(2), None);
}

#[test]
fn done_distinguishes_exact_from_over_long() {
    let buf = [0x01, 0x02];
    let mut r = Reader::new(&buf);
    assert!(!r.done());
    r.u8();
    assert!(!r.done());
    r.u8();
    assert!(r.done());
}

#[test]
fn a_zero_length_take_succeeds_at_the_end() {
    let mut r = Reader::new(&[]);
    assert_eq!(r.take(0), Some(&[][..]));
    assert!(r.done());
}

#[test]
fn a_fixed_field_pads_a_short_value_and_truncates_a_long_one() {
    let mut w = Writer::new();
    w.fixed(b"ab", 5);
    w.fixed(b"abcdefg", 3);
    assert_eq!(w.finish(), alloc::vec![b'a', b'b', 0, 0, 0, b'a', b'b', b'c']);
}

#[test]
fn an_address_keeps_its_wire_order() {
    let a = BdAddr([1, 2, 3, 4, 5, 6]);
    let mut w = Writer::new();
    w.addr(&a);
    let buf = w.finish();
    assert_eq!(buf, alloc::vec![1, 2, 3, 4, 5, 6]);
    assert_eq!(Reader::new(&buf).addr(), Some(a));
}

#[test]
fn a_short_address_read_fails() {
    let buf = [1, 2, 3, 4, 5];
    assert_eq!(Reader::new(&buf).addr(), None);
}
