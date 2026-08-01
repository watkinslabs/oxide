// AF_UNIX SOCK_STREAM out-of-band (`MSG_OOB`) contract. Every assertion here is
// the observable behaviour of a Linux AF_UNIX stream pair, encoded so a later
// change to the queue model has to keep answering the same way.

use super::*;
use crate::unix_sock::stream::{at_mark, limit, step, OobStep};

/// Drain the ring `end` reads with `SO_OOBINLINE` off. # C: O(max)
fn read(p: &alloc::sync::Arc<UnixPair>, end: UnixEnd, max: usize) -> alloc::vec::Vec<u8> {
    p.read_passcred(end, max, false, false)
}

/// Drain the ring `end` reads with `SO_OOBINLINE` on. # C: O(max)
fn read_inline(p: &alloc::sync::Arc<UnixPair>, end: UnixEnd, max: usize) -> alloc::vec::Vec<u8> {
    p.read_passcred(end, max, false, true)
}

#[test]
fn out_of_band_byte_is_delivered_only_through_its_own_receive() {
    let _serial = test_guard();
    let p = UnixPair::new();
    p.write(UnixEnd::A, b"abc").unwrap();
    p.write_oob_byte(UnixEnd::A, b'X').unwrap();
    assert!(p.has_oob(UnixEnd::B), "a byte awaits its out-of-band receive");
    // The in-band receive stops in front of the mark rather than gluing across.
    assert_eq!(&read(&p, UnixEnd::B, 64)[..], b"abc");
    assert_eq!(p.recv_oob(UnixEnd::B, false, false), Some(b'X'));
    assert!(!p.has_oob(UnixEnd::B));
}

#[test]
fn in_band_receive_never_glues_across_the_pending_byte() {
    let _serial = test_guard();
    let p = UnixPair::new();
    p.write(UnixEnd::A, b"abc").unwrap();
    p.write_oob_byte(UnixEnd::A, b'X').unwrap();
    p.write(UnixEnd::A, b"def").unwrap();
    assert_eq!(&read(&p, UnixEnd::B, 64)[..], b"abc", "stops before the out-of-band byte");
}

#[test]
fn a_receive_that_copied_nothing_discards_the_pending_byte() {
    let _serial = test_guard();
    let p = UnixPair::new();
    p.write(UnixEnd::A, b"abc").unwrap();
    p.write_oob_byte(UnixEnd::A, b'X').unwrap();
    p.write(UnixEnd::A, b"def").unwrap();
    assert_eq!(&read(&p, UnixEnd::B, 64)[..], b"abc");
    // Without SO_OOBINLINE the byte nobody claimed is dropped, and dropping it
    // removes the boundary too, so the same receive carries on into `def`.
    assert_eq!(&read(&p, UnixEnd::B, 64)[..], b"def");
    assert!(!p.has_oob(UnixEnd::B));
    assert_eq!(p.recv_oob(UnixEnd::B, false, false), None);
}

#[test]
fn oobinline_delivers_the_byte_in_the_stream() {
    let _serial = test_guard();
    let p = UnixPair::new();
    p.write(UnixEnd::A, b"abc").unwrap();
    p.write_oob_byte(UnixEnd::A, b'X').unwrap();
    p.write(UnixEnd::A, b"def").unwrap();
    // The boundary still ends the first receive; the option changes who
    // delivers the byte, not that it is a boundary.
    assert_eq!(&read_inline(&p, UnixEnd::B, 64)[..], b"abc");
    assert_eq!(&read_inline(&p, UnixEnd::B, 64)[..], b"Xdef");
    assert!(!p.has_oob(UnixEnd::B));
}

#[test]
fn oobinline_refuses_the_out_of_band_receive() {
    let _serial = test_guard();
    let p = UnixPair::new();
    p.write_oob_byte(UnixEnd::A, b'X').unwrap();
    assert_eq!(p.recv_oob(UnixEnd::B, false, true), None, "the byte is in-band now");
    // The pending record survives the refusal: the option can be cleared again.
    assert!(p.has_oob(UnixEnd::B));
    assert_eq!(p.recv_oob(UnixEnd::B, false, false), Some(b'X'));
}

#[test]
fn out_of_band_receive_with_nothing_pending_is_refused() {
    let _serial = test_guard();
    let p = UnixPair::new();
    assert_eq!(p.recv_oob(UnixEnd::B, false, false), None);
    p.write(UnixEnd::A, b"abc").unwrap();
    assert_eq!(p.recv_oob(UnixEnd::B, false, false), None, "in-band data is not urgent data");
}

#[test]
fn out_of_band_peek_leaves_the_byte_pending() {
    let _serial = test_guard();
    let p = UnixPair::new();
    p.write_oob_byte(UnixEnd::A, b'X').unwrap();
    assert_eq!(p.recv_oob(UnixEnd::B, true, false), Some(b'X'));
    assert_eq!(p.recv_oob(UnixEnd::B, true, false), Some(b'X'), "a peek consumes nothing");
    assert!(p.has_oob(UnixEnd::B));
    assert_eq!(p.recv_oob(UnixEnd::B, false, false), Some(b'X'));
    assert_eq!(p.recv_oob(UnixEnd::B, false, false), None);
}

#[test]
fn in_band_peek_steps_over_the_pending_byte_without_taking_it() {
    let _serial = test_guard();
    let p = UnixPair::new();
    p.write(UnixEnd::A, b"abc").unwrap();
    p.write_oob_byte(UnixEnd::A, b'X').unwrap();
    p.write(UnixEnd::A, b"def").unwrap();
    assert_eq!(&p.peek(UnixEnd::B, 64, false)[..], b"abc");
    assert_eq!(&read(&p, UnixEnd::B, 64)[..], b"abc");
    // The peek walks past the byte to reach `def` and leaves it queued.
    assert_eq!(&p.peek(UnixEnd::B, 64, false)[..], b"def");
    assert!(p.has_oob(UnixEnd::B), "a peek never discards the urgent byte");
    assert_eq!(p.recv_oob(UnixEnd::B, false, false), Some(b'X'));
}

#[test]
fn spent_record_bounds_the_next_receive_then_retires() {
    let _serial = test_guard();
    let p = UnixPair::new();
    p.write(UnixEnd::A, b"abc").unwrap();
    p.write_oob_byte(UnixEnd::A, b'X').unwrap();
    p.write(UnixEnd::A, b"def").unwrap();
    assert_eq!(p.recv_oob(UnixEnd::B, false, false), Some(b'X'));
    // The delivered byte leaves its position behind as a boundary.
    assert_eq!(&read(&p, UnixEnd::B, 64)[..], b"abc");
    assert_eq!(&read(&p, UnixEnd::B, 64)[..], b"def");
    assert_eq!(&read(&p, UnixEnd::B, 64)[..], b"");
}

#[test]
fn second_out_of_band_send_demotes_the_first_byte() {
    let _serial = test_guard();
    let p = UnixPair::new();
    p.write_oob_byte(UnixEnd::A, b'X').unwrap();
    p.write_oob_byte(UnixEnd::A, b'Y').unwrap();
    assert_eq!(p.recv_oob(UnixEnd::B, false, false), Some(b'Y'), "only the latest is urgent");
    // The superseded byte is ordinary data, and it is bounded by the record
    // that replaced it.
    assert_eq!(&read(&p, UnixEnd::B, 64)[..], b"X");
}

#[test]
fn mark_reports_the_pending_byte_and_its_spent_record() {
    let _serial = test_guard();
    let p = UnixPair::new();
    assert!(!p.at_oob_mark(UnixEnd::B), "an empty queue is not at the mark");
    p.write(UnixEnd::A, b"abc").unwrap();
    p.write_oob_byte(UnixEnd::A, b'X').unwrap();
    assert!(!p.at_oob_mark(UnixEnd::B), "in-band bytes stand in front of it");
    assert_eq!(&read(&p, UnixEnd::B, 64)[..], b"abc");
    assert!(p.at_oob_mark(UnixEnd::B));
    assert_eq!(p.recv_oob(UnixEnd::B, false, false), Some(b'X'));
    assert!(p.at_oob_mark(UnixEnd::B), "the spent record still marks the position");
    assert_eq!(&read(&p, UnixEnd::B, 64)[..], b"");
    assert!(!p.at_oob_mark(UnixEnd::B));
}

#[test]
fn queued_byte_count_discounts_the_spent_record() {
    let _serial = test_guard();
    let p = UnixPair::new();
    p.write(UnixEnd::A, b"abc").unwrap();
    p.write_oob_byte(UnixEnd::A, b'X').unwrap();
    assert_eq!(p.readable_len(UnixEnd::B), 4, "the pending byte is still queued data");
    assert_eq!(p.recv_oob(UnixEnd::B, false, false), Some(b'X'));
    assert_eq!(p.readable_len(UnixEnd::B), 3, "its spent record delivers nothing");
}

#[test]
fn out_of_band_boundary_ends_a_glued_receive() {
    let _serial = test_guard();
    let p = UnixPair::new();
    p.write(UnixEnd::A, b"abc").unwrap();
    p.write_oob_byte(UnixEnd::A, b'X').unwrap();
    let got = p.read_stream_with_offset(UnixEnd::B, 64, false, 0, false, None, false,
        |data, _, _| Ok::<_, ()>((data.to_vec(), data.len()))).unwrap();
    let (data, files, _) = got.expect("queued bytes");
    assert_eq!(&data[..], b"abc");
    assert!(files.stops_waitall(false), "MSG_WAITALL must not glue across the mark");
}

#[test]
fn descriptors_ride_the_out_of_band_byte() {
    let _serial = test_guard();
    let p = UnixPair::new();
    let rights = crate::classify_files(alloc::vec![anon_file()]);
    p.write_oob(UnixEnd::A, b'X', rights, None, usize::MAX).unwrap();
    assert_eq!(p.recv_oob(UnixEnd::B, false, false), Some(b'X'));
    // The descriptors ride the byte's queue position, so the receive that
    // walks over the spent record collects them.
    let (data, files, _) = p.read_stream(UnixEnd::B, 64);
    assert!(data.is_empty());
    assert_eq!(files.len(), 1);
}

#[test]
fn a_run_stops_at_the_nearest_out_of_band_position() {
    assert_eq!(limit(0, Some(4), None, 9), (4, true));
    assert_eq!(limit(0, None, Some(2), 9), (2, true));
    assert_eq!(limit(0, Some(4), Some(2), 9), (2, true));
    assert_eq!(limit(0, None, None, 9), (9, false), "only the queue end stops it");
    assert_eq!(limit(5, Some(4), None, 9), (9, false), "a position behind the cursor is past");
}

#[test]
fn a_receive_that_copied_bytes_halts_at_either_record() {
    assert_eq!(step(3, Some(3), None, 9, true, false), OobStep::Halt);
    assert_eq!(step(3, None, Some(3), 9, true, false), OobStep::Halt);
    assert_eq!(step(3, Some(3), None, 9, true, true), OobStep::Halt,
        "SO_OOBINLINE does not let a started receive glue across the mark");
}

#[test]
fn a_fresh_receive_steps_over_what_it_may_not_deliver() {
    assert_eq!(step(3, Some(3), None, 9, false, false), OobStep::Skip);
    assert_eq!(step(3, None, Some(3), 9, false, false), OobStep::Skip);
    assert_eq!(step(3, None, Some(3), 9, false, true), OobStep::Skip,
        "a spent record carries no byte for SO_OOBINLINE to deliver");
    assert_eq!(step(3, Some(3), None, 9, false, true), OobStep::Inline { stop: 9 });
    assert_eq!(step(3, Some(3), Some(6), 9, false, true), OobStep::Inline { stop: 6 });
    assert_eq!(step(0, Some(3), None, 9, false, false), OobStep::Copy { stop: 3 });
}

#[test]
fn the_mark_stands_at_the_pending_byte_and_at_a_record_it_follows() {
    assert!(at_mark(3, Some(3), None, true));
    assert!(at_mark(3, None, Some(3), true), "nothing else is pending behind it");
    assert!(at_mark(3, Some(4), Some(3), true), "the next byte is the urgent one");
    assert!(!at_mark(3, Some(7), Some(3), true), "in-band bytes stand between");
    assert!(!at_mark(3, Some(4), None, true), "the cursor has not reached it");
    assert!(!at_mark(3, Some(3), None, false), "an empty queue is never at the mark");
}
