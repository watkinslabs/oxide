// `FlipRing` — the staging buffer between the UART interrupt and the line
// discipline. Ungated on purpose: the module carries no target gate, so these
// tests actually compile and run (`CLAUDE.md`, phantom-test trap).

use super::*;

fn drained(r: &mut FlipRing, n: usize) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec![0u8; n];
    let got = r.drain(&mut out);
    out.truncate(got);
    out
}

#[test]
fn insert_then_drain_preserves_order() {
    let mut r = FlipRing::new();
    assert_eq!(r.insert(b"xsessions"), 9);
    assert_eq!(r.pending(), 9);
    assert_eq!(drained(&mut r, 16), b"xsessions".to_vec());
    assert_eq!(r.pending(), 0);
}

#[test]
fn a_byte_is_delivered_exactly_once() {
    // The duplication symptom (`xsessions` -> `xsessiions`) must not be
    // reachable through the staging buffer: every inserted byte comes out
    // once, and a partial drain does not re-yield what it already gave.
    let mut r = FlipRing::new();
    r.insert(b"abcdef");
    assert_eq!(drained(&mut r, 3), b"abc".to_vec());
    assert_eq!(drained(&mut r, 3), b"def".to_vec());
    assert_eq!(drained(&mut r, 3), alloc::vec::Vec::<u8>::new());
}

#[test]
fn interleaved_inserts_and_drains_keep_fifo_order() {
    let mut r = FlipRing::new();
    r.insert(b"ab");
    assert_eq!(drained(&mut r, 1), b"a".to_vec());
    r.insert(b"cd");
    assert_eq!(drained(&mut r, 8), b"bcd".to_vec());
}

#[test]
fn drain_of_an_empty_ring_reports_zero() {
    let mut r = FlipRing::new();
    let mut out = [0u8; 4];
    assert_eq!(r.drain(&mut out), 0);
    assert_eq!(r.drain(&mut []), 0);
}

#[test]
fn insert_never_exceeds_the_reserved_capacity() {
    // The producer is a hard-IRQ handler, so a push past the reserve would be
    // an allocation in interrupt context. The short return IS the contract.
    let mut r = FlipRing::new();
    let big = alloc::vec![b'x'; FLIP_CAPACITY + 100];
    assert_eq!(r.insert(&big), FLIP_CAPACITY);
    assert_eq!(r.pending(), FLIP_CAPACITY);
    assert_eq!(r.dropped(), 100);
    assert_eq!(r.insert(b"y"), 0, "a full ring accepts nothing");
    assert_eq!(r.dropped(), 101, "and says so");
}

#[test]
fn room_reopens_as_the_ldisc_consumes() {
    let mut r = FlipRing::new();
    r.insert(&alloc::vec![b'a'; FLIP_CAPACITY]);
    assert_eq!(r.insert(b"z"), 0);
    assert_eq!(drained(&mut r, 1).len(), 1);
    assert_eq!(r.insert(b"z"), 1);
}

#[test]
fn clear_discards_staged_input() {
    // TCIFLUSH: input already staged for the ldisc is input the caller asked
    // to discard, so leaving it makes the flush arrive late instead of not at
    // all — worse than either.
    let mut r = FlipRing::new();
    r.insert(b"stale");
    r.clear();
    assert_eq!(r.pending(), 0);
    assert_eq!(drained(&mut r, 8), alloc::vec::Vec::<u8>::new());
}

#[test]
fn dropped_is_cumulative_and_starts_at_zero() {
    let mut r = FlipRing::new();
    assert_eq!(r.dropped(), 0);
    r.insert(&alloc::vec![b'a'; FLIP_CAPACITY + 1]);
    r.insert(b"bb");
    assert_eq!(r.dropped(), 3);
}

#[test]
fn flush_chunk_is_a_real_subdivision_of_the_ring() {
    // A chunk larger than the ring would put the whole buffer on the worker's
    // stack; a zero chunk would spin forever.
    assert!(FLUSH_CHUNK > 0);
    assert!(FLUSH_CHUNK < FLIP_CAPACITY);
}
