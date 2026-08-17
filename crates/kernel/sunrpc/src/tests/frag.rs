// Record marking: the framing that gives a byte stream message boundaries.

extern crate alloc;
use alloc::vec::Vec;
use alloc::vec;

use crate::err::RpcError;
use crate::frag::{frame, last_marker, Reassembler};
use crate::uapi::frag as F;

fn hdr(len: u32, last: bool) -> [u8; 4] {
    (if last { len | F::LAST_FRAGMENT } else { len }).to_be_bytes()
}

#[test]
fn the_marker_sets_the_last_bit_and_the_length() {
    assert_eq!(last_marker(4).unwrap(), [0x80, 0, 0, 4]);
    assert_eq!(last_marker(0).unwrap(), [0x80, 0, 0, 0]);
}

#[test]
fn framing_prefixes_the_body_with_one_marker() {
    assert_eq!(frame(b"abcd").unwrap(), vec![0x80, 0, 0, 4, b'a', b'b', b'c', b'd']);
}

#[test]
fn a_body_past_the_fragment_maximum_is_refused() {
    assert_eq!(last_marker(F::MAX_FRAGMENT_SIZE as usize + 1), Err(RpcError::MsgTooLarge));
}

#[test]
fn one_whole_record_comes_back_intact() {
    let mut r = Reassembler::new(4096);
    let got = r.feed(&frame(b"hello!!!").unwrap()).unwrap();
    assert_eq!(got, vec![b"hello!!!".to_vec()]);
}

#[test]
fn a_record_split_across_fragments_is_concatenated() {
    // Nothing stops a server splitting a large reply. A receiver that assumed
    // one fragment per record would take the second fragment's header for four
    // bytes of reply data and every field after it would be shifted.
    let mut buf = Vec::new();
    buf.extend_from_slice(&hdr(4, false));
    buf.extend_from_slice(b"AAAA");
    buf.extend_from_slice(&hdr(4, true));
    buf.extend_from_slice(b"BBBB");
    let mut r = Reassembler::new(4096);
    assert_eq!(r.feed(&buf).unwrap(), vec![b"AAAABBBB".to_vec()]);
}

#[test]
fn a_non_final_fragment_yields_nothing_yet() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&hdr(4, false));
    buf.extend_from_slice(b"AAAA");
    let mut r = Reassembler::new(4096);
    assert!(r.feed(&buf).unwrap().is_empty());
    assert_eq!(r.pending(), 4);
}

#[test]
fn an_empty_final_fragment_terminates_the_record() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&hdr(3, false));
    buf.extend_from_slice(b"abc");
    buf.extend_from_slice(&hdr(0, true));
    let mut r = Reassembler::new(4096);
    assert_eq!(r.feed(&buf).unwrap(), vec![b"abc".to_vec()]);
}

#[test]
fn a_header_arriving_one_byte_at_a_time_still_parses() {
    // A stream splits wherever the network did; a header straddling two reads
    // is ordinary, not an error.
    let whole = frame(b"wxyz").unwrap();
    let mut r = Reassembler::new(4096);
    let mut out = Vec::new();
    for b in &whole { out.extend(r.feed(&[*b]).unwrap()); }
    assert_eq!(out, vec![b"wxyz".to_vec()]);
}

#[test]
fn several_records_in_one_read_all_come_back_in_order() {
    let mut buf = frame(b"one!").unwrap();
    buf.extend_from_slice(&frame(b"two!").unwrap());
    buf.extend_from_slice(&frame(b"three456").unwrap());
    let mut r = Reassembler::new(4096);
    assert_eq!(r.feed(&buf).unwrap(),
               vec![b"one!".to_vec(), b"two!".to_vec(), b"three456".to_vec()]);
}

#[test]
fn a_record_over_the_cap_is_refused_and_the_stream_state_is_dropped() {
    // The length is wire-supplied. Without the cap a corrupt word makes the
    // client buffer unboundedly waiting for bytes that never come.
    let mut buf = Vec::new();
    buf.extend_from_slice(&hdr(9000, true));
    let mut r = Reassembler::new(4096);
    assert_eq!(r.feed(&buf), Err(RpcError::MsgTooLarge));
    assert_eq!(r.pending(), 0);
}

#[test]
fn the_cap_counts_the_whole_record_not_each_fragment() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&hdr(64, false));
    buf.extend_from_slice(&[0u8; 64]);
    buf.extend_from_slice(&hdr(64, true));
    let mut r = Reassembler::new(100);
    assert_eq!(r.feed(&buf), Err(RpcError::MsgTooLarge));
}

#[test]
fn reset_discards_a_partial_record() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&hdr(8, false));
    buf.extend_from_slice(b"partial!");
    let mut r = Reassembler::new(4096);
    r.feed(&buf).unwrap();
    assert_eq!(r.pending(), 8);
    r.reset();
    assert_eq!(r.pending(), 0);
    assert_eq!(r.feed(&frame(b"fresh!!!").unwrap()).unwrap(), vec![b"fresh!!!".to_vec()]);
}
