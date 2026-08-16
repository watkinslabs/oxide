// The representation itself: byte order, padding, and bounds.
//
// Every assertion here is a byte-level fact about the encoding, not a
// round-trip through our own codec. A round-trip test agrees with itself when
// the encoder and decoder share a mistake, and the mistakes this layer makes —
// a forgotten pad byte, a little-endian word — are exactly the ones a
// round-trip hides.

extern crate alloc;

use crate::err::RpcError;
use crate::xdr::{padded, pad_of, Dec, Enc};

#[test]
fn u32_is_big_endian_on_the_wire() {
    let mut e = Enc::new();
    e.u32(0x0102_0304).unwrap();
    assert_eq!(e.as_slice(), &[0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn hyper_is_two_big_endian_words_high_first() {
    let mut e = Enc::new();
    e.u64(0x0102_0304_0506_0708).unwrap();
    assert_eq!(e.as_slice(), &[1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn opaque_writes_length_then_bytes_then_padding() {
    let mut e = Enc::new();
    e.opaque(b"abc").unwrap();
    assert_eq!(e.as_slice(), &[0, 0, 0, 3, b'a', b'b', b'c', 0]);
}

#[test]
fn opaque_of_aligned_length_gets_no_padding() {
    let mut e = Enc::new();
    e.opaque(b"abcd").unwrap();
    assert_eq!(e.len(), 8);
    assert_eq!(&e.as_slice()[4..], b"abcd");
}

#[test]
fn empty_opaque_is_a_bare_zero_length() {
    let mut e = Enc::new();
    e.opaque(b"").unwrap();
    assert_eq!(e.as_slice(), &[0, 0, 0, 0]);
}

#[test]
fn fixed_opaque_omits_the_length_but_keeps_the_padding() {
    let mut e = Enc::new();
    e.opaque_fixed(b"xy").unwrap();
    assert_eq!(e.as_slice(), &[b'x', b'y', 0, 0]);
}

#[test]
fn padding_helpers_round_up_to_the_xdr_unit() {
    assert_eq!((padded(0), padded(1), padded(4), padded(5)), (0, 4, 4, 8));
    assert_eq!((pad_of(0), pad_of(1), pad_of(3), pad_of(4)), (0, 3, 1, 0));
}

#[test]
fn decoder_consumes_the_padding_after_a_short_opaque() {
    // The field after a 3-byte opaque must be read from offset 8, not 7. A
    // decoder that skipped the pad byte would read this marker one byte early
    // and every later field with it.
    let mut e = Enc::new();
    e.opaque(b"abc").unwrap();
    e.u32(0xDEAD_BEEF).unwrap();
    let buf = e.finish();
    let mut d = Dec::new(&buf);
    assert_eq!(d.opaque(16).unwrap(), b"abc");
    assert_eq!(d.pos(), 8);
    assert_eq!(d.u32().unwrap(), 0xDEAD_BEEF);
    assert!(d.at_end());
}

#[test]
fn decoding_past_the_end_is_an_error_not_a_wrap() {
    let mut d = Dec::new(&[0, 0, 0]);
    assert_eq!(d.u32(), Err(RpcError::Unparsable));
}

#[test]
fn an_opaque_longer_than_its_cap_is_refused_before_it_is_read() {
    // The length word is wire-supplied. A decoder that trusted it would read
    // past the buffer or allocate whatever the wire asked for.
    let buf = [0, 0, 0x10, 0, b'x'];
    let mut d = Dec::new(&buf);
    assert_eq!(d.opaque(64), Err(RpcError::Unparsable));
}

#[test]
fn an_opaque_whose_length_exceeds_the_buffer_is_refused() {
    let buf = [0, 0, 0, 8, b'a', b'b', b'c', b'd'];
    let mut d = Dec::new(&buf);
    assert_eq!(d.opaque(64), Err(RpcError::Unparsable));
}

#[test]
fn a_boolean_must_be_exactly_zero_or_one() {
    // XDR defines only two values. Accepting "non-zero means true" would let a
    // misaligned decode present a stray word as a set discriminant, and the
    // decoder would then read an optional field that is not on the wire.
    assert_eq!(Dec::new(&[0, 0, 0, 0]).bool(), Ok(false));
    assert_eq!(Dec::new(&[0, 0, 0, 1]).bool(), Ok(true));
    assert_eq!(Dec::new(&[0, 0, 0, 2]).bool(), Err(RpcError::Unparsable));
    assert_eq!(Dec::new(&[0xFF, 0xFF, 0xFF, 0xFF]).bool(), Err(RpcError::Unparsable));
}

#[test]
fn a_string_must_be_valid_utf8() {
    let buf = [0, 0, 0, 2, 0xFF, 0xFE, 0, 0];
    let mut d = Dec::new(&buf);
    assert_eq!(d.string(16), Err(RpcError::Unparsable));
}

#[test]
fn the_encoder_refuses_to_pass_its_limit() {
    let mut e = Enc::with_limit(8);
    e.u32(1).unwrap();
    e.u32(2).unwrap();
    assert_eq!(e.u32(3), Err(RpcError::MsgTooLarge));
    assert_eq!(e.len(), 8);
}

#[test]
fn the_limit_counts_padding_not_just_payload() {
    // A 5-byte opaque occupies 4 + 5 + 3 = 12 bytes. An encoder that charged
    // only the payload would overrun a transport's frame by the pad.
    let mut e = Enc::with_limit(11);
    assert_eq!(e.opaque(b"abcde"), Err(RpcError::MsgTooLarge));
    let mut e = Enc::with_limit(12);
    e.opaque(b"abcde").unwrap();
    assert_eq!(e.len(), 12);
}

#[test]
fn a_reserved_word_is_patched_in_place() {
    let mut e = Enc::new();
    e.u32(0xAAAA_AAAA).unwrap();
    let at = e.reserve_u32().unwrap();
    e.u32(0xBBBB_BBBB).unwrap();
    e.patch_u32(at, 0x1234_5678).unwrap();
    let buf = e.finish();
    let mut d = Dec::new(&buf);
    assert_eq!(d.u32().unwrap(), 0xAAAA_AAAA);
    assert_eq!(d.u32().unwrap(), 0x1234_5678);
    assert_eq!(d.u32().unwrap(), 0xBBBB_BBBB);
}

#[test]
fn patching_outside_the_buffer_is_refused() {
    let mut e = Enc::new();
    e.u32(0).unwrap();
    assert_eq!(e.patch_u32(4, 1), Err(RpcError::Unparsable));
}
