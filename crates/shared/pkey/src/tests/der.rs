// The decoder's rules. A permissive DER decoder is how two implementations
// end up disagreeing about what a signed blob said, so each rejection is
// pinned.

use crate::der::*;

#[test]
fn short_form_length() {
    let (tlv, rest) = parse_one(&[0x02, 0x03, 1, 2, 3, 0xff]).expect("well formed");
    assert_eq!(tlv, Tlv { tag: TAG_INTEGER, value: &[1, 2, 3] });
    assert_eq!(rest, &[0xff]);
}

#[test]
fn long_form_length() {
    let mut buf = alloc::vec![0x04, 0x81, 0x80];
    buf.extend(core::iter::repeat(0xaa).take(128));
    let (tlv, rest) = parse_one(&buf).expect("well formed");
    assert_eq!(tlv.tag, TAG_OCTET_STRING);
    assert_eq!(tlv.value.len(), 128);
    assert!(rest.is_empty());
}

#[test]
fn malformed_lengths_are_rejected() {
    // Indefinite length (BER only).
    assert_eq!(parse_one(&[0x30, 0x80, 0x00, 0x00]), Err(DerError::BadLength));
    // A long form used for a length that fits the short form.
    assert_eq!(parse_one(&[0x02, 0x81, 0x01, 0x05]), Err(DerError::BadLength));
    // A leading zero inside a multi-byte length.
    assert_eq!(parse_one(&[0x02, 0x82, 0x00, 0x81]), Err(DerError::BadLength));
    // A length running past the buffer.
    assert_eq!(parse_one(&[0x02, 0x05, 1, 2]), Err(DerError::Truncated));
    assert_eq!(parse_one(&[0x02]), Err(DerError::Truncated));
}

#[test]
fn exact_parse_rejects_trailing_bytes() {
    assert_eq!(parse_exact(&[0x30, 0x01, 0x00, 0x00], TAG_SEQUENCE), Err(DerError::Trailing));
    assert_eq!(parse_exact(&[0x30, 0x01, 0x00], TAG_INTEGER), Err(DerError::WrongTag));
    assert_eq!(parse_exact(&[0x30, 0x01, 0x00], TAG_SEQUENCE), Ok(&[0u8][..]));
}

#[test]
fn bit_string_requires_whole_octets() {
    assert_eq!(bit_string_bytes(&[0x00, 0xde, 0xad]), Ok(&[0xde, 0xad][..]));
    assert_eq!(bit_string_bytes(&[0x03, 0xde]), Err(DerError::BadValue), "unused bits");
    assert_eq!(bit_string_bytes(&[]), Err(DerError::Truncated));
}

#[test]
fn integers_are_non_negative_and_lose_the_sign_byte() {
    assert_eq!(positive_integer(&[0x00, 0xff]), Ok(&[0xff][..]));
    assert_eq!(positive_integer(&[0x7f]), Ok(&[0x7f][..]));
    assert_eq!(positive_integer(&[0x00]), Ok(&[0x00][..]), "zero keeps its single octet");
    assert_eq!(positive_integer(&[0x80, 0x01]), Err(DerError::BadValue), "negative");
    assert_eq!(positive_integer(&[]), Err(DerError::Truncated));
}

#[test]
fn reader_walks_a_sequence() {
    // SEQUENCE { INTEGER 1, OCTET STRING "hi" }
    let buf = [0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x02, b'h', b'i'];
    let body = parse_exact(&buf, TAG_SEQUENCE).expect("well formed");
    let mut r = Reader::new(body);
    assert_eq!(r.expect(TAG_INTEGER), Ok(&[1u8][..]));
    assert_eq!(r.take_if(TAG_INTEGER), Ok(None), "a tag that is not there leaves the cursor");
    assert_eq!(r.take_if(TAG_OCTET_STRING), Ok(Some(&b"hi"[..])));
    assert_eq!(r.end(), Ok(()));
    assert_eq!(r.expect(TAG_INTEGER), Err(DerError::Truncated));
}
