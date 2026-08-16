// The Galois-mode cipher.
//
// It shares a header layout with the counter-mode cipher and does NOT share a
// nonce: its initialisation vector is the transmitter address and the packet
// number with no flags byte. A test that only round-trips would never notice
// the two being swapped, so the derived bytes are asserted directly and the
// mode underneath is pinned to a published vector.

use alloc::vec;
use alloc::vec::Vec;

use aes::block::AesKey;
use aes::gcm;

use crate::crypto::pn::Pn;
use crate::crypto::{aad, gcmp, CryptoError};
use crate::tests_fixture as f;
use crate::uapi::cipher_len;

const TK: [u8; 16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const PAYLOAD: [u8; 24] = [0x45, 0x00, 0x00, 0x18, 0x00, 0x01, 0x00, 0x00,
                           0x40, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
                           0x0a, 0x00, 0x00, 0x02, 0x08, 0x00, 0xf7, 0xff];

/// A published Galois-mode vector, so the mode this cipher composes with the
/// 802.11 header derivation is pinned rather than merely self-consistent.
#[test]
fn the_underlying_mode_matches_a_published_vector() {
    let key = AesKey::new(&[0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                            0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08]).unwrap();
    let iv: [u8; 12] = [0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                        0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88];
    let mut data: Vec<u8> = vec![
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5,
        0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95,
        0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
        0x1a, 0xaf, 0xd2, 0x55];
    let mut tag = [0u8; 16];
    gcm::encrypt(&key, &iv, &[], &mut data, &mut tag).unwrap();
    assert_eq!(&data[..16], &[0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
                              0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c]);
    assert_eq!(&data[48..], &[0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
                              0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f, 0x59, 0x85]);
    assert_eq!(tag, [0x4d, 0x5c, 0x2a, 0xf3, 0x27, 0xcd, 0x64, 0xa6,
                     0x2c, 0xf3, 0x5a, 0xbd, 0x2b, 0xa6, 0xfa, 0xb4]);
}

#[test]
fn the_initialisation_vector_carries_no_flags_byte() {
    let hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, Some(5), true);
    let parsed = f::parse(&hdr);
    let pn = Pn(0x0000_0000_1234);
    let iv = aad::gcm_iv(&parsed, &pn.to_bytes());
    assert_eq!(&iv[0..6], &f::AP.0, "the transmitter comes first, with no flags byte");
    assert_eq!(&iv[6..12], &pn.to_bytes());
    // The counter-mode nonce for the same frame is a different thing.
    let nonce = aad::ccm_nonce(&parsed, 5, &pn.to_bytes());
    assert_ne!(&nonce[0..6], &iv[0..6]);
}

#[test]
fn the_header_matches_the_counter_mode_layout() {
    let pn = Pn(0x0a0b_0c0d_0e0f);
    assert_eq!(gcmp::build_hdr(pn, 3), crate::crypto::ccmp::build_hdr(pn, 3));
    let (back, idx) = gcmp::parse_hdr(&gcmp::build_hdr(pn, 3)).unwrap();
    assert_eq!((back, idx), (pn, 3));
}

#[test]
fn encrypt_then_decrypt_returns_the_plaintext() {
    let hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, Some(2), true);
    let parsed = f::parse(&hdr);
    let sealed = gcmp::encrypt(&TK, &parsed, Pn(77), 0, &PAYLOAD).unwrap();
    assert_eq!(sealed.len(), cipher_len::GCMP_HDR + PAYLOAD.len() + cipher_len::GCMP_MIC);
    assert_ne!(&sealed[cipher_len::GCMP_HDR..cipher_len::GCMP_HDR + PAYLOAD.len()],
               &PAYLOAD[..]);
    let (pn, idx, plain) = gcmp::decrypt(&TK, &parsed, &sealed).unwrap();
    assert_eq!((pn, idx), (Pn(77), 0));
    assert_eq!(plain, PAYLOAD);
}

#[test]
fn the_two_hundred_fifty_six_bit_variant_round_trips() {
    let key: Vec<u8> = (0u8..32).rev().collect();
    let hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, None, true);
    let parsed = f::parse(&hdr);
    let sealed = gcmp::encrypt(&key, &parsed, Pn(5), 2, &PAYLOAD).unwrap();
    let (_, idx, plain) = gcmp::decrypt(&key, &parsed, &sealed).unwrap();
    assert_eq!(idx, 2);
    assert_eq!(plain, PAYLOAD);
}

#[test]
fn a_flipped_bit_anywhere_fails() {
    let hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, Some(0), true);
    let parsed = f::parse(&hdr);
    let sealed = gcmp::encrypt(&TK, &parsed, Pn(0x2233_4455_6677), 0, &PAYLOAD).unwrap();
    // The cipher header's reserved byte and key-identifier octet are NOT
    // covered by the tag — the standard authenticates the MAC header and the
    // payload, and the key identifier is what selects the key rather than
    // something the key protects. Every other byte is covered.
    for i in 0..sealed.len() {
        if i == 2 || i == 3 { continue; }
        let mut bad = sealed.clone();
        bad[i] ^= 0x02;
        assert_eq!(gcmp::decrypt(&TK, &parsed, &bad), Err(CryptoError::IntegrityFailure),
                   "byte {i} was accepted");
    }
}

#[test]
fn a_flipped_bit_in_the_authenticated_header_fails() {
    let hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, Some(0), true);
    let parsed = f::parse(&hdr);
    let sealed = gcmp::encrypt(&TK, &parsed, Pn(1), 0, &PAYLOAD).unwrap();
    let other = f::data_hdr_from_ds(f::OTHER, f::AP, f::PEER, Some(0), true);
    assert_eq!(gcmp::decrypt(&TK, &f::parse(&other), &sealed),
               Err(CryptoError::IntegrityFailure));
}

#[test]
fn a_truncated_frame_is_refused() {
    let hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, None, true);
    let parsed = f::parse(&hdr);
    for len in 0..(cipher_len::GCMP_HDR + cipher_len::GCMP_MIC) {
        assert_eq!(gcmp::decrypt(&TK, &parsed, &vec![0u8; len]),
                   Err(CryptoError::TooShort));
    }
}
