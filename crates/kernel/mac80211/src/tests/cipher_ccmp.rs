// The counter-mode cipher: its wire format, its round trip, and what a
// single altered bit does to it.
//
// A note on provenance. The 802.11 construction is the published CCM mode
// with a nonce and an additional-authenticated-data block derived from the
// frame header in a specified way. This suite pins BOTH halves: the derived
// bytes are asserted against the published construction exactly, and the mode
// underneath is run against a published CCM vector. A round-trip test alone
// would be satisfied by any self-consistent invention.

use alloc::vec;
use alloc::vec::Vec;

use aes::block::AesKey;
use aes::ccm;

use crate::crypto::pn::Pn;
use crate::crypto::{aad, ccmp, CryptoError};
use crate::tests_fixture as f;
use crate::uapi::cipher_len;

const TK: [u8; 16] = [0xc9, 0x7c, 0x1f, 0x67, 0xce, 0x37, 0x11, 0x85,
                      0x51, 0x4a, 0x8a, 0x19, 0xf2, 0xbd, 0xd5, 0x2f];
const PAYLOAD: [u8; 20] = [0xf8, 0xba, 0x1a, 0x55, 0xd0, 0x2f, 0x85, 0xae, 0x96, 0x7b,
                           0xb6, 0x2f, 0xb6, 0xcd, 0xa8, 0xeb, 0x7e, 0x78, 0xa0, 0x50];

/// A published CCM vector, so the mode this cipher composes with the 802.11
/// header derivation is itself pinned and not merely self-consistent.
#[test]
fn the_underlying_mode_matches_a_published_vector() {
    // Key, nonce, associated data, plaintext and ciphertext of the first
    // vector of the counter-mode-with-CBC-MAC specification.
    let key = AesKey::new(&[0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
                            0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf]).unwrap();
    let nonce = [0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00,
                 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5];
    let assoc = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let mut data: Vec<u8> = (0x08u8..=0x1e).collect();
    let mut mic = [0u8; 8];
    ccm::encrypt(&key, &nonce, &assoc, &mut data, &mut mic).unwrap();
    assert_eq!(&data[..], &[0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2,
                            0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9, 0x89, 0x80,
                            0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84][..]);
    assert_eq!(mic, [0x17, 0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0]);
}

#[test]
fn the_header_splits_the_packet_number_the_way_the_wire_does() {
    // The six bytes are NOT in transmission order: the two low bytes come
    // first, reversed, then a reserved byte, then the key-identifier octet,
    // then the four high bytes, reversed.
    let pn = Pn(0x0102_0304_0506);
    let hdr = ccmp::build_hdr(pn, 2);
    assert_eq!(hdr, [0x06, 0x05, 0x00, 0x20 | (2 << 6), 0x04, 0x03, 0x02, 0x01]);
    let (back, idx) = ccmp::parse_hdr(&hdr).unwrap();
    assert_eq!(back, pn);
    assert_eq!(idx, 2);
}

#[test]
fn a_header_without_the_extended_bit_is_refused() {
    let mut hdr = ccmp::build_hdr(Pn(1), 0);
    hdr[3] &= !ccmp::EXT_IV;
    assert_eq!(ccmp::parse_hdr(&hdr), Err(CryptoError::NoExtIv));
}

#[test]
fn the_authenticated_header_masks_exactly_the_volatile_bits() {
    use wireless::ieee80211::fctl;
    let hdr = f::with_seq(f::data_hdr_from_ds(f::STA, f::AP, f::PEER, None, true), 0x123, 5);
    let mut parsed = f::parse(&hdr);
    // Set every bit the construction must mask away.
    parsed.frame_control |= fctl::FCTL_RETRY | fctl::FCTL_PM | fctl::FCTL_MOREDATA;
    let (masked, tid) = aad::build(&parsed);
    assert_eq!(tid, 0);
    // Three addresses, the frame control and the sequence control.
    assert_eq!(masked.len(), aad::MIN_AAD_LEN);
    let fc = u16::from_le_bytes([masked[0], masked[1]]);
    assert_eq!(fc & (fctl::FCTL_RETRY | fctl::FCTL_PM | fctl::FCTL_MOREDATA), 0,
               "retry, power-management and more-data must not be authenticated");
    assert_ne!(fc & fctl::FCTL_PROTECTED, 0, "the protected bit is always authenticated");
    assert_eq!(&masked[2..8], &f::STA.0);
    assert_eq!(&masked[8..14], &f::AP.0);
    assert_eq!(&masked[14..20], &f::PEER.0);
    // Only the fragment number survives from the sequence-control field.
    assert_eq!(masked[20], 5);
    assert_eq!(masked[21], 0);
}

#[test]
fn a_quality_of_service_frame_authenticates_its_traffic_identifier() {
    let hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, Some(6), true);
    let parsed = f::parse(&hdr);
    let (masked, tid) = aad::build(&parsed);
    assert_eq!(tid, 6);
    assert_eq!(masked.len(), aad::MIN_AAD_LEN + 2);
    assert_eq!(masked[22], 6);
    assert_eq!(masked[23], 0);
}

#[test]
fn the_nonce_is_the_priority_the_transmitter_and_the_packet_number() {
    let hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, Some(3), true);
    let parsed = f::parse(&hdr);
    let pn = Pn(0x0000_0000_002a);
    let nonce = aad::ccm_nonce(&parsed, 3, &pn.to_bytes());
    assert_eq!(nonce[0], 3, "the flags byte carries the traffic identifier");
    assert_eq!(&nonce[1..7], &f::AP.0, "the transmitter, not the source");
    assert_eq!(&nonce[7..13], &pn.to_bytes());
}

#[test]
fn a_management_frame_sets_the_management_bit_in_the_nonce() {
    use wireless::ieee80211::{build, fctl::mgmt_stype};
    let mut frame = Vec::new();
    build::mgmt_header(&mut frame, mgmt_stype::DEAUTH, f::STA, f::AP, f::AP);
    let parsed = f::parse(&frame);
    let nonce = aad::ccm_nonce(&parsed, 0, &[0; 6]);
    assert_eq!(nonce[0], 1 << 4);
}

#[test]
fn encrypt_then_decrypt_returns_the_plaintext() {
    let hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, Some(0), true);
    let parsed = f::parse(&hdr);
    let pn = Pn(0xb503_9776);
    let sealed = ccmp::encrypt(&TK, &parsed, pn, 0, &PAYLOAD).unwrap();
    assert_eq!(sealed.len(), cipher_len::CCMP_HDR + PAYLOAD.len() + cipher_len::CCMP_MIC);
    assert_ne!(&sealed[cipher_len::CCMP_HDR..cipher_len::CCMP_HDR + PAYLOAD.len()],
               &PAYLOAD[..], "the payload must not travel in the clear");
    let (back_pn, idx, plain) = ccmp::decrypt(&TK, &parsed, &sealed).unwrap();
    assert_eq!(back_pn, pn);
    assert_eq!(idx, 0);
    assert_eq!(plain, PAYLOAD);
}

#[test]
fn the_two_hundred_fifty_six_bit_variant_round_trips_with_a_wider_tag() {
    let key: Vec<u8> = (0u8..32).collect();
    let hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, None, true);
    let parsed = f::parse(&hdr);
    let sealed = ccmp::encrypt(&key, &parsed, Pn(9), 1, &PAYLOAD).unwrap();
    assert_eq!(sealed.len(),
               cipher_len::CCMP_HDR + PAYLOAD.len() + cipher_len::CCMP_256_MIC);
    let (_, idx, plain) = ccmp::decrypt(&key, &parsed, &sealed).unwrap();
    assert_eq!(idx, 1);
    assert_eq!(plain, PAYLOAD);
}

#[test]
fn a_flipped_bit_anywhere_in_the_frame_body_fails() {
    let hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, Some(0), true);
    let parsed = f::parse(&hdr);
    let sealed = ccmp::encrypt(&TK, &parsed, Pn(1), 0, &PAYLOAD).unwrap();
    // Every byte of the ciphertext and the integrity field.
    for i in cipher_len::CCMP_HDR..sealed.len() {
        for bit in [0u8, 3, 7] {
            let mut bad = sealed.clone();
            bad[i] ^= 1 << bit;
            assert_eq!(ccmp::decrypt(&TK, &parsed, &bad),
                       Err(CryptoError::IntegrityFailure),
                       "byte {i} bit {bit} was accepted");
        }
    }
}

#[test]
fn a_flipped_bit_in_the_cipher_header_fails() {
    let hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, Some(0), true);
    let parsed = f::parse(&hdr);
    let sealed = ccmp::encrypt(&TK, &parsed, Pn(0x1122_3344_5566), 0, &PAYLOAD).unwrap();
    // Every packet-number byte in the header is part of the nonce, so
    // altering one must break the frame rather than silently decrypt it under
    // a different counter.
    for i in [0usize, 1, 4, 5, 6, 7] {
        let mut bad = sealed.clone();
        bad[i] ^= 0x01;
        assert_eq!(ccmp::decrypt(&TK, &parsed, &bad), Err(CryptoError::IntegrityFailure),
                   "header byte {i} was accepted");
    }
}

#[test]
fn a_flipped_bit_in_the_authenticated_header_fails() {
    let hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, Some(0), true);
    let parsed = f::parse(&hdr);
    let sealed = ccmp::encrypt(&TK, &parsed, Pn(1), 0, &PAYLOAD).unwrap();

    // A different destination.
    let other = f::data_hdr_from_ds(f::OTHER, f::AP, f::PEER, Some(0), true);
    assert_eq!(ccmp::decrypt(&TK, &f::parse(&other), &sealed),
               Err(CryptoError::IntegrityFailure));
    // A different transmitter — which is also in the nonce.
    let moved = f::data_hdr_from_ds(f::STA, f::OTHER, f::PEER, Some(0), true);
    assert_eq!(ccmp::decrypt(&TK, &f::parse(&moved), &sealed),
               Err(CryptoError::IntegrityFailure));
    // A different traffic identifier.
    let retid = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, Some(5), true);
    assert_eq!(ccmp::decrypt(&TK, &f::parse(&retid), &sealed),
               Err(CryptoError::IntegrityFailure));
    // A different fragment number.
    let refrag = f::with_seq(f::data_hdr_from_ds(f::STA, f::AP, f::PEER, Some(0), true),
                             0, 1);
    assert_eq!(ccmp::decrypt(&TK, &f::parse(&refrag), &sealed),
               Err(CryptoError::IntegrityFailure));
}

#[test]
fn a_retransmission_still_verifies() {
    // The retry, power-management and more-data bits are masked out of the
    // authenticated header precisely so a frame retried on the air still
    // verifies. If it did not, every retransmission on a busy link would be
    // discarded as forged.
    use wireless::ieee80211::fctl;
    let hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, Some(0), true);
    let parsed = f::parse(&hdr);
    let sealed = ccmp::encrypt(&TK, &parsed, Pn(1), 0, &PAYLOAD).unwrap();

    let mut retried = hdr.clone();
    let fc = u16::from_le_bytes([retried[0], retried[1]])
        | fctl::FCTL_RETRY | fctl::FCTL_PM | fctl::FCTL_MOREDATA;
    retried[0..2].copy_from_slice(&fc.to_le_bytes());
    let plain = ccmp::decrypt(&TK, &f::parse(&retried), &sealed).unwrap().2;
    assert_eq!(plain, PAYLOAD);
}

#[test]
fn a_wrong_key_fails() {
    let hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, None, true);
    let parsed = f::parse(&hdr);
    let sealed = ccmp::encrypt(&TK, &parsed, Pn(1), 0, &PAYLOAD).unwrap();
    let mut wrong = TK;
    wrong[0] ^= 1;
    assert_eq!(ccmp::decrypt(&wrong, &parsed, &sealed),
               Err(CryptoError::IntegrityFailure));
}

#[test]
fn a_truncated_frame_is_refused_before_anything_is_read() {
    let hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, None, true);
    let parsed = f::parse(&hdr);
    for len in 0..(cipher_len::CCMP_HDR + cipher_len::CCMP_MIC) {
        let short = vec![0u8; len];
        assert_eq!(ccmp::decrypt(&TK, &parsed, &short), Err(CryptoError::TooShort),
                   "a {len}-byte body was not refused");
    }
}

#[test]
fn a_four_address_frame_authenticates_the_fourth_address() {
    use wireless::ieee80211::fctl;
    let mut hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, None, true);
    let fc = u16::from_le_bytes([hdr[0], hdr[1]]) | fctl::FCTL_TODS;
    hdr[0..2].copy_from_slice(&fc.to_le_bytes());
    hdr.extend_from_slice(&f::OTHER.0);
    let parsed = f::parse(&hdr);
    let (masked, _) = aad::build(&parsed);
    // Four addresses and no QoS control: six bytes more than the three-
    // address form, not eight. Authenticating two bytes that are not on the
    // air is a link on which nothing verifies.
    assert_eq!(masked.len(), aad::MIN_AAD_LEN + 6);
    assert_eq!(&masked[22..28], &f::OTHER.0);
}

#[test]
fn a_four_address_quality_of_service_frame_authenticates_both_extras() {
    use wireless::ieee80211::fctl;
    let mut hdr = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, None, true);
    let fc = u16::from_le_bytes([hdr[0], hdr[1]]) | fctl::FCTL_TODS
        | fctl::data_stype::QOS;
    hdr[0..2].copy_from_slice(&fc.to_le_bytes());
    hdr.extend_from_slice(&f::OTHER.0);
    hdr.extend_from_slice(&7u16.to_le_bytes());
    let parsed = f::parse(&hdr);
    let (masked, tid) = aad::build(&parsed);
    assert_eq!(tid, 7);
    assert_eq!(masked.len(), aad::MAX_AAD_LEN);
    assert_eq!(&masked[22..28], &f::OTHER.0);
    assert_eq!(masked[28], 7);
    assert_eq!(masked[29], 0);
}
