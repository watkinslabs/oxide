// The temporal-key cipher: the integrity code, the key mixing, the stream,
// and the check value.
//
// The integrity code is pinned by the published chained test vectors, in
// which each result becomes the next key. A wrong byte order would produce a
// plausible-looking first value and then break at the second, which is
// exactly what makes the chain worth using instead of one vector.

use alloc::vec;
use alloc::vec::Vec;

use crate::crypto::pn::{Pn, Tsc};
use crate::crypto::{michael, tkip, CryptoError};
use crate::tests_fixture as f;
use crate::uapi::{cipher_len, tkip_key};

/// A three-part key blob: encryption key, then the two directional integrity
/// keys.
fn blob() -> Vec<u8> {
    let mut k = Vec::with_capacity(tkip_key::TOTAL_LEN);
    k.extend_from_slice(&[0x0f; tkip_key::ENCR_LEN]);
    k.extend_from_slice(&[0xa1; tkip_key::MIC_LEN]);
    k.extend_from_slice(&[0xb2; tkip_key::MIC_LEN]);
    k
}

const PAYLOAD: [u8; 18] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00,
                           0x45, 0x00, 0x00, 0x0a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];

#[test]
fn the_integrity_code_matches_the_published_chain() {
    // Each entry's result is the next entry's key, over the message shown.
    // Getting the word order wrong breaks the chain at the second step.
    let chain: [(&[u8; 8], &[u8], [u8; 8]); 6] = [
        (&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], b"",
         [0x82, 0x92, 0x5c, 0x1c, 0xa1, 0xd1, 0x30, 0xb8]),
        (&[0x82, 0x92, 0x5c, 0x1c, 0xa1, 0xd1, 0x30, 0xb8], b"M",
         [0x43, 0x47, 0x21, 0xca, 0x40, 0x63, 0x9b, 0x3f]),
        (&[0x43, 0x47, 0x21, 0xca, 0x40, 0x63, 0x9b, 0x3f], b"Mi",
         [0xe8, 0xf9, 0xbe, 0xca, 0xe9, 0x7e, 0x5d, 0x29]),
        (&[0xe8, 0xf9, 0xbe, 0xca, 0xe9, 0x7e, 0x5d, 0x29], b"Mic",
         [0x90, 0x03, 0x8f, 0xc6, 0xcf, 0x13, 0xc1, 0xdb]),
        (&[0x90, 0x03, 0x8f, 0xc6, 0xcf, 0x13, 0xc1, 0xdb], b"Mich",
         [0xd5, 0x5e, 0x10, 0x05, 0x10, 0x12, 0x89, 0x86]),
        (&[0xd5, 0x5e, 0x10, 0x05, 0x10, 0x12, 0x89, 0x86], b"Michael",
         [0x0a, 0x94, 0x2b, 0x12, 0x4e, 0xca, 0xa5, 0x46]),
    ];
    for (key, msg, want) in chain {
        assert_eq!(michael::mic_over(key, msg), want,
                   "message {:?} produced the wrong code", core::str::from_utf8(msg));
    }
}

#[test]
fn the_integrity_code_covers_the_addresses_and_the_priority() {
    let key = [0x11u8; 8];
    let base = michael::michael_mic(&key, f::STA, f::AP, 0, &PAYLOAD);
    // Any of the three pseudo-header fields changing changes the code, which
    // is what stops a peer rewriting a frame's addresses or its category.
    assert_ne!(michael::michael_mic(&key, f::OTHER, f::AP, 0, &PAYLOAD), base);
    assert_ne!(michael::michael_mic(&key, f::STA, f::OTHER, 0, &PAYLOAD), base);
    assert_ne!(michael::michael_mic(&key, f::STA, f::AP, 6, &PAYLOAD), base);
}

#[test]
fn the_two_directional_integrity_keys_are_not_interchangeable() {
    let b = blob();
    assert_ne!(tkip::tx_mic_key(&b), tkip::rx_mic_key(&b));
    assert_eq!(tkip::encr_key(&b).unwrap().len(), tkip_key::ENCR_LEN);
    assert_eq!(tkip::tx_mic_key(&b).unwrap().len(), tkip_key::MIC_LEN);
}

#[test]
fn the_header_carries_the_counter_in_its_two_halves() {
    let tsc = Tsc { iv16: 0x1234, iv32: 0xdead_beef };
    let h = tkip::build_hdr(tsc, 1);
    assert_eq!(h[0], 0x12);
    // The second byte is the first with a bit forced on and the top bit off:
    // a weak-key avoidance rule that is part of the wire format.
    assert_eq!(h[1], ((0x12u8 | 0x20) & 0x7f));
    assert_eq!(h[2], 0x34);
    assert_eq!(h[3], tkip::EXT_IV | (1 << tkip::KEY_ID_SHIFT));
    assert_eq!(&h[4..8], &0xdead_beefu32.to_le_bytes());
    let (back, idx) = tkip::parse_hdr(&h).unwrap();
    assert_eq!((back, idx), (tsc, 1));
}

#[test]
fn a_header_without_the_extended_bit_is_refused() {
    let mut h = tkip::build_hdr(Tsc { iv16: 1, iv32: 2 }, 0);
    h[3] &= !tkip::EXT_IV;
    assert_eq!(tkip::parse_hdr(&h), Err(CryptoError::NoExtIv));
}

#[test]
fn the_first_mixing_phase_depends_on_the_transmitter_and_the_counter_half() {
    let tk = [0x0fu8; 16];
    let a = tkip::phase1(&tk, f::AP, 1);
    assert_ne!(a, tkip::phase1(&tk, f::OTHER, 1), "a different transmitter, a different key");
    assert_ne!(a, tkip::phase1(&tk, f::AP, 2), "a different counter, a different key");
    assert_eq!(a, tkip::phase1(&tk, f::AP, 1), "and it is deterministic");
}

#[test]
fn the_second_mixing_phase_changes_with_every_frame() {
    let tk = [0x0fu8; 16];
    let p1 = tkip::phase1(&tk, f::AP, 7);
    let a = tkip::phase2(&tk, &p1, 0);
    let b = tkip::phase2(&tk, &p1, 1);
    assert_ne!(a, b, "a per-frame key that repeats is what the mixing exists to prevent");
    // The first three bytes of the per-frame key repeat the counter's low
    // half in the same form the header carries.
    assert_eq!(&a[..3], &tkip::build_hdr(Tsc { iv16: 0, iv32: 7 }, 0)[..3]);
}

#[test]
fn encrypt_then_decrypt_returns_the_plaintext() {
    let b = blob();
    let tsc = Tsc { iv16: 0x0102, iv32: 0x0304_0506 };
    let sealed = tkip::encrypt(&b, f::AP, tsc, 0, &PAYLOAD).unwrap();
    assert_eq!(sealed.len(), cipher_len::TKIP_IV + PAYLOAD.len() + cipher_len::TKIP_ICV);
    assert_ne!(&sealed[cipher_len::TKIP_IV..cipher_len::TKIP_IV + PAYLOAD.len()],
               &PAYLOAD[..]);
    let (back, idx, plain) = tkip::decrypt(&b, f::AP, &sealed).unwrap();
    assert_eq!((back, idx), (tsc, 0));
    assert_eq!(plain, PAYLOAD);
}

#[test]
fn a_flipped_bit_in_the_payload_fails_the_check_value() {
    let b = blob();
    let tsc = Tsc { iv16: 1, iv32: 1 };
    let sealed = tkip::encrypt(&b, f::AP, tsc, 0, &PAYLOAD).unwrap();
    for i in cipher_len::TKIP_IV..sealed.len() {
        let mut bad = sealed.clone();
        bad[i] ^= 0x40;
        assert_eq!(tkip::decrypt(&b, f::AP, &bad), Err(CryptoError::IntegrityFailure),
                   "byte {i} was accepted");
    }
}

#[test]
fn a_flipped_bit_in_the_counter_produces_the_wrong_frame_key() {
    let b = blob();
    let sealed = tkip::encrypt(&b, f::AP, Tsc { iv16: 0x1111, iv32: 0x2222_2222 }, 0,
                               &PAYLOAD).unwrap();
    // Every counter byte feeds the mixing, so altering one yields a different
    // per-frame key and the check value no longer holds.
    for i in [0usize, 2, 4, 5, 6, 7] {
        let mut bad = sealed.clone();
        bad[i] ^= 0x08;
        assert!(tkip::decrypt(&b, f::AP, &bad).is_err(), "counter byte {i} was accepted");
    }
}

#[test]
fn a_different_transmitter_cannot_decrypt_the_frame() {
    let b = blob();
    let sealed = tkip::encrypt(&b, f::AP, Tsc { iv16: 3, iv32: 4 }, 0, &PAYLOAD).unwrap();
    assert!(tkip::decrypt(&b, f::OTHER, &sealed).is_err());
}

#[test]
fn a_wrong_key_fails() {
    let b = blob();
    let mut wrong = b.clone();
    wrong[0] ^= 1;
    let sealed = tkip::encrypt(&b, f::AP, Tsc { iv16: 3, iv32: 4 }, 0, &PAYLOAD).unwrap();
    assert!(tkip::decrypt(&wrong, f::AP, &sealed).is_err());
}

#[test]
fn a_truncated_frame_is_refused() {
    let b = blob();
    for len in 0..(cipher_len::TKIP_IV + cipher_len::TKIP_ICV) {
        assert_eq!(tkip::decrypt(&b, f::AP, &vec![0u8; len]), Err(CryptoError::TooShort));
    }
}

#[test]
fn the_two_part_counter_and_the_flat_one_agree() {
    for v in [0u64, 1, 0xffff, 0x1_0000, 0x1234_5678_9abc] {
        let tsc = Tsc::from_pn(Pn(v));
        assert_eq!(tsc.to_pn(), Pn(v), "value {v:#x}");
    }
    // The low sixteen bits are the half that changes per frame.
    assert_eq!(Tsc::from_pn(Pn(0x0001_0002)).iv16, 2);
    assert_eq!(Tsc::from_pn(Pn(0x0001_0002)).iv32, 1);
}
