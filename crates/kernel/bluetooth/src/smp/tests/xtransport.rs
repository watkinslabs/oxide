//! Cross-transport derivation, both directions and both generations.

use super::hex;
use crate::smp::crypto::{h6, h7};
use crate::smp::xtransport::*;

const LTK: [u8; 16] = hex("9b7d390aa610103405adc857a33402ec");

#[test]
fn identifiers_are_the_published_four_byte_values() {
    // Each spells a four-character tag when read most-significant-first.
    assert_eq!(KEY_ID_TMP1, [0x31, 0x70, 0x6d, 0x74]);
    assert_eq!(KEY_ID_TMP2, [0x32, 0x70, 0x6d, 0x74]);
    assert_eq!(KEY_ID_LEBR, [0x72, 0x62, 0x65, 0x6c]);
    assert_eq!(KEY_ID_BRLE, [0x65, 0x6c, 0x72, 0x62]);
    // The two directions are distinct identifiers, not one reused.
    assert_ne!(KEY_ID_LEBR, KEY_ID_BRLE);
    assert_ne!(KEY_ID_TMP1, KEY_ID_TMP2);
}

#[test]
fn the_salt_is_the_identifier_padded_with_zeros() {
    let s = ct2_salt(&KEY_ID_TMP1);
    assert_eq!(&s[..4], &KEY_ID_TMP1);
    assert!(s[4..].iter().all(|b| *b == 0));
}

#[test]
fn first_generation_derivation_is_the_two_step_published_chain() {
    // The intermediate is the published vector for the first step, so the
    // link key is pinned to a value with published provenance in its middle.
    let tmp = h6(&LTK, &KEY_ID_TMP1);
    assert_eq!(ltk_to_link_key(&LTK, false), h6(&tmp, &KEY_ID_LEBR));
    let tmp2 = h6(&LTK, &KEY_ID_TMP2);
    assert_eq!(link_key_to_ltk(&LTK, false), h6(&tmp2, &KEY_ID_BRLE));
}

#[test]
fn second_generation_derivation_replaces_only_the_first_step() {
    let tmp = h7(&LTK, &ct2_salt(&KEY_ID_TMP1));
    assert_eq!(ltk_to_link_key(&LTK, true), h6(&tmp, &KEY_ID_LEBR));
    let tmp2 = h7(&LTK, &ct2_salt(&KEY_ID_TMP2));
    assert_eq!(link_key_to_ltk(&LTK, true), h6(&tmp2, &KEY_ID_BRLE));
}

#[test]
fn the_two_generations_disagree() {
    // Deriving with the wrong generation produces a usable-looking key that
    // the peer will not have, which is exactly the failure this pins.
    assert_ne!(ltk_to_link_key(&LTK, false), ltk_to_link_key(&LTK, true));
    assert_ne!(link_key_to_ltk(&LTK, false), link_key_to_ltk(&LTK, true));
}

#[test]
fn the_two_directions_disagree() {
    for ct2 in [false, true] {
        assert_ne!(ltk_to_link_key(&LTK, ct2), link_key_to_ltk(&LTK, ct2), "ct2 {}", ct2);
        // Converting one way and back does not return the original: the
        // derivation is one-way, not a reversible encoding.
        assert_ne!(link_key_to_ltk(&ltk_to_link_key(&LTK, ct2), ct2), LTK, "ct2 {}", ct2);
    }
}

#[test]
fn derivation_depends_on_every_bit_of_the_key() {
    for bit in 0..128 {
        let mut k = LTK;
        k[bit / 8] ^= 1 << (bit % 8);
        assert_ne!(ltk_to_link_key(&k, false), ltk_to_link_key(&LTK, false), "bit {}", bit);
        assert_ne!(ltk_to_link_key(&k, true), ltk_to_link_key(&LTK, true), "bit {}", bit);
    }
}
