//! Published AES-CMAC known-answer vectors: the subkeys, and the four message
//! lengths that exercise the empty case, the exact-block case, the padded case
//! and the multi-block case.

use super::hex;
use crate::{Cmac, cmac};
use crate::cmac::dbl;

const KEY: [u8; 16] = hex("2b7e151628aed2a6abf7158809cf4f3c");
const MSG: [u8; 64] = hex(concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
));

#[test]
fn subkeys_match_published_derivation() {
    let c = Cmac::new(&KEY);
    assert_eq!(*c.k1(), hex::<16>("fbeed618357133667c85e08f7236a8de"));
    assert_eq!(*c.k2(), hex::<16>("f7ddac306ae266ccf90bc11ee46d513b"));
}

#[test]
fn doubling_reduces_when_the_high_bit_is_set() {
    // The published intermediate: AES-128(K, 0^128) doubled once gives K1.
    let l = hex::<16>("7df76b0c1ab899b33e42f047b91b546f");
    assert_eq!(dbl(&l), hex::<16>("fbeed618357133667c85e08f7236a8de"));
    // A value whose top bit is set must pick up the reduction term.
    let hi = hex::<16>("80000000000000000000000000000000");
    assert_eq!(dbl(&hi), hex::<16>("00000000000000000000000000000087"));
}

#[test]
fn empty_message() {
    assert_eq!(cmac(&KEY, &[]), hex::<16>("bb1d6929e95937287fa37d129b756746"));
}

#[test]
fn one_whole_block() {
    assert_eq!(cmac(&KEY, &MSG[..16]), hex::<16>("070a16b46b4d4144f79bdd9dd04a287c"));
}

#[test]
fn partial_final_block() {
    assert_eq!(cmac(&KEY, &MSG[..40]), hex::<16>("dfa66747de9ae63030ca32611497c827"));
}

#[test]
fn four_whole_blocks() {
    assert_eq!(cmac(&KEY, &MSG), hex::<16>("51f0bebf7e3b9d92fc49741779363cfe"));
}

#[test]
fn reused_key_matches_one_shot() {
    let c = Cmac::new(&KEY);
    for len in [0usize, 1, 15, 16, 17, 40, 63, 64] {
        assert_eq!(c.mac(&MSG[..len]), cmac(&KEY, &MSG[..len]), "len {}", len);
    }
}
