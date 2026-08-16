//! Published AES-128 known-answer vectors.

use super::hex;
use crate::Aes128;

#[test]
fn fips197_appendix_c1() {
    let k = hex::<16>("000102030405060708090a0b0c0d0e0f");
    let pt = hex::<16>("00112233445566778899aabbccddeeff");
    let ct = hex::<16>("69c4e0d86a7b0430d8cdb78070b4c55a");
    assert_eq!(Aes128::new(&k).encrypt(&pt), ct);
}

#[test]
fn ecb_mode_example_vectors() {
    let k = hex::<16>("2b7e151628aed2a6abf7158809cf4f3c");
    let c = Aes128::new(&k);
    let cases: [([u8; 16], [u8; 16]); 4] = [
        (hex("6bc1bee22e409f96e93d7e117393172a"), hex("3ad77bb40d7a3660a89ecaf32466ef97")),
        (hex("ae2d8a571e03ac9c9eb76fac45af8e51"), hex("f5d3d58503b9699de785895a96fdbaaf")),
        (hex("30c81c46a35ce411e5fbc1191a0a52ef"), hex("43b1cd7f598ece23881b00e3ed030688")),
        (hex("f69f2445df4f9b17ad2b417be66c3710"), hex("7b0c785e27e8ad3f8223207104725dd4")),
    ];
    for (pt, ct) in cases { assert_eq!(c.encrypt(&pt), ct); }
}

#[test]
fn all_zero_key_and_block() {
    let c = Aes128::new(&[0u8; 16]);
    assert_eq!(c.encrypt(&[0u8; 16]), hex::<16>("66e94bd4ef8a2c3b884cfa59ca342b2e"));
}

#[test]
fn encrypt_in_place_matches_by_value() {
    let k = hex::<16>("2b7e151628aed2a6abf7158809cf4f3c");
    let c = Aes128::new(&k);
    let mut b = hex::<16>("6bc1bee22e409f96e93d7e117393172a");
    let by_value = c.encrypt(&b);
    c.encrypt_block(&mut b);
    assert_eq!(b, by_value);
}
