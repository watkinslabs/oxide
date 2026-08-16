// AES block-cipher known-answer tests.
//
// Provenance of the vectors, transcribed as hex:
//   - the block-cipher standard's appendix worked examples for the 128- and
//     256-bit key sizes (single block 00112233445566778899aabbccddeeff);
//   - the block-cipher-modes recommendation's ECB example blocks, four blocks
//     each for the 128- and 256-bit keys.
// Both directions are checked, so a broken inverse round cannot hide behind a
// correct forward round.

use crate::aes::block::{Aes128, Aes256, AesKey};
use crate::aes::tests_util::{assert_hex, hex};

fn b16(v: &[u8]) -> [u8; 16] { let mut b = [0u8; 16]; b.copy_from_slice(v); b }
fn k16(v: &[u8]) -> [u8; 16] { b16(v) }
fn k32(v: &[u8]) -> [u8; 32] { let mut b = [0u8; 32]; b.copy_from_slice(v); b }

const STD_KEY128: &str = "000102030405060708090a0b0c0d0e0f";
const STD_KEY256: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const STD_PT: &str = "00112233445566778899aabbccddeeff";

const MODES_KEY128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const MODES_KEY256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const MODES_PT: [&str; 4] = [
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
];

#[test]
fn standard_appendix_aes128() {
    let k = Aes128::new(&k16(&hex(STD_KEY128)));
    let mut b = b16(&hex(STD_PT));
    k.encrypt_block(&mut b);
    assert_hex(&b, "69c4e0d86a7b0430d8cdb78070b4c55a");
    k.decrypt_block(&mut b);
    assert_hex(&b, STD_PT);
}

#[test]
fn standard_appendix_aes256() {
    let k = Aes256::new(&k32(&hex(STD_KEY256)));
    let mut b = b16(&hex(STD_PT));
    k.encrypt_block(&mut b);
    assert_hex(&b, "8ea2b7ca516745bfeafc49904b496089");
    k.decrypt_block(&mut b);
    assert_hex(&b, STD_PT);
}

#[test]
fn modes_ecb_blocks_aes128() {
    const CT: [&str; 4] = [
        "3ad77bb40d7a3660a89ecaf32466ef97",
        "f5d3d58503b9699de785895a96fdbaaf",
        "43b1cd7f598ece23881b00e3ed030688",
        "7b0c785e27e8ad3f8223207104725dd4",
    ];
    let k = Aes128::new(&k16(&hex(MODES_KEY128)));
    for i in 0..4 {
        let mut b = b16(&hex(MODES_PT[i]));
        k.encrypt_block(&mut b);
        assert_hex(&b, CT[i]);
        k.decrypt_block(&mut b);
        assert_hex(&b, MODES_PT[i]);
    }
}

#[test]
fn modes_ecb_blocks_aes256() {
    const CT: [&str; 4] = [
        "f3eed1bdb5d2a03c064b5a7e3db181f8",
        "591ccb10d410ed26dc5ba74a31362870",
        "b6ed21b99ca6f4f9f153e7b1beafed1d",
        "23304b7a39f9f3ff067d8d8f9e24ecc7",
    ];
    let k = Aes256::new(&k32(&hex(MODES_KEY256)));
    for i in 0..4 {
        let mut b = b16(&hex(MODES_PT[i]));
        k.encrypt_block(&mut b);
        assert_hex(&b, CT[i]);
        k.decrypt_block(&mut b);
        assert_hex(&b, MODES_PT[i]);
    }
}

#[test]
fn aeskey_accepts_only_two_widths() {
    assert!(AesKey::new(&hex(STD_KEY128)).is_some());
    assert!(AesKey::new(&hex(STD_KEY256)).is_some());
    for n in [0usize, 1, 8, 15, 17, 24, 31, 33, 64] {
        let key = alloc::vec![0u8; n];
        assert!(AesKey::new(&key).is_none(), "len {n} must be rejected");
    }
    assert_eq!(AesKey::new(&hex(STD_KEY128)).unwrap().key_len(), 16);
    assert_eq!(AesKey::new(&hex(STD_KEY256)).unwrap().key_len(), 32);
}

#[test]
fn aeskey_dispatch_matches_direct() {
    for (ks, ct) in [(STD_KEY128, "69c4e0d86a7b0430d8cdb78070b4c55a"),
                     (STD_KEY256, "8ea2b7ca516745bfeafc49904b496089")] {
        let k = AesKey::new(&hex(ks)).unwrap();
        let mut b = b16(&hex(STD_PT));
        k.encrypt_block(&mut b);
        assert_hex(&b, ct);
        k.decrypt_block(&mut b);
        assert_hex(&b, STD_PT);
    }
}

/// Every 16-byte block over a deterministic pseudo-random walk must survive an
/// encrypt/decrypt round trip under both key widths. Catches an inverse round
/// that happens to be right on the standard's single vector.
#[test]
fn roundtrip_walk_both_widths() {
    let mut state: u64 = 0x0123_4567_89ab_cdef;
    let mut next = move || { state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407); (state >> 32) as u8 };
    let k128 = AesKey::new(&hex(STD_KEY128)).unwrap();
    let k256 = AesKey::new(&hex(STD_KEY256)).unwrap();
    for _ in 0..256 {
        let mut b = [0u8; 16];
        for i in 0..16 { b[i] = next(); }
        for k in [&k128, &k256] {
            let orig = b;
            let mut t = b;
            k.encrypt_block(&mut t);
            assert_ne!(t, orig, "cipher must not be the identity");
            k.decrypt_block(&mut t);
            assert_eq!(t, orig);
        }
    }
}
