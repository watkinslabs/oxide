// AES-CMAC and AES-GMAC known-answer tests.
//
// Provenance of the vectors, transcribed as hex: the CMAC recommendation's
// worked examples for the 128- and 256-bit keys, at message lengths 0, 16, 40
// and 64 bytes — which between them exercise the empty-message path, the
// exact-block path masked with the first subkey, and the padded path masked
// with the second. The GMAC values are the GCM tag with an empty payload and
// are pinned both absolutely and against the GCM entry point.

use crate::aes::block::AesKey;
use crate::aes::cmac::{self, CMAC_LEN, CMAC_LEN_8};
use crate::aes::gcm;
use crate::aes::tests_util::{assert_hex, hex};
use alloc::vec::Vec;

const K128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const K256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const MSG: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

/// (message length in bytes, expected 128-bit-key tag, expected 256-bit-key tag)
const CASES: &[(usize, &str, &str)] = &[
    (0,  "bb1d6929e95937287fa37d129b756746", "028962f61b7bf89efc6b551f4667d983"),
    (16, "070a16b46b4d4144f79bdd9dd04a287c", "28a7023f452e8f82bd4bf28d8c37c35c"),
    (40, "dfa66747de9ae63030ca32611497c827", "aaf3d8f1de5640c232f5b169b9c911e6"),
    (64, "51f0bebf7e3b9d92fc49741779363cfe", "e1992190549f6ed5696a2c056c315410"),
];

#[test]
fn cmac_matches_vectors() {
    let msg = hex(MSG);
    for (ks, pick) in [(K128, 0usize), (K256, 1usize)] {
        let key = AesKey::new(&hex(ks)).unwrap();
        for (n, t128, t256) in CASES {
            let want = if pick == 0 { t128 } else { t256 };
            let mut out = [0u8; CMAC_LEN];
            cmac::cmac(&key, &msg[..*n], &mut out);
            assert_hex(&out, want);
            assert_eq!(cmac::cmac_full(&key, &msg[..*n]), out);
        }
    }
}

/// A truncated tag is the prefix of the full one; that is how the shorter
/// management-frame tag is defined.
#[test]
fn truncated_tag_is_prefix_of_full() {
    let msg = hex(MSG);
    for ks in [K128, K256] {
        let key = AesKey::new(&hex(ks)).unwrap();
        for n in 0..=msg.len() {
            let full = cmac::cmac_full(&key, &msg[..n]);
            let mut short = [0u8; CMAC_LEN_8];
            cmac::cmac(&key, &msg[..n], &mut short);
            assert_eq!(&short[..], &full[..CMAC_LEN_8]);
        }
    }
}

/// Flipping any single message bit must change the tag; a CBC-MAC whose final
/// masking is wrong tends to collide on the block boundary.
#[test]
fn one_bit_message_change_changes_tag() {
    let key = AesKey::new(&hex(K128)).unwrap();
    for n in [0usize, 1, 15, 16, 17, 31, 32, 33] {
        let base: Vec<u8> = (0..n).map(|i| i as u8).collect();
        let want = cmac::cmac_full(&key, &base);
        for bit in 0..(n * 8) {
            let mut m = base.clone();
            m[bit / 8] ^= 1 << (bit % 8);
            assert_ne!(cmac::cmac_full(&key, &m), want);
        }
        // Appending a byte must also change the tag, including from empty.
        let mut longer = base.clone();
        longer.push(0);
        assert_ne!(cmac::cmac_full(&key, &longer), want);
    }
}

const GMAC_IV: &str = "cafebabefacedbaddecaf888";
const GMAC_AAD: &str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
const GMAC_K128: &str = "feffe9928665731c6d6a8f9467308308";
const GMAC_K256: &str = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";

fn iv12(s: &str) -> [u8; 12] { let mut b = [0u8; 12]; b.copy_from_slice(&hex(s)); b }

#[test]
fn gmac_matches_vectors() {
    for (ks, want) in [(GMAC_K128, "346434fd51d5cd0c5887ec63e39b907a"),
                       (GMAC_K256, "9f6be07603c0b0bd1272854063e9c9ba")] {
        let key = AesKey::new(&hex(ks)).unwrap();
        let mut out = [0u8; 16];
        cmac::gmac(&key, &iv12(GMAC_IV), &hex(GMAC_AAD), &mut out);
        assert_hex(&out, want);
    }
}

/// GMAC is the GCM tag with an empty payload; the two entry points must agree
/// over a range of associated-data lengths.
#[test]
fn gmac_agrees_with_gcm_empty_payload() {
    for ks in [GMAC_K128, GMAC_K256] {
        let key = AesKey::new(&hex(ks)).unwrap();
        let iv = iv12(GMAC_IV);
        for n in 0..=48usize {
            let aad: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_add(7)).collect();
            let mut want = [0u8; 16];
            let mut empty: [u8; 0] = [];
            gcm::encrypt(&key, &iv, &aad, &mut empty, &mut want).unwrap();
            let mut got = [0u8; 16];
            cmac::gmac(&key, &iv, &aad, &mut got);
            assert_eq!(got, want, "aad len {n}");
        }
    }
}

/// A one-byte change anywhere in the associated data must change the GMAC.
#[test]
fn gmac_one_byte_aad_change_changes_tag() {
    let key = AesKey::new(&hex(GMAC_K256)).unwrap();
    let iv = iv12(GMAC_IV);
    let aad = hex(GMAC_AAD);
    let mut want = [0u8; 16];
    cmac::gmac(&key, &iv, &aad, &mut want);
    for i in 0..aad.len() {
        let mut bad = aad.clone();
        bad[i] ^= 0x01;
        let mut got = [0u8; 16];
        cmac::gmac(&key, &iv, &bad, &mut got);
        assert_ne!(got, want);
    }
}
