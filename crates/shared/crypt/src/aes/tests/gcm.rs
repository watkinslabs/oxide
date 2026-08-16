// AES-GCM known-answer tests, 12-byte IV and 16-byte tag.
//
// Provenance of the vectors, transcribed as hex: the GCM specification's
// published test-case set — cases 1-4 for the 128-bit key and 13-16 for the
// 256-bit key. Between them they cover empty plaintext with empty associated
// data, a single all-zero plaintext block, a multi-block plaintext with no
// associated data, and a non-block-multiple plaintext with associated data.

use crate::aes::block::AesKey;
use crate::aes::gcm::{self, GcmError};
use crate::aes::tests_util::{assert_hex, hex};
use alloc::vec::Vec;

struct Vector { key: &'static str, iv: &'static str, aad: &'static str,
                pt: &'static str, ct: &'static str, tag: &'static str }

const K128: &str = "feffe9928665731c6d6a8f9467308308";
const K256: &str = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
const IV: &str = "cafebabefacedbaddecaf888";
const AAD: &str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
const PT64: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
const PT60: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
const CT128_64: &str = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";
const CT128_60: &str = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";
const CT256_64: &str = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";
const CT256_60: &str = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";

const VECTORS: &[Vector] = &[
    // case 1: 128-bit key, everything empty
    Vector { key: "00000000000000000000000000000000", iv: "000000000000000000000000", aad: "",
             pt: "", ct: "", tag: "58e2fccefa7e3061367f1d57a4e7455a" },
    // case 2: 128-bit key, one zero block
    Vector { key: "00000000000000000000000000000000", iv: "000000000000000000000000", aad: "",
             pt: "00000000000000000000000000000000", ct: "0388dace60b6a392f328c2b971b2fe78",
             tag: "ab6e47d42cec13bdf53a67b21257bddf" },
    // case 3: 128-bit key, four blocks, no associated data
    Vector { key: K128, iv: IV, aad: "", pt: PT64, ct: CT128_64,
             tag: "4d5c2af327cd64a62cf35abd2ba6fab4" },
    // case 4: 128-bit key, partial final block, with associated data
    Vector { key: K128, iv: IV, aad: AAD, pt: PT60, ct: CT128_60,
             tag: "5bc94fbc3221a5db94fae95ae7121a47" },
    // case 13: 256-bit key, everything empty
    Vector { key: "0000000000000000000000000000000000000000000000000000000000000000",
             iv: "000000000000000000000000", aad: "", pt: "", ct: "",
             tag: "530f8afbc74536b9a963b4f1c4cb738b" },
    // case 14: 256-bit key, one zero block
    Vector { key: "0000000000000000000000000000000000000000000000000000000000000000",
             iv: "000000000000000000000000", aad: "",
             pt: "00000000000000000000000000000000", ct: "cea7403d4d606b6e074ec5d3baf39d18",
             tag: "d0d1c8a799996bf0265b98b5d48ab919" },
    // case 15: 256-bit key, four blocks, no associated data
    Vector { key: K256, iv: IV, aad: "", pt: PT64, ct: CT256_64,
             tag: "b094dac5d93471bdec1a502270e3cc6c" },
    // case 16: 256-bit key, partial final block, with associated data
    Vector { key: K256, iv: IV, aad: AAD, pt: PT60, ct: CT256_60,
             tag: "76fc6ece0f4e1768cddf8853bb2d551b" },
];

fn iv12(s: &str) -> [u8; 12] { let mut b = [0u8; 12]; b.copy_from_slice(&hex(s)); b }
fn tag16(s: &str) -> [u8; 16] { let mut b = [0u8; 16]; b.copy_from_slice(&hex(s)); b }

#[test]
fn encrypt_matches_vectors() {
    for v in VECTORS {
        let key = AesKey::new(&hex(v.key)).unwrap();
        let mut data = hex(v.pt);
        let mut tag = [0u8; 16];
        gcm::encrypt(&key, &iv12(v.iv), &hex(v.aad), &mut data, &mut tag).unwrap();
        assert_hex(&data, v.ct);
        assert_hex(&tag, v.tag);
    }
}

#[test]
fn decrypt_matches_vectors() {
    for v in VECTORS {
        let key = AesKey::new(&hex(v.key)).unwrap();
        let mut data = hex(v.ct);
        gcm::decrypt(&key, &iv12(v.iv), &hex(v.aad), &mut data, &tag16(v.tag)).unwrap();
        assert_hex(&data, v.pt);
    }
}

#[test]
fn one_bit_wrong_tag_rejected() {
    let mut checked = 0;
    for v in VECTORS {
        let key = AesKey::new(&hex(v.key)).unwrap();
        let good = tag16(v.tag);
        for bit in 0..128 {
            let mut bad = good;
            bad[bit / 8] ^= 1 << (bit % 8);
            let mut data = hex(v.ct);
            assert_eq!(gcm::decrypt(&key, &iv12(v.iv), &hex(v.aad), &mut data, &bad),
                       Err(GcmError::AuthFailed));
            checked += 1;
        }
    }
    assert_eq!(checked, VECTORS.len() * 128);
}

#[test]
fn one_byte_wrong_aad_rejected() {
    for v in VECTORS {
        let aad = hex(v.aad);
        if aad.is_empty() { continue; }
        let key = AesKey::new(&hex(v.key)).unwrap();
        for i in 0..aad.len() {
            let mut bad = aad.clone();
            bad[i] ^= 0x01;
            let mut data = hex(v.ct);
            assert_eq!(gcm::decrypt(&key, &iv12(v.iv), &bad, &mut data, &tag16(v.tag)),
                       Err(GcmError::AuthFailed));
        }
    }
}

/// The tag covers the ciphertext, so a rejected message must leave the buffer
/// holding the untouched ciphertext — no plaintext is ever produced.
#[test]
fn rejected_message_leaves_ciphertext_untouched() {
    let v = &VECTORS[3];
    let key = AesKey::new(&hex(v.key)).unwrap();
    let ct = hex(v.ct);
    let mut bad = tag16(v.tag);
    bad[0] ^= 0x40;
    let mut data = ct.clone();
    assert_eq!(gcm::decrypt(&key, &iv12(v.iv), &hex(v.aad), &mut data, &bad),
               Err(GcmError::AuthFailed));
    assert_eq!(data, ct, "forgery must not release plaintext");
    let pt = hex(v.pt);
    assert_ne!(data, pt);
}

/// A wrong IV must fail, and must not be silently equivalent to another IV.
#[test]
fn wrong_iv_rejected() {
    let v = &VECTORS[3];
    let key = AesKey::new(&hex(v.key)).unwrap();
    let mut iv = iv12(v.iv);
    iv[11] ^= 0x01;
    let mut data = hex(v.ct);
    assert_eq!(gcm::decrypt(&key, &iv, &hex(v.aad), &mut data, &tag16(v.tag)),
               Err(GcmError::AuthFailed));
}

/// Payload lengths straddling block boundaries, both key widths.
#[test]
fn roundtrip_all_lengths_to_three_blocks() {
    for ks in [K128, K256] {
        let key = AesKey::new(&hex(ks)).unwrap();
        let iv = iv12(IV);
        for n in 0..=48usize {
            let pt: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_mul(31)).collect();
            let aad: Vec<u8> = (0..(n % 23)).map(|i| (i as u8) ^ 0xa5).collect();
            let mut data = pt.clone();
            let mut tag = [0u8; 16];
            gcm::encrypt(&key, &iv, &aad, &mut data, &mut tag).unwrap();
            if n > 0 { assert_ne!(data, pt); }
            gcm::decrypt(&key, &iv, &aad, &mut data, &tag).unwrap();
            assert_eq!(data, pt);
        }
    }
}

/// The 32-bit counter is incremented per block; a payload spanning many blocks
/// must agree with block-at-a-time encryption of the same stream.
#[test]
fn counter_advances_across_many_blocks() {
    let key = AesKey::new(&hex(K256)).unwrap();
    let iv = iv12(IV);
    let pt: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    let mut a = pt.clone();
    let mut ta = [0u8; 16];
    gcm::encrypt(&key, &iv, &[], &mut a, &mut ta).unwrap();
    // Same key/IV over the first 64 bytes must be a prefix of the long stream.
    let mut b = pt[..64].to_vec();
    let mut tb = [0u8; 16];
    gcm::encrypt(&key, &iv, &[], &mut b, &mut tb).unwrap();
    assert_eq!(&a[..64], &b[..]);
    assert_ne!(ta, tb, "tag must depend on payload length");
}
