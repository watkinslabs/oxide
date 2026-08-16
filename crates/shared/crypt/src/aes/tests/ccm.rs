// AES-CCM known-answer tests at L=2 (13-byte nonce), the link-cipher shape.
//
// Provenance of the vectors, transcribed as hex:
//   - packet vectors 1 and 2 of the CCM-with-AES packet-encryption
//     specification (8-byte MIC, 8-byte associated data);
//   - the same packet vector 1 inputs at a 16-byte MIC, which must reuse the
//     identical keystream and differ only in the MIC;
//   - 128- and 256-bit cases with empty associated data and with an empty
//     payload, cross-checked against an independent CCM implementation.
// The negative cases pin the rejection contract: a MIC wrong by one bit, and
// associated data wrong by one byte, must both fail.

use crate::aes::block::AesKey;
use crate::aes::ccm::{self, CcmError};
use crate::aes::tests_util::{assert_hex, hex};
use alloc::vec::Vec;

struct Vector { key: &'static str, nonce: &'static str, aad: &'static str,
                pt: &'static str, ct: &'static str, mic: &'static str }

const PV1_KEY: &str = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf";
const K256: &str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
const K128: &str = "404142434445464748494a4b4c4d4e4f";
const N13: &str = "101112131415161718191a1b1c";
const AAD20: &str = "000102030405060708090a0b0c0d0e0f10111213";
const PT24: &str = "202122232425262728292a2b2c2d2e2f3031323334353637";

const VECTORS: &[Vector] = &[
    // packet vector 1, 8-byte MIC
    Vector { key: PV1_KEY, nonce: "00000003020100a0a1a2a3a4a5", aad: "0001020304050607",
             pt: "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
             ct: "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384",
             mic: "17e8d12cfdf926e0" },
    // packet vector 2, 8-byte MIC
    Vector { key: PV1_KEY, nonce: "00000004030201a0a1a2a3a4a5", aad: "0001020304050607",
             pt: "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
             ct: "72c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3b",
             mic: "a091d56e10400916" },
    // packet vector 1 inputs at a 16-byte MIC: same keystream, longer MIC
    Vector { key: PV1_KEY, nonce: "00000003020100a0a1a2a3a4a5", aad: "0001020304050607",
             pt: "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
             ct: "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384",
             mic: "509da654e32deac369c2dae7133cb08d" },
    // 256-bit key, 16-byte MIC
    Vector { key: K256, nonce: N13, aad: AAD20, pt: PT24,
             ct: "40527dbf457197dcf6b47b20e974d1741c6ad6948f9f0e50",
             mic: "c0312a74760a5eed4fc27499b09c196d" },
    // 256-bit key, 8-byte MIC over the same inputs
    Vector { key: K256, nonce: N13, aad: AAD20, pt: PT24,
             ct: "40527dbf457197dcf6b47b20e974d1741c6ad6948f9f0e50",
             mic: "d836b8e4fee33ffe" },
    // 128-bit key, empty associated data
    Vector { key: K128, nonce: N13, aad: "", pt: PT24,
             ct: "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc4",
             mic: "5d6f772800d8ebb658f7114434124d8f" },
    // 128-bit key, empty payload — MIC only
    Vector { key: K128, nonce: N13, aad: AAD20, pt: "", ct: "",
             mic: "86f144b5df0ad25ba0be5fcec1ea6573" },
];

fn key_of(v: &Vector) -> AesKey { AesKey::new(&hex(v.key)).unwrap() }

#[test]
fn encrypt_matches_vectors() {
    for v in VECTORS {
        let key = key_of(v);
        let mut data = hex(v.pt);
        let mut mic = alloc::vec![0u8; hex(v.mic).len()];
        ccm::encrypt(&key, &hex(v.nonce), &hex(v.aad), &mut data, &mut mic).unwrap();
        assert_hex(&data, v.ct);
        assert_hex(&mic, v.mic);
    }
}

#[test]
fn decrypt_matches_vectors() {
    for v in VECTORS {
        let key = key_of(v);
        let mut data = hex(v.ct);
        ccm::decrypt(&key, &hex(v.nonce), &hex(v.aad), &mut data, &hex(v.mic)).unwrap();
        assert_hex(&data, v.pt);
    }
}

#[test]
fn one_bit_wrong_mic_rejected() {
    let mut checked = 0;
    for v in VECTORS {
        let key = key_of(v);
        let good: Vec<u8> = hex(v.mic);
        for bit in 0..(good.len() * 8) {
            let mut bad = good.clone();
            bad[bit / 8] ^= 1 << (bit % 8);
            let mut data = hex(v.ct);
            assert_eq!(ccm::decrypt(&key, &hex(v.nonce), &hex(v.aad), &mut data, &bad),
                       Err(CcmError::AuthFailed));
            checked += 1;
        }
    }
    assert!(checked >= 64, "expected many single-bit MIC forgeries, got {checked}");
}

#[test]
fn one_byte_wrong_aad_rejected() {
    for v in VECTORS {
        let aad = hex(v.aad);
        if aad.is_empty() { continue; }
        let key = key_of(v);
        for i in 0..aad.len() {
            let mut bad = aad.clone();
            bad[i] ^= 0x01;
            let mut data = hex(v.ct);
            assert_eq!(ccm::decrypt(&key, &hex(v.nonce), &bad, &mut data, &hex(v.mic)),
                       Err(CcmError::AuthFailed));
        }
    }
}

#[test]
fn one_bit_wrong_ciphertext_rejected() {
    let v = &VECTORS[0];
    let key = key_of(v);
    let ct = hex(v.ct);
    for i in 0..ct.len() {
        let mut data = ct.clone();
        data[i] ^= 0x80;
        assert_eq!(ccm::decrypt(&key, &hex(v.nonce), &hex(v.aad), &mut data, &hex(v.mic)),
                   Err(CcmError::AuthFailed));
    }
}

#[test]
fn nonce_and_mic_length_contract() {
    let key = AesKey::new(&hex(K128)).unwrap();
    let mut data = hex(PT24);
    let mut mic16 = [0u8; 16];
    for n in [0usize, 12, 14, 16] {
        let nonce = alloc::vec![0u8; n];
        assert_eq!(ccm::encrypt(&key, &nonce, &[], &mut data, &mut mic16), Err(CcmError::BadNonce));
    }
    let nonce = hex(N13);
    for m in [0usize, 4, 6, 7, 9, 12, 14, 15, 17] {
        let mut mic = alloc::vec![0u8; m];
        assert_eq!(ccm::encrypt(&key, &nonce, &[], &mut data, &mut mic), Err(CcmError::BadMicLen));
    }
}

#[test]
fn payload_longer_than_length_field_rejected() {
    let key = AesKey::new(&hex(K128)).unwrap();
    let mut data = alloc::vec![0u8; 0x10000];
    let mut mic = [0u8; 8];
    assert_eq!(ccm::encrypt(&key, &hex(N13), &[], &mut data, &mut mic), Err(CcmError::TooLong));
    let mut ok = alloc::vec![0u8; 0xffff];
    assert!(ccm::encrypt(&key, &hex(N13), &[], &mut ok, &mut mic).is_ok());
}

/// Associated data at and past the two-byte encoding limit switches to the
/// six-byte escape form; a round trip must survive the switch, and the two
/// lengths must produce different MICs.
#[test]
fn long_aad_escape_encoding_roundtrips() {
    let key = AesKey::new(&hex(K256)).unwrap();
    let nonce = hex(N13);
    let mut mics = Vec::new();
    for alen in [0usize, 1, 15, 16, 17, 0xfeff, 0xff00, 0xff01] {
        let aad: Vec<u8> = (0..alen).map(|i| (i * 7 + 3) as u8).collect();
        let mut data = hex(PT24);
        let mut mic = [0u8; 16];
        ccm::encrypt(&key, &nonce, &aad, &mut data, &mut mic).unwrap();
        ccm::decrypt(&key, &nonce, &aad, &mut data, &mic).unwrap();
        assert_hex(&data, PT24);
        mics.push(mic);
    }
    for i in 0..mics.len() { for j in (i + 1)..mics.len() { assert_ne!(mics[i], mics[j]); } }
}

/// Payload lengths straddling the block boundary, both key widths.
#[test]
fn roundtrip_all_lengths_to_three_blocks() {
    let nonce = hex(N13);
    for ks in [K128, K256] {
        let key = AesKey::new(&hex(ks)).unwrap();
        for n in 0..=48usize {
            let pt: Vec<u8> = (0..n).map(|i| (i as u8) ^ 0x5a).collect();
            let aad: Vec<u8> = (0..(n % 19)).map(|i| i as u8).collect();
            let mut data = pt.clone();
            let mut mic = [0u8; 8];
            ccm::encrypt(&key, &nonce, &aad, &mut data, &mut mic).unwrap();
            if n > 0 { assert_ne!(data, pt, "payload must be transformed"); }
            ccm::decrypt(&key, &nonce, &aad, &mut data, &mic).unwrap();
            assert_eq!(data, pt);
        }
    }
}
