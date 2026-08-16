// HCTR2 known-answer tests.
//
// Provenance: the published conformance vector set for HCTR2 over AES,
// transcribed as hex. Selected to cover the four places implementations
// diverge and a round trip cannot see:
//   - a message of exactly one block, where the bulk part is empty and the
//     keystream pass does nothing;
//   - messages that are not a whole number of blocks (17, 31 bytes), which
//     flip the remainder flag in the hashed length block and append the
//     padding bit;
//   - a multi-block message (48, 128 bytes), which advances the keystream
//     counter and the hash over several blocks;
//   - both key widths.
// Every vector carries a 32-byte tweak, which is the length the filesystem
// encryption ABI fixes.
//
// A wrong length encoding, a wrong padding rule, a dropped L block, or a
// keystream nonce built in the other order all still decrypt what they
// encrypt. Only these values reject them.

use crate::hctr2::{Hctr2, Hctr2Error};
use super::vec_util::{assert_hex, hex};

struct Vector { key: &'static str, tweak: &'static str, pt: &'static str, ct: &'static str }

const VECTORS: &[Vector] = &[
    // 128-bit key, 16-byte message — bulk part empty
    Vector { key: "e115663c8dc63affef41d747a2cc8aba",
             tweak: "c3be2acbb53986f191ad6cf4de7445635c7ad5cc8b76ef0ecf2c606937fd0796",
             pt: "6575aed3e2bc435cb31ad805c3d05629",
             ct: "1191ea7458ccd5a2d0559e3dfe7fc8fe" },
    // 128-bit key, 31-byte message — partial final block
    Vector { key: "e7d17748760bcd342a2de774ca119cae",
             tweak: "711c4962d95b505e6887bcf689ffed30e4e5bdb6104f9f6628065af42735cde5",
             pt: "87038f06a86154da0145d401ef4a22cf78159fbd64bd2cb9401d72ae5363a5",
             ct: "4ea10527b845e4a1bb30b4a6127463d617c9cc2f1864e0060aa0ff72107b22" },
    // 128-bit key, 128-byte message
    Vector { key: "59653b1d435ec0aeb89d9bdd2203bfca",
             tweak: "ec95fa5acf5ed293a3b5e5bef3017b01d1ca6c0682f0bd67d96ca4dcb4380f74",
             pt: concat!(
              "45df7587bc72ce55c9facbfc9f40822bc64f4f5b8b3b6d67a69362898c19f4e308929cc9472c6ed0a3022bdb2cf28d46cdb09d26634c406b7943e5ce42a8ec3b",
              "5bd0eaa4e6db66557a76ecab7d2a2bbda9ab22641aa1ae84867967e9b250be122fb214f0db71d8a7418a88a06a6e9d2afa11374032094c47410731853da8f764"),
             ct: concat!(
              "2d4b9f93ca5a482601cc54e4315012f049ff594268bd878f9e6296cdb92457a40b7bf52e0ea86507ab05d5cae79c6c345d4234a462e975483d9e8ffa42e97508",
              "4e54912bbd110f8ef082f524f1c4fcae42547fce15a8b233c086b62be844ce1f685766946eadebf330f811bd6000c6d54c81f1202b4a5b99793bc95c7423e65d") },
    // 256-bit key, 16-byte message — the width filesystem content encryption uses
    Vector { key: "9eebb2493c1cf5f46a99c2c4dfb1f4dd752057ea2c4fcdb2a53d7b491eabfd0f",
             tweak: "df63d4abd249f3d8338137607dfa7308d8496d80e82f6254eb0ea9395b457f8a",
             pt: "67c9f23084418e43fbf3b33e79367fe8",
             ct: "2738784716d971352e7edd7e433cb840" },
    // 256-bit key, 17-byte message — one byte past a block
    Vector { key: "93fa7ee20e67c439e7ca4795689d5e5a7c2619abc6ca6a4c45a69642ae6cffe7",
             tweak: "ea8247953b22a13a6aca244c507e23cd0e50e541b66529d8302300d254a7d656",
             pt: "db1f1fecad836e5d19a5f63bb4935a576f",
             ct: "f1466e9db301f06bc2ac5788486d407268" },
    // 256-bit key, 31-byte message
    Vector { key: "362b5797f85dcd995f1a5a441d920f27cc16d72b856399d3ba96a1dbd26068da",
             tweak: "ef5869b12c5e9a4724c1b169e112938f433d6d00db5ed8d9129afed9ff2daac4",
             pt: "5ea8681985981223260accdb0a04b9df4db3487bb0e3c819435a4606942df2",
             ct: "dbfdc803d0ecc1febd6437b88243624e7e54a3e224a727e8a4d5b36cb226b4" },
    // 256-bit key, 48-byte message
    Vector { key: "0365036e4de6e84e8bbe22194831eed9a09121be6289de78d9b036a33cce43d5",
             tweak: "a9c34be70ffc6dbf5627211cfcd604105f43e23035296c1090f1bf61ed0f8a91",
             pt: "07aa0226b498115e3341215151632c7200ab32a71cc83c9c250e8b9adf85ed2df4f2bc55ca926d22fd223b424c0b74ec",
             ct: "7bb1436dd8726cf6676a00c4f1f0f5a4fc6091ab460b15fcd7c12815a1fcf7688ecc276200645672a617d73f67801058" },
    // 256-bit key, 128-byte message
    Vector { key: "a52824341a3cd8f705918fee851f357f803dfc9b94f6fc9e190900a904314f11",
             tweak: "a1ba4995ff346db8cd875d5efdea85db8a7b5eb25d57dd62aca98c41429475b7",
             pt: concat!(
              "69b4e88c37e86782f1ec5d04e5149113dff2871b69811d71709e9c3bde497011a0a3db0d544f6669d7db80a7709268ce81042cc6abaee56015e96fefaa8fa7a7",
              "638ff2f077f1a8eae1b71f9eab9e4b3f07875b6fcda8afb9fa700b52b8a8a79e075fa60eb39b791379c33e8d1c2c68c8511d3c7b7d79772a5665c5542328b003"),
             ct: concat!(
              "ebf998863c409f168401f9060feb3ca94ca48e5dc38de5d3aea6e6ccd62d374f99c8a32146b869f2e31489d7b9f59e4e07936f788e6bea8ffb43b83e9b4c1d7e",
              "209ac587eeaff6f946c5188ae869e79652555f001e1adccc13a5eeff4b27cadc10a64876984394a3c7e2c9659b0814261d68fb150a33498484335a1b24463192") },
];

#[test]
fn encrypt_matches_vectors() {
    for v in VECTORS {
        let c = Hctr2::new(&hex(v.key)).unwrap();
        let mut data = hex(v.pt);
        c.encrypt(&hex(v.tweak), &mut data).unwrap();
        assert_hex(&data, v.ct);
    }
}

#[test]
fn decrypt_matches_vectors() {
    for v in VECTORS {
        let c = Hctr2::new(&hex(v.key)).unwrap();
        let mut data = hex(v.ct);
        c.decrypt(&hex(v.tweak), &mut data).unwrap();
        assert_hex(&data, v.pt);
    }
}

/// One flipped ciphertext bit must change every plaintext byte with high
/// probability: the mode is wide-block, not a stream. A construction that
/// skipped either hash pass would leave most of the message intact.
#[test]
fn single_bit_change_diffuses() {
    let v = &VECTORS[7];
    let c = Hctr2::new(&hex(v.key)).unwrap();
    let plain = hex(v.pt);
    let mut flipped = hex(v.ct);
    flipped[40] ^= 1;
    c.decrypt(&hex(v.tweak), &mut flipped).unwrap();
    let same = plain.iter().zip(flipped.iter()).filter(|(a, b)| a == b).count();
    assert!(same * 8 < plain.len(), "wide-block diffusion failed: {same} bytes unchanged");
}

/// The tweak is an input, not decoration: the same message under a different
/// tweak is a different ciphertext, and a tweak of a different LENGTH is
/// different again — the length is hashed, so a 31-byte tweak and a 32-byte
/// tweak sharing a prefix do not collide.
#[test]
fn tweak_separates_ciphertexts() {
    let v = &VECTORS[3];
    let c = Hctr2::new(&hex(v.key)).unwrap();
    let tweak = hex(v.tweak);
    let mut other_tweak = tweak.clone();
    other_tweak[0] ^= 1;

    let mut a = hex(v.pt);
    let mut b = hex(v.pt);
    let mut short = hex(v.pt);
    c.encrypt(&tweak, &mut a).unwrap();
    c.encrypt(&other_tweak, &mut b).unwrap();
    c.encrypt(&tweak[..tweak.len() - 1], &mut short).unwrap();
    assert_ne!(a, b);
    assert_ne!(a, short);
}

/// Tweaks the published set does not cover — empty, and shorter than a block —
/// are accepted and round-trip. The vectors above all carry the 32-byte tweak
/// the filesystem ABI fixes, so these lengths have no published answer to
/// check against; what they pin is that the zero-padding path runs and is
/// self-consistent.
#[test]
fn short_and_empty_tweaks_round_trip() {
    let v = &VECTORS[6];
    let c = Hctr2::new(&hex(v.key)).unwrap();
    let plain = hex(v.pt);
    for tweak_len in [0usize, 1, 15, 16, 17, 32] {
        let tweak = &hex(v.tweak)[..tweak_len];
        let mut data = plain.clone();
        c.encrypt(tweak, &mut data).unwrap();
        assert_ne!(data, plain);
        c.decrypt(tweak, &mut data).unwrap();
        assert_eq!(data, plain);
    }
}

#[test]
fn rejects_bad_key_length() {
    for len in [0usize, 8, 15, 17, 24, 31, 33] {
        // No `unwrap_err`: the ok side holds key material and deliberately
        // has no Debug.
        assert!(matches!(Hctr2::new(&[0u8; 64][..len]), Err(Hctr2Error::BadKeyLen)));
    }
}

#[test]
fn rejects_short_message() {
    let c = Hctr2::new(&[0u8; 32]).unwrap();
    let mut buf = [0u8; 32];
    for len in 0..16 {
        assert_eq!(c.encrypt(&[0u8; 32], &mut buf[..len]).unwrap_err(), Hctr2Error::TooShort);
        assert_eq!(c.decrypt(&[0u8; 32], &mut buf[..len]).unwrap_err(), Hctr2Error::TooShort);
    }
    assert!(c.encrypt(&[0u8; 32], &mut buf[..16]).is_ok());
}
