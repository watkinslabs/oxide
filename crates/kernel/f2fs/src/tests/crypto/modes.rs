//! The four modes beyond the AES pairings: that they are reachable at all,
//! that the bytes they produce are the primitive's own answer under the key
//! the derivation produces, and that the two wide ones are wide.
//!
//! A round trip proves nothing here — every wrong key half, wrong tweak width
//! and wrong cipher decrypts its own output perfectly. What these check is
//! agreement with the primitive driven DIRECTLY, at the key and tweak the
//! policy implies, which is where a wiring defect shows.

use alloc::vec::Vec;

use blockcipher::cipher::BlockCipher;

use super::fixture::*;
use crate::crypto::mode;
use crate::crypto::uapi::*;
use crate::crypto::Info;

/// The per-file key a v2 policy with no derivation flag produces. # C: O(n)
fn per_file_key(n: usize) -> Vec<u8> {
    let mut k = alloc::vec![0u8; n];
    master().expand(HKDF_PER_FILE_ENC_KEY, &[&nonce()], &mut k).unwrap();
    k
}

/// The IV a data unit index produces with no derivation flag set. # C: O(1)
fn plain_iv(index: u64) -> [u8; MAX_IV_SIZE] {
    let mut iv = [0u8; MAX_IV_SIZE];
    iv[..8].copy_from_slice(&index.to_le_bytes());
    iv
}

fn counting(n: usize) -> Vec<u8> { (0..n).map(|i| (i % 251) as u8).collect() }

/// The other block cipher's tweakable mode, at the derived key and the same
/// IV, must produce exactly what the inode produces.
#[test]
fn sm4_contents_are_the_other_ciphers_tweakable_mode() {
    let p = policy_v2(MODE_SM4_XTS, MODE_SM4_CTS, FLAGS_PAD_4);
    let i = Info::setup(&ctx(p), &reg(), &fs(), &master(), &uuid(), 5).unwrap();
    assert_eq!(i.mode(), mode::SM4_XTS);
    let plain = counting(512);
    let mut got = plain.clone();
    i.encrypt_data_unit(3, &mut got).unwrap();

    let k = per_file_key(mode::SM4_XTS.key_size);
    assert_eq!(k.len(), 2 * sm4::SM4_KEY_LEN);
    let mut want = plain.clone();
    let unit: [u8; 16] = plain_iv(3)[..16].try_into().unwrap();
    sm4::Sm4Xts::new(&k).unwrap().encrypt(&unit, &mut want).unwrap();
    assert_eq!(got, want);

    // And it is genuinely the other cipher: the AES pairing at the same
    // derived key material answers differently.
    let mut aes_answer = plain.clone();
    aes::Xts::new(&per_file_key(64)).unwrap().encrypt(&unit, &mut aes_answer).unwrap();
    assert_ne!(got, aes_answer);

    i.decrypt_data_unit(3, &mut got).unwrap();
    assert_eq!(got, plain);
}

/// Names under the same pairing are the stealing mode over that cipher, at
/// index zero, with a key ONE cipher key wide rather than two.
#[test]
fn sm4_names_are_the_stealing_mode_over_the_other_cipher() {
    let p = policy_v2(MODE_SM4_XTS, MODE_SM4_CTS, FLAGS_PAD_4);
    let i = Info::setup(&ctx(p), &dir(), &fs(), &master(), &uuid(), 5).unwrap();
    assert_eq!(i.mode(), mode::SM4_CTS);
    assert_eq!(mode::SM4_CTS.key_size, sm4::SM4_KEY_LEN);
    let got = i.encrypt_name(b"a-name-of-some-length").unwrap();

    let k = per_file_key(mode::SM4_CTS.key_size);
    let cipher = sm4::block::Sm4::from_key(&k).unwrap();
    let mut want = got.clone();
    let unit: [u8; 16] = plain_iv(0)[..16].try_into().unwrap();
    blockcipher::cbc::cts_decrypt(&cipher, &unit, &mut want).unwrap();
    // Ciphertext stealing is length-preserving, so the padded plaintext is
    // recovered whole and the name is its head.
    assert_eq!(&want[..21], b"a-name-of-some-length");

    assert_eq!(i.decrypt_name(&got).unwrap(), b"a-name-of-some-length");
}

/// The stream-cipher wide mode, at the derived key and the WHOLE 32-byte
/// tweak.
#[test]
fn adiantum_contents_are_the_primitives_answer() {
    let p = policy_v2(MODE_ADIANTUM, MODE_ADIANTUM, FLAGS_PAD_4);
    let i = Info::setup(&ctx(p), &reg(), &fs(), &master(), &uuid(), 5).unwrap();
    assert_eq!(i.mode(), mode::ADIANTUM);
    let plain = counting(512);
    let mut got = plain.clone();
    i.encrypt_data_unit(3, &mut got).unwrap();

    let k = per_file_key(mode::ADIANTUM.key_size);
    let mut want = plain.clone();
    adiantum::Adiantum::new(&k).unwrap().encrypt(&plain_iv(3), &mut want).unwrap();
    assert_eq!(got, want);

    i.decrypt_data_unit(3, &mut got).unwrap();
    assert_eq!(got, plain);
}

/// The counter-mode wide mode is the FILENAMES half of its pairing, so it is
/// the mode a directory under that policy gets.
#[test]
fn hctr2_names_are_the_primitives_answer() {
    let p = policy_v2(MODE_AES_256_XTS, MODE_AES_256_HCTR2, FLAGS_PAD_4);
    let i = Info::setup(&ctx(p), &dir(), &fs(), &master(), &uuid(), 5).unwrap();
    assert_eq!(i.mode(), mode::AES_256_HCTR2);
    let got = i.encrypt_name(b"another-name").unwrap();

    let k = per_file_key(mode::AES_256_HCTR2.key_size);
    let mut want = got.clone();
    aes::Hctr2::new(&k).unwrap().decrypt(&plain_iv(0), &mut want).unwrap();
    assert_eq!(&want[..12], b"another-name");

    assert_eq!(i.decrypt_name(&got).unwrap(), b"another-name");
    // A regular file under the same policy takes the CONTENTS half instead.
    let r = Info::setup(&ctx(p), &reg(), &fs(), &master(), &uuid(), 5).unwrap();
    assert_eq!(r.mode(), mode::AES_256_XTS);
}

/// A wide-block mode diffuses one changed input byte across the whole unit;
/// the narrow tweakable mode changes only the 16 bytes it sits in. Getting
/// the two confused is invisible to any round trip.
#[test]
fn the_wide_modes_diffuse_one_byte_across_the_whole_unit() {
    let wide = [
        policy_v2(MODE_ADIANTUM, MODE_ADIANTUM, FLAGS_PAD_4),
        // The counter-mode one only ever encrypts names, so drive it there.
        policy_v2(MODE_AES_256_XTS, MODE_AES_256_HCTR2, FLAGS_PAD_4),
    ];
    for (n, p) in wide.into_iter().enumerate() {
        // A name is capped well below a data unit, so drive each half of the
        // pairing at a length it accepts.
        let (kind, len) = if n == 0 { (reg(), 512usize) } else { (dir(), 64usize) };
        let i = Info::setup(&ctx(p), &kind, &fs(), &master(), &uuid(), 5).unwrap();
        let (mut a, mut b) = (counting(len), counting(len));
        b[len - 12] ^= 1;
        if n == 0 {
            i.encrypt_data_unit(0, &mut a).unwrap();
            i.encrypt_data_unit(0, &mut b).unwrap();
        } else {
            a = i.encrypt_name(&a).unwrap();
            b = i.encrypt_name(&b).unwrap();
        }
        let same = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
        // A few coincidental matches are expected; wholesale agreement is not.
        assert!(same < len / 16, "wide mode {n} left {same} of {len} bytes unchanged");
    }
    // The narrow mode, for contrast: everything below the changed block is
    // untouched.
    let i = info(reg(), 5);
    let (mut a, mut b) = (counting(512), counting(512));
    b[500] ^= 1;
    i.encrypt_data_unit(0, &mut a).unwrap();
    i.encrypt_data_unit(0, &mut b).unwrap();
    assert_eq!(a[..496], b[..496]);
}

/// The direct-key flag moves the file nonce into the tweak's bytes 8..24. A
/// mode that read only 16 bytes of tweak would ignore it entirely and two
/// files would share one ciphertext — which is the whole reason the flag is
/// restricted by IV width.
#[test]
fn the_direct_key_nonce_reaches_the_wide_tweak() {
    let p = policy_v2(MODE_ADIANTUM, MODE_ADIANTUM, FLAG_DIRECT_KEY);
    let other = crate::crypto::Context { policy: p, nonce: core::array::from_fn(|i| (0x70 + i) as u8) };
    let a = Info::setup(&ctx(p), &reg(), &fs(), &master(), &uuid(), 5).unwrap();
    let b = Info::setup(&other, &reg(), &fs(), &master(), &uuid(), 5).unwrap();
    let plain = counting(512);
    let (mut x, mut y) = (plain.clone(), plain.clone());
    a.encrypt_data_unit(0, &mut x).unwrap();
    b.encrypt_data_unit(0, &mut y).unwrap();
    // The KEY is the same under this flag — it is derived from the mode
    // number alone — so only the tweak separates them.
    let mut k = [0u8; 32];
    master().expand(HKDF_DIRECT_KEY, &[&[MODE_ADIANTUM]], &mut k).unwrap();
    let mut want = plain.clone();
    let mut iv = plain_iv(0);
    iv[8..8 + FILE_NONCE_SIZE].copy_from_slice(&nonce());
    adiantum::Adiantum::new(&k).unwrap().encrypt(&iv, &mut want).unwrap();
    assert_eq!(x, want);
    assert_ne!(x, y);

    a.decrypt_data_unit(0, &mut x).unwrap();
    assert_eq!(x, plain);
}

/// The parameters each mode number carries, which decide how short a master
/// key may be and how much derived material is consumed.
#[test]
fn each_mode_carries_the_parameters_its_number_is_defined_with() {
    let want = [
        (MODE_AES_256_XTS, 64usize, 32usize, 16usize),
        (MODE_AES_256_CTS, 32, 32, 16),
        (MODE_AES_128_CBC, 16, 16, 16),
        (MODE_AES_128_CTS, 16, 16, 16),
        (MODE_SM4_XTS, 32, 16, 16),
        (MODE_SM4_CTS, 16, 16, 16),
        (MODE_ADIANTUM, 32, 32, 32),
        (MODE_AES_256_HCTR2, 32, 32, 32),
    ];
    for (num, key, strength, ivs) in want {
        let m = mode::by_number(num).unwrap();
        assert_eq!((m.key_size, m.security_strength, m.iv_size), (key, strength, ivs),
                   "mode {num}");
    }
}

/// A v2 policy needs a master key only as long as the mode's STRENGTH, and
/// the other cipher's tweakable mode has a lower strength than its key size —
/// so a 16-byte master key serves it and does not serve the AES pairing.
#[test]
fn the_other_ciphers_strength_is_its_cipher_key_not_its_derived_key() {
    let short = crate::crypto::MasterKey::new(&[7u8; 16]).unwrap();
    let id = short.identifier();
    let mut p = policy_v2(MODE_SM4_XTS, MODE_SM4_CTS, FLAGS_PAD_4);
    p.key = crate::crypto::KeyId::Identifier(id);
    Info::setup(&ctx(p), &reg(), &fs(), &short, &uuid(), 5).unwrap();
    let mut q = policy_v2(MODE_AES_256_XTS, MODE_AES_256_CTS, FLAGS_PAD_4);
    q.key = crate::crypto::KeyId::Identifier(id);
    assert_eq!(Info::setup(&ctx(q), &reg(), &fs(), &short, &uuid(), 5).err(),
               Some(crate::crypto::FscryptError::KeyTooShort));
}
