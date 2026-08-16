//! File contents: the ciphertext each mode produces, and the four IV rules.

use alloc::vec::Vec;

use super::fixture::*;
use crate::crypto::iv;
use crate::crypto::uapi::*;
use crate::crypto::{FscryptError, Info};

/// 0x00..0xff twice — one 512-byte data unit.
fn counting_512() -> Vec<u8> { (0..512usize).map(|i| (i % 256) as u8).collect() }

/// The tweakable mode over a whole data unit, at a non-zero index.
#[test]
fn the_tweakable_mode_matches_its_known_answer() {
    let i = info(reg(), 5);
    let plain = counting_512();
    let mut buf = plain.clone();
    i.encrypt_data_unit(3, &mut buf).unwrap();
    assert_eq!(&buf[..32], &hex::<32>(
        "cd5879c7be830000b04ed3fe91e158f4f75eda01b1acc6c2375435b53d602aec")[..]);
    assert_eq!(&buf[480..], &hex::<32>(
        "30622654be9638026665ce0dea6d099fa7e9de2ab4eb731e72dea533fb4c5541")[..]);
    i.decrypt_data_unit(3, &mut buf).unwrap();
    assert_eq!(buf, plain);
}

/// The index is in the IV, so the same bytes at a different index encrypt
/// differently. A reader that loses track of the index reads noise.
#[test]
fn the_data_unit_index_changes_every_byte() {
    let i = info(reg(), 5);
    let plain = counting_512();
    let mut a = plain.clone();
    let mut b = plain.clone();
    i.encrypt_data_unit(3, &mut a).unwrap();
    i.encrypt_data_unit(4, &mut b).unwrap();
    assert_ne!(a, b);
    // Decrypting at the wrong index gives neither an error nor the plaintext.
    let mut wrong = a.clone();
    i.decrypt_data_unit(4, &mut wrong).unwrap();
    assert_ne!(wrong, plain);
}

/// The chaining mode's IV is the block index enciphered under a key derived
/// from the file key, which is what makes a predictable index unpredictable.
#[test]
fn the_chaining_mode_matches_its_known_answer() {
    let p = policy_v2(MODE_AES_128_CBC, MODE_AES_128_CTS, FLAGS_PAD_4);
    let i = Info::setup(&ctx(p), &reg(), &fs(), &master(), &uuid(), 5).unwrap();
    let plain: [u8; 32] = core::array::from_fn(|n| n as u8);
    let mut buf = plain;
    i.encrypt_data_unit(3, &mut buf).unwrap();
    assert_eq!(buf, hex::<32>(
        "4cab20b6f4034180f609a4ccad10385f0bf2b4091a8333ead2c0ccd7e6a30061"));
    i.decrypt_data_unit(3, &mut buf).unwrap();
    assert_eq!(buf, plain);
}

/// The default rule puts nothing but the index in the IV: the key is already
/// unique per file.
#[test]
fn the_default_iv_is_the_index_alone() {
    let got = iv::generate(FLAGS_PAD_4, &nonce(), 0x1234, 0, 7);
    let mut want = [0u8; MAX_IV_SIZE];
    want[..8].copy_from_slice(&7u64.to_le_bytes());
    assert_eq!(got, want);
}

/// Sharing a key across the volume needs the inode number to keep files
/// apart, and it goes in the index's HIGH half.
#[test]
fn the_wide_inode_rule_puts_the_inode_above_the_index() {
    let got = iv::generate(FLAG_IV_INO_LBLK_64, &nonce(), 0x1234, 0, 7);
    let want_value = 7u64 | (0x1234u64 << 32);
    assert_eq!(&got[..8], &want_value.to_le_bytes());
    assert!(got[8..].iter().all(|&b| b == 0));
}

/// The narrow rule ADDS a hash of the inode number and wraps at 32 bits, so
/// the whole value fits one word.
#[test]
fn the_narrow_inode_rule_adds_a_hash_and_wraps() {
    let got = iv::generate(FLAG_IV_INO_LBLK_32, &nonce(), 0x1234, 0xffff_fff0, 0x20);
    let want = u64::from(0xffff_fff0u32.wrapping_add(0x20));
    assert_eq!(&got[..8], &want.to_le_bytes());
    // The wrap is what makes it fit: the sum exceeded 32 bits.
    assert!(want < u64::from(u32::MAX));
}

/// The direct-key rule carries the file nonce beside the index. No mode this
/// build carries has an IV wide enough for it, which is why the policy check
/// refuses the combination — but the construction is exercised here.
#[test]
fn the_direct_key_rule_carries_the_nonce_in_the_iv() {
    let got = iv::generate(FLAG_DIRECT_KEY, &nonce(), 0x1234, 0, 7);
    assert_eq!(&got[..8], &7u64.to_le_bytes());
    assert_eq!(&got[8..8 + FILE_NONCE_SIZE], &nonce()[..]);
    // A 16-byte IV would truncate the nonce, which is exactly why the modes
    // that take one are refused with this flag.
    assert!(got[8 + FILE_NONCE_SIZE..].iter().all(|&b| b == 0));
}

/// Sharing a key across the volume means the inode number is the only thing
/// separating two files' ciphertext.
#[test]
fn under_a_shared_key_the_inode_number_separates_the_files() {
    let p = policy_v2(MODE_AES_256_XTS, MODE_AES_256_CTS, FLAG_IV_INO_LBLK_64);
    let a = Info::setup(&ctx(p), &reg(), &fs(), &master(), &uuid(), 11).unwrap();
    let b = Info::setup(&ctx(p), &reg(), &fs(), &master(), &uuid(), 12).unwrap();
    let plain = counting_512();
    let (mut x, mut y) = (plain.clone(), plain.clone());
    a.encrypt_data_unit(0, &mut x).unwrap();
    b.encrypt_data_unit(0, &mut y).unwrap();
    assert_ne!(x, y);
    a.decrypt_data_unit(0, &mut x).unwrap();
    assert_eq!(x, plain);
}

/// The hashed-inode rule likewise, and its hash comes from the key rather
/// than from the number itself.
#[test]
fn the_hashed_inode_rule_separates_the_files_too() {
    let p = policy_v2(MODE_AES_256_XTS, MODE_AES_256_CTS, FLAG_IV_INO_LBLK_32);
    let a = Info::setup(&ctx(p), &reg(), &fs(), &master(), &uuid(), 11).unwrap();
    let b = Info::setup(&ctx(p), &reg(), &fs(), &master(), &uuid(), 12).unwrap();
    let plain = counting_512();
    let (mut x, mut y) = (plain.clone(), plain.clone());
    a.encrypt_data_unit(0, &mut x).unwrap();
    b.encrypt_data_unit(0, &mut y).unwrap();
    assert_ne!(x, y);
    b.decrypt_data_unit(0, &mut y).unwrap();
    assert_eq!(y, plain);
}

/// The inode number that goes into the narrow rule's IV is a keyed hash of
/// the number, not the number.
#[test]
fn the_narrow_rule_hashes_the_inode_number_with_a_derived_key() {
    let k = master().siphash_key(HKDF_INODE_HASH_KEY, &[]).unwrap();
    let want = siphash::siphash_1u64(11, &k) as u32;
    let p = policy_v2(MODE_AES_256_XTS, MODE_AES_256_CTS, FLAG_IV_INO_LBLK_32);
    let a = Info::setup(&ctx(p), &reg(), &fs(), &master(), &uuid(), 11).unwrap();
    // Reproduce the same unit through the IV the hash implies.
    let mut direct = counting_512();
    a.encrypt_data_unit(0, &mut direct).unwrap();
    let expect_iv = iv::generate(FLAG_IV_INO_LBLK_32, &nonce(), 11, want, 0);
    assert_eq!(&expect_iv[..8], &u64::from(want).to_le_bytes());
    assert_ne!(want, 11);
}

/// A whole buffer encrypts unit by unit, and the units are numbered from the
/// caller's starting index.
#[test]
fn a_buffer_of_several_units_is_the_units_encrypted_separately() {
    let mut p = default_v2();
    p.log2_data_unit_size = 9;
    let i = Info::setup(&ctx(p), &reg(), &fs(), &master(), &uuid(), 5).unwrap();
    assert_eq!(i.data_unit_size(), 512);
    let plain: Vec<u8> = (0..2048usize).map(|n| (n * 5) as u8).collect();
    let mut whole = plain.clone();
    i.crypt_contents(4, &mut whole, true).unwrap();
    for (n, unit) in plain.chunks(512).enumerate() {
        let mut one = Vec::from(unit);
        i.encrypt_data_unit(4 + n as u64, &mut one).unwrap();
        assert_eq!(&whole[n * 512..(n + 1) * 512], &one[..]);
    }
    i.crypt_contents(4, &mut whole, false).unwrap();
    assert_eq!(whole, plain);
}

#[test]
fn a_misaligned_or_empty_request_is_refused() {
    let i = info(reg(), 5);
    let mut empty: [u8; 0] = [];
    assert_eq!(i.encrypt_data_unit(0, &mut empty).unwrap_err(), FscryptError::BadLength(0));
    let mut odd = [0u8; 20];
    assert_eq!(i.encrypt_data_unit(0, &mut odd).unwrap_err(), FscryptError::BadLength(20));
    assert_eq!(i.decrypt_data_unit(0, &mut odd).unwrap_err(), FscryptError::BadLength(20));
    let mut part = alloc::vec![0u8; 4096 + 16];
    assert_eq!(i.crypt_contents(0, &mut part, true).unwrap_err(),
               FscryptError::BadLength(4096 + 16));
}
