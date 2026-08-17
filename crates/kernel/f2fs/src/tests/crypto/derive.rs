//! Every key the master key produces, against known answers.
//!
//! These are the values that cannot be checked by a round trip: a wrong
//! context byte, a wrong info string, or a wrong order of the pieces still
//! yields a key that encrypts and decrypts perfectly — and disagrees with
//! every other reader of the volume.

use super::fixture::*;
use crate::crypto::key::{v1_file_key, MasterKey};
use crate::crypto::uapi::*;
use crate::crypto::FscryptError;

/// The key's public name is a derivation from the key itself, so naming it in
/// a policy is a commitment to which key opens the file.
#[test]
fn the_identifier_is_derived_from_the_key() {
    assert_eq!(master().identifier(), hex::<16>(IDENTIFIER));
    // A different key has a different name.
    let other = MasterKey::new(&[7u8; 32]).unwrap();
    assert_ne!(other.identifier(), hex::<16>(IDENTIFIER));
}

/// The per-file key's info string is the file's NONCE, under context 2.
#[test]
fn the_per_file_key_is_the_nonce_under_its_own_context() {
    let mk = master();
    let mut k = [0u8; 64];
    mk.expand(HKDF_PER_FILE_ENC_KEY, &[&nonce()], &mut k).unwrap();
    assert_eq!(k, hex::<64>(
        "25ad833e87ed63ca6f2a5b415cf06e3c1be301c875469c3ba4cb3775716a815f\
c7f8b99d36ac802951f5164da22c687710aad7050e3fe655efbb4d832040bbf1"));
    // A key of a different width is a PREFIX of the same stream, which is
    // what makes the shorter modes' keys derivable from the same call.
    let mut short = [0u8; 32];
    mk.expand(HKDF_PER_FILE_ENC_KEY, &[&nonce()], &mut short).unwrap();
    assert_eq!(&short[..], &k[..32]);
}

/// Every context byte gives a different key from the same info string. Two
/// purposes sharing one would leak each other.
#[test]
fn the_context_byte_separates_the_purposes() {
    let mk = master();
    let mut seen = alloc::vec::Vec::new();
    for c in [HKDF_KEY_IDENTIFIER, HKDF_PER_FILE_ENC_KEY, HKDF_DIRECT_KEY,
              HKDF_IV_INO_LBLK_64_KEY, HKDF_DIRHASH_KEY, HKDF_IV_INO_LBLK_32_KEY,
              HKDF_INODE_HASH_KEY] {
        let mut k = [0u8; 32];
        mk.expand(c, &[&nonce()], &mut k).unwrap();
        assert!(!seen.contains(&k), "context {c} repeats another context's output");
        seen.push(k);
    }
}

/// The per-mode keys bind to the volume as well as the mode, so one master key
/// on two volumes does not produce one key.
#[test]
fn the_per_mode_keys_bind_the_mode_number_and_the_volume() {
    let mk = master();
    let info: [u8; 17] = {
        let mut b = [0u8; 17];
        b[0] = MODE_AES_256_XTS;
        b[1..].copy_from_slice(&uuid());
        b
    };
    let mut k64 = [0u8; 64];
    mk.expand(HKDF_IV_INO_LBLK_64_KEY, &[&info[..1], &info[1..]], &mut k64).unwrap();
    assert_eq!(k64, hex::<64>(
        "11c6fd494e487871e3e72dbf586bc45185ee2f06d3fe8bc621ca4b77f8f78d85\
638c4df9ed2fd97f343d2e2da7275fc2994c1f1a3afbb42e43e3ceb259dd9938"));
    let mut k32 = [0u8; 64];
    mk.expand(HKDF_IV_INO_LBLK_32_KEY, &[&info[..1], &info[1..]], &mut k32).unwrap();
    assert_eq!(k32, hex::<64>(
        "b8b094f04e4f1c9884e1d869435eb51c240e8cd77915d31987a494ac381d75bf\
fee1c0a24bb90f129df1d97402fec4c06b34fe1a525a2797d05777fd55078229"));
    assert_ne!(k64, k32);
    // A different volume, same key and mode: a different derived key.
    let mut other = [0u8; 64];
    let mut oinfo = info;
    oinfo[1] ^= 1;
    mk.expand(HKDF_IV_INO_LBLK_64_KEY, &[&oinfo[..1], &oinfo[1..]], &mut other).unwrap();
    assert_ne!(other, k64);
}

/// The direct-key derivation binds only the mode number.
#[test]
fn the_direct_key_binds_the_mode_alone() {
    let mut k = [0u8; 64];
    master().expand(HKDF_DIRECT_KEY, &[&[MODE_AES_256_XTS]], &mut k).unwrap();
    assert_eq!(k, hex::<64>(
        "0e98bd92fd7821ccd96c46d0dd3adb7cf544bf0f40afcbb9560976fc61940699\
e5b687699adbd49ce38ba4d26205eea4103bf349274ba6495a460a243cb33c28"));
}

/// The hash keys are 128 bits read little-endian; reading them the other way
/// gives a self-consistent hash that no other reader agrees with.
#[test]
fn the_hash_keys_are_read_little_endian() {
    let mk = master();
    let dirhash = hex::<16>("52a4ee66987370d10c7790873e83c2f8");
    let inode = hex::<16>("cc6d7952a779ec64f5337034b402bcb7");
    let mut b = [0u8; 16];
    mk.expand(HKDF_DIRHASH_KEY, &[&nonce()], &mut b).unwrap();
    assert_eq!(b, dirhash);
    assert_eq!(mk.siphash_key(HKDF_DIRHASH_KEY, &[&nonce()]).unwrap(),
               siphash::Key::from_bytes(&dirhash));
    mk.expand(HKDF_INODE_HASH_KEY, &[], &mut b).unwrap();
    assert_eq!(b, inode);
    assert_eq!(mk.siphash_key(HKDF_INODE_HASH_KEY, &[]).unwrap(),
               siphash::Key::from_bytes(&inode));
}

/// The older version's derivation enciphers the MASTER KEY under the NONCE.
/// Swapping the two is the mistake that round-trips against itself.
#[test]
fn the_older_derivation_enciphers_the_master_key_under_the_nonce() {
    let k = v1_file_key(&master_bytes(), &nonce(), 64).unwrap();
    assert_eq!(k[..], hex::<64>(
        "424bd9b0edc4eea9ecb99122eb673042b2e415d6f91aa972922cbf41c8819d3a\
4223fc06785154d03b8c808b5d0edcb22f286a521f4c353c74eb63fc12a1decf")[..]);
    // A 32-byte key is the same first two blocks: the derivation is per
    // block, so a shorter key is a prefix.
    let short = v1_file_key(&master_bytes(), &nonce(), 32).unwrap();
    assert_eq!(short[..], k[..32]);
}

/// That derivation cannot stretch, so a master key shorter than the key it
/// must produce has no material for the tail.
#[test]
fn the_older_derivation_refuses_a_master_key_shorter_than_its_output() {
    assert_eq!(v1_file_key(&[0u8; 32], &nonce(), 64).unwrap_err(), FscryptError::KeyTooShort);
    v1_file_key(&[0u8; 32], &nonce(), 32).unwrap();
    // The output must be whole blocks of the cipher.
    assert_eq!(v1_file_key(&master_bytes(), &nonce(), 20).unwrap_err(),
               FscryptError::BadKeySize(20));
}

#[test]
fn master_key_bounds() {
    assert!(matches!(MasterKey::new(&[0u8; 15]), Err(FscryptError::BadKeySize(15))));
    MasterKey::new(&[0u8; 16]).unwrap();
    MasterKey::new(&[0u8; 64]).unwrap();
    assert!(matches!(MasterKey::new(&[0u8; 65]), Err(FscryptError::BadKeySize(65))));
}

/// Setting up an inode with the wrong key is caught by the identifier, not by
/// producing bytes that are not the file's.
#[test]
fn a_v2_policy_rejects_a_key_that_is_not_the_one_it_names() {
    let wrong = MasterKey::new(&[3u8; 64]).unwrap();
    let e = crate::crypto::Info::setup(&ctx(default_v2()), &reg(), &fs(), &wrong, &uuid(), 5)
        .err()
        .expect("the wrong key must be refused");
    assert_eq!(e, FscryptError::KeyMismatch);
    assert_eq!(e.errno(), syscall::errno::Errno::Enokey);
}

/// The two versions have different minimum key sizes: the older needs the
/// full derived width, the newer only the mode's security strength.
#[test]
fn the_minimum_master_key_size_depends_on_the_version() {
    // 32 bytes is below the 64-byte tweakable key but at its strength.
    let mk32 = MasterKey::new(&[9u8; 32]).unwrap();
    let mut p = default_v2();
    if let crate::crypto::KeyId::Identifier(_) = p.key { p.key = crate::crypto::KeyId::Identifier(mk32.identifier()); }
    crate::crypto::Info::setup(&ctx(p), &reg(), &fs(), &mk32, &uuid(), 5).unwrap();
    let v1 = policy_v1(MODE_AES_256_XTS, MODE_AES_256_CTS, 0);
    assert_eq!(crate::crypto::Info::setup(&ctx(v1), &reg(), &fs(), &mk32, &uuid(), 5).err(),
               Some(FscryptError::KeyTooShort));
    // The full width satisfies the older version.
    crate::crypto::Info::setup(&ctx(v1), &reg(), &fs(), &master(), &uuid(), 5).unwrap();
}
