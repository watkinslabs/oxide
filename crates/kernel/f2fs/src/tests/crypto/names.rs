//! Filenames: how long a stored name is, what it encrypts to, and how a
//! case-folding encrypted directory hashes.

use super::fixture::*;
use crate::crypto::fname::encrypted_size;
use crate::crypto::uapi::*;
use crate::crypto::{FscryptError, Info};
use crate::uapi::NAME_LEN;

/// Short names are padded up to the minimum message length first, and only
/// then rounded to the policy's padding — so a one-byte name and a fifteen-
/// byte name are the same size on the medium.
#[test]
fn a_short_name_is_padded_to_the_minimum_before_the_policy_padding() {
    for n in 1..=FNAME_MIN_MSG_LEN {
        assert_eq!(encrypted_size(n, 4, NAME_LEN), Some(16));
        assert_eq!(encrypted_size(n, 32, NAME_LEN), Some(32));
    }
    assert_eq!(encrypted_size(17, 4, NAME_LEN), Some(20));
    assert_eq!(encrypted_size(17, 8, NAME_LEN), Some(24));
    assert_eq!(encrypted_size(17, 16, NAME_LEN), Some(32));
    assert_eq!(encrypted_size(33, 32, NAME_LEN), Some(64));
}

/// The padding never pushes a name past what an entry holds: the rounded
/// length is capped, which is what lets the longest name still be stored.
#[test]
fn padding_is_capped_at_the_widest_name() {
    assert_eq!(encrypted_size(NAME_LEN, 32, NAME_LEN), Some(NAME_LEN));
    assert_eq!(encrypted_size(250, 32, NAME_LEN), Some(NAME_LEN));
    // A name already longer than the cap has no shorter encrypted form.
    assert_eq!(encrypted_size(NAME_LEN + 1, 4, NAME_LEN), None);
}

#[test]
fn a_name_matches_its_known_ciphertext() {
    let d = info(dir(), 9);
    assert_eq!(d.encrypt_name(b"hello").unwrap(),
               hexv("c1818e1645b4e4057caebf945f07bb45"));
    assert_eq!(d.encrypt_name(b"a-considerably-longer-file-name.txt").unwrap(),
               hexv("49b46a22c6715219be6b35a7fa107623fcb76a67c6b296682dbdb813e9d32b17adc26af4"));
}

/// Every name round-trips, and the padding comes off again — a plaintext name
/// cannot contain a zero byte, so the first one ends it.
#[test]
fn every_name_round_trips_and_loses_its_padding() {
    let d = info(dir(), 9);
    for n in 1..=200usize {
        let name: alloc::vec::Vec<u8> = (0..n).map(|i| b'a' + (i % 26) as u8).collect();
        let ct = d.encrypt_name(&name).unwrap();
        assert_eq!(ct.len(), encrypted_size(n, 4, NAME_LEN).unwrap());
        assert!(ct.len() >= FNAME_MIN_MSG_LEN);
        assert_eq!(d.decrypt_name(&ct).unwrap(), name);
    }
}

/// A wider padding changes the stored length, and therefore the ciphertext.
#[test]
fn the_padding_setting_changes_the_stored_name() {
    let a = info(dir(), 9);
    let wide = Info::setup(
        &ctx(policy_v2(MODE_AES_256_XTS, MODE_AES_256_CTS, FLAGS_PAD_32)),
        &dir(), &fs(), &master(), &uuid(), 9).unwrap();
    let x = a.encrypt_name(b"report.txt").unwrap();
    let y = wide.encrypt_name(b"report.txt").unwrap();
    assert_eq!(x.len(), 16);
    assert_eq!(y.len(), 32);
    assert_eq!(wide.decrypt_name(&y).unwrap(), b"report.txt");
}

/// The two exempt names are stored as themselves in an encrypted directory,
/// so a locked listing still has a `.` and a `..`.
#[test]
fn dot_and_dotdot_are_never_encrypted() {
    let d = info(dir(), 9);
    for n in [&b"."[..], &b".."[..]] {
        assert_eq!(d.encrypt_name(n).unwrap(), n);
        assert_eq!(d.decrypt_name(n).unwrap(), n);
    }
}

/// Names carry no index of their own, so one name has one ciphertext in a
/// directory — which is what makes lookup by ciphertext possible at all.
#[test]
fn the_same_name_encrypts_to_the_same_bytes_every_time() {
    let d = info(dir(), 9);
    assert_eq!(d.encrypt_name(b"same").unwrap(), d.encrypt_name(b"same").unwrap());
    // Two directories with different nonces do not agree, though.
    let other = Info::setup(
        &crate::crypto::policy::Context { policy: default_v2(), nonce: [0x77; 16] },
        &dir(), &fs(), &master(), &uuid(), 9).unwrap();
    assert_ne!(d.encrypt_name(b"same").unwrap(), other.encrypt_name(b"same").unwrap());
}

#[test]
fn a_name_too_long_to_pad_is_refused_and_a_short_ciphertext_is_corrupt() {
    let d = info(dir(), 9);
    let long = alloc::vec![b'x'; NAME_LEN + 1];
    assert_eq!(d.encrypt_name(&long).unwrap_err(), FscryptError::NameTooLong);
    assert_eq!(d.decrypt_name(&[0u8; 8]).unwrap_err(), FscryptError::CorruptName);
    assert_eq!(FscryptError::CorruptName.errno(), syscall::errno::Errno::Euclean);
}

/// A directory that both folds case and encrypts cannot hash the bytes it
/// stores — two spellings encrypt differently. It hashes the folded plaintext
/// under a key derived from the master key.
#[test]
fn a_case_folding_encrypted_directory_hashes_the_plaintext_with_a_derived_key() {
    let d = Info::setup(&ctx(default_v2()), &folding_dir(), &fs(), &master(), &uuid(), 9)
        .unwrap();
    assert!(d.has_dirhash_key());
    let k = siphash::Key::from_bytes(&hex::<16>("52a4ee66987370d10c7790873e83c2f8"));
    for name in [&b"readme"[..], &b""[..], &b"a longer folded name"[..]] {
        assert_eq!(d.dirhash(name), Some(siphash::siphash(name, &k) as u32));
    }
    // It is not the format's own name hash, and must not be confused with it.
    assert_ne!(d.dirhash(b"readme").unwrap(), crate::hash::name_hash(b"readme"));
}

/// A directory that only encrypts has no such key: it hashes the ciphertext
/// with the format's own hash, like any other directory.
#[test]
fn a_plain_encrypted_directory_has_no_hash_key() {
    let d = info(dir(), 9);
    assert!(!d.has_dirhash_key());
    assert_eq!(d.dirhash(b"readme"), None);
}

/// A regular file's key is the CONTENTS mode, a directory's is the NAMES
/// mode; they are different keys from the same master key and nonce.
#[test]
fn a_file_and_a_directory_derive_different_keys_from_one_context() {
    let f = info(reg(), 9);
    let d = info(dir(), 9);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    for (n, x) in a.iter_mut().enumerate() { *x = n as u8; }
    b.copy_from_slice(&a);
    f.encrypt_data_unit(0, &mut a).unwrap();
    d.encrypt_data_unit(0, &mut b).unwrap();
    assert_ne!(a, b);
}
