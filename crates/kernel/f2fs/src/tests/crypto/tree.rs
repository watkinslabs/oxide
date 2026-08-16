//! Inheritance, the same-policy rule, and encrypted symbolic links.

use super::fixture::*;
use crate::crypto::inherit::{context_for_new, permitted};
use crate::crypto::uapi::*;
use crate::crypto::{symlink, FscryptError, Info};

/// A new file takes its parent's policy WHOLE and only its nonce is its own.
#[test]
fn a_new_file_inherits_the_policy_and_gets_its_own_nonce() {
    let parent = info(dir(), 9);
    let fresh = [0x5au8; FILE_NONCE_SIZE];
    let c = context_for_new(Some(&parent), &reg(), &fs(), fresh).unwrap().unwrap();
    assert_eq!(&c.policy, parent.policy());
    assert_eq!(c.nonce, fresh);
    assert_ne!(c.nonce, nonce());
}

/// An unencrypted directory's children inherit nothing.
#[test]
fn an_unencrypted_parent_hands_down_nothing() {
    assert!(context_for_new(None, &reg(), &fs(), [0; FILE_NONCE_SIZE]).unwrap().is_none());
}

/// The parent's policy has to be usable for what the CHILD is. Refusing at
/// creation is what keeps the tree uniform later.
#[test]
fn a_policy_the_child_cannot_use_is_refused_at_creation() {
    let v1 = Info::setup(&ctx(policy_v1(MODE_AES_256_XTS, MODE_AES_256_CTS, 0)),
                         &dir(), &fs(), &master(), &uuid(), 9).unwrap();
    let e = context_for_new(Some(&v1), &folding_dir(), &fs(), [1; FILE_NONCE_SIZE]).unwrap_err();
    assert_eq!(e, FscryptError::V1WithCasefold);
    context_for_new(Some(&v1), &dir(), &fs(), [1; FILE_NONCE_SIZE]).unwrap();
}

/// A child of an encrypted directory must be encrypted under the identical
/// policy — checked on access, because a volume can be edited offline.
#[test]
fn an_encrypted_directory_admits_only_the_identical_policy() {
    let p = default_v2();
    let other = policy_v2(MODE_AES_256_XTS, MODE_AES_256_CTS, FLAGS_PAD_32);
    assert!(permitted(Some(&p), &reg(), Some(&p)));
    assert!(!permitted(Some(&p), &reg(), Some(&other)));
    // A plaintext file inside an encrypted directory is a hole in the tree.
    assert!(!permitted(Some(&p), &reg(), None));
    assert!(!permitted(Some(&p), &dir(), None));
    assert!(!permitted(Some(&p), &lnk(), None));
}

/// Nothing is restricted when the parent is not encrypted, and file types
/// that are never encrypted are unrestricted either way.
#[test]
fn the_rule_applies_only_where_it_can() {
    let p = default_v2();
    assert!(permitted(None, &reg(), None));
    assert!(permitted(None, &reg(), Some(&p)));
    let dev = crate::crypto::InodeFacts {
        is_dir: false, is_reg: false, is_symlink: false, casefolded: false,
    };
    assert!(permitted(Some(&p), &dev, None));
}

/// A link's target is encrypted the way a NAME is, and the stored form
/// prefixes the ciphertext length — a reader that trusts the file size
/// instead reads the terminator as ciphertext.
#[test]
fn a_symbolic_link_stores_its_length_before_its_ciphertext() {
    let l = Info::setup(&ctx(default_v2()), &lnk(), &fs(), &master(), &uuid(), 12).unwrap();
    let stored = symlink::encode(&l, b"/etc/passwd").unwrap();
    assert_eq!(u16::from_le_bytes([stored[0], stored[1]]) as usize, 16);
    assert_eq!(stored.len(), 2 + 16 + 1);
    assert_eq!(*stored.last().unwrap(), 0);
    assert_eq!(symlink::ciphertext(&stored).unwrap().len(), 16);
    assert_eq!(symlink::present(Some(&l), &stored).unwrap(), b"/etc/passwd");
}

/// Without the key a link presents the same encoded form a locked directory
/// entry does, with no hash to carry.
#[test]
fn a_locked_link_presents_an_encoded_target() {
    let l = Info::setup(&ctx(default_v2()), &lnk(), &fs(), &master(), &uuid(), 12).unwrap();
    let stored = symlink::encode(&l, b"/etc/passwd").unwrap();
    let shown = symlink::present(None, &stored).unwrap();
    assert_ne!(shown, b"/etc/passwd");
    let rec = crate::crypto::nokey::parse(&shown).unwrap();
    assert_eq!(rec.hash, 0);
    assert_eq!(rec.disk_name(), Some(symlink::ciphertext(&stored).unwrap()));
}

#[test]
fn a_stored_link_that_cannot_have_been_written_is_refused() {
    let l = Info::setup(&ctx(default_v2()), &lnk(), &fs(), &master(), &uuid(), 12).unwrap();
    assert_eq!(symlink::encode(&l, b"").unwrap_err(), FscryptError::CorruptName);
    for bad in [&[][..], &[0u8][..], &[0, 0, 0][..], &[0x40, 0x00, 1, 2][..]] {
        assert_eq!(symlink::ciphertext(bad).err(), Some(FscryptError::CorruptName));
    }
    // A length that fits but a ciphertext below the minimum message length.
    let short = [8u8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0];
    assert_eq!(symlink::present(Some(&l), &short).unwrap_err(), FscryptError::CorruptName);
}

/// Every target length round-trips.
#[test]
fn every_target_length_round_trips() {
    let l = Info::setup(&ctx(default_v2()), &lnk(), &fs(), &master(), &uuid(), 12).unwrap();
    for n in 1..=200usize {
        let t: alloc::vec::Vec<u8> = (0..n).map(|i| b'/' + (i % 20) as u8).collect();
        let stored = symlink::encode(&l, &t).unwrap();
        assert_eq!(symlink::present(Some(&l), &stored).unwrap(), t);
    }
}
